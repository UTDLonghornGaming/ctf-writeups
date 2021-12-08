# MetaCTF 2021 - Company Picnic - 225 points - Writeup

## Analysis

We provided a vast amount of RSA modulo/exponent pairs, which can be used in conjunction for cracking private keys.

## Cryptographic Analysis

We found two different ways to crack this problem:

## GCD Attack

First, since we are given so many moduli, we can find the GCDs of each unique pair of moduli using the Extended Euclidean Algorithm, which runs in O(log N) time. If the GCD of any particular pair does not equal one, then they share a common prime factor, and we can easily crack the RSA formula. 

As it turns out, the first modulus and the last modulus share a common factor, which can be used to find their respective private keys.


```
from Crypto.Util.number import *

N1 # 0x41840b1083456f7b3df068d97c20ca7957d64fac69d3c8da30b3828c79dae5e8...
N2 # 0x9aa17e6ffd055863c60ec97c0d6ac50d0fd8d6aa4d058ae3cd9df9576cc2b3f6...
e1 # 0x95556ed8309980d69aa99efa04fb8ab9be63a8fcb7bb210830c7d4dee89f25ac...
e2 # 0x3322d9aaa53bce5de4a4de28ab102bdd48ec4901852f6edd75e9eb9437728e19...

p = GCD(N1,N2) # 125344748245102983316212132112929581797568138794932871...

q1 = N1/p
q2 = N2/p

d1 = pow(e1, -1, (p-1)*(q1-1)) = 124371070310885214163351663921689794277478796054632466093536095
d2 = pow(e2, -1, (p-1)*(q2-1)) = 556323220537042674972669390039755165956093988221

print(long_to_bytes(d1)) #b'MetaCTF{Oops_those_primes_'
print(long_to_bytes(d2)) #b'are_not_that_randoM}'
```

## Wiener's attack

Each moduli is comprised of 512 hex characters, meaning that they are 2048-bits total.
Because we know that the private keys are concatenated form the flag, we might suspect that the private keys are much smaller than 2048-bits moduli, which would typically be able to depict 256 ASCII characters.

As it turns out, when private keys are much smaller than the modulus, there is a quick deterministic way to find them, known as Weiner's attack.
While this attack is implementable some knowledge of continued fractions, we can also easily apply it by importing orisano's owiener library.

```
import owiener
from Crypto.Util.number import *

with open("message.txt") as file:
    lines = file.readlines()

arr = []
for i in range(0, len(lines), 3):
    if lines[i].strip() == "":
        break
    n = lines[i].lstrip("N =").rstrip()
    e = lines[i + 1].lstrip("e =").rstrip()
    d = owiener.attack(int(e,16), int(n,16))
    if d is None:
        pass
    else:   
        arr.append(d)

print(arr)
for l in arr:
    print(long_to_bytes(l))

#[124371070310885214163351663921689794277478796054632466093536095, 556323220537042674972669390039755165956093988221]
#b'MetaCTF{Oops_those_primes_'
#b'are_not_that_randoM}'
```

## Conclusion
After either exploit, we convert each private key to bytes and append them, arriving at the flag:
```
MetaCTF{Oops_those_primes_are_not_that_randoM}
```
