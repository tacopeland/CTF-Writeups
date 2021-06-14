# RSAtrix

These challenges involve doing RSA over a different multiplicative group, this time matrices over an integer mod ring with the matrix multiplication operation being the group operation.

## RSAtrix 1
"RSA, RSA, RSA. After so many RSA problems, they all start to look the same. But what looks different? Matrices! After a lot of detailed R&D, we're proud to present RSAtrix, the world's first* matrix RSA system!"

In this challenge, you are given `rt1.sage` and `enc_rt1.txt`, and from that need to recover the message.
Looking at the code, it looks like the encryption step is just multiplying a matrix by a scalar `m`, which is our message encoded into an integer:
```python
def encrypt(m):
    M = m * P
    return (M^e).list()
```

They also give us the following code, from which we can deduce a few things:
```python
p = 35953130875571662629774552621633952493346190947047
q = 68201352784431955275947627343562102980308744031461
n = p * q
e = 3

R = Zmod(n)
MS = MatrixSpace(R, 5, 5)
s = PermutationGroupElement('(1,4)(2,3,5)')
P = MS(s.matrix())
```
- We have our normal RSA parameters `p`, `q`, `n` and `e`. What can we do with `d`?
- It looks like each element of this matrix is an element of the ring `Z(n)`, where `n` is the RSA modulus.
- It looks like our matrix P is a permutation matrix; that is, it only ever rearranges elements and only has `1`s and `0`s as elements.

From these we can glean one bit of information: raising either the encrypted matrix or one of its elements to the power of `d`, we should get our message back. This is because if you multiply a permutation matrix by a scalar `k` and raise that matrix to the `i`th power, you end up with each element being `k^i`.

What does this mean in terms of code? We can do one of two things:
```python
from Crypto.Util.number import long_to_bytes as ltb

p = 35953130875571662629774552621633952493346190947047
q = 68201352784431955275947627343562102980308744031461
n = p * q
e = 3

R = Zmod(n)
MS = MatrixSpace(R, 5, 5)
s = PermutationGroupElement('(1,4)(2,3,5)')
P = MS(s.matrix())
# The matrix stored in enc_rt1.txt
E = MS([0, 0, 0, 1879922562037963072325125556499104095457740584077567873217970367519076380025989311243974742849996920, 0, 0, 1879922562037963072325125556499104095457740584077567873217970367519076380025989311243974742849996920, 0, 0, 0, 0, 0, 1879922562037963072325125556499104095457740584077567873217970367519076380025989311243974742849996920, 0, 0, 1879922562037963072325125556499104095457740584077567873217970367519076380025989311243974742849996920, 0, 0, 0, 0, 0, 0, 0, 0, 1879922562037963072325125556499104095457740584077567873217970367519076380025989311243974742849996920])

phi = (p-1)*(q-1)
d = inverse_mod(e, phi)

# Method 1 (what I used):
M = E^d
m = E[0][3]
print(ltb(m))

# Method 2 (what I should have done in hindsight):
m = E[0][3]^d
print(ltb(m))
```
This leaves us with our message m.

## RSAtrix 2
"Sure, you saw our first prototype, but you could obviously see it was just RSA slapped on a permutation matrix. Will you still be able to decode our messages if we conjugate our generator first?"

In this challenge, you are given `rt2.sage` and `enc_rt2.txt`, the latter of which contains a 23x23 matrix. It is mostly the same as RSAtrix 1, however the initial permutation matrix has undergone a similarity transform prior to encryption.

```python
# Same as before
R = Zmod(n)
MS = MatrixSpace(R, N, N)
s = PermutationGroupElement('(1,6,8)(2,3,4,5,7)(9,11,13,15,17,19,21,23)(10,12,14,16,18,20,22)')
P = MS(s.matrix())
# They seeded it, so we know C.
with seed(1): C = MS([randrange(100) for i in range(N*N)])
# Similarity transform.
G = C * P * C^-1
```

Seeing this, we can take advantage of this rule: `C^-1 * (C * P * C^-1)^e * C = P^e`.
You can either use the smart or the monke method (I used the monke method):
```python
from Crypto.Util.number import long_to_bytes as ltb

# Calculate RSA params
phi = (p-1)*(q-1)
d = inverse_mod(e, phi)

# Get ciphertext array
f = open('enc_rt2.txt')
tmp = eval(f.read())
E = MS(tmp)
del(tmp)

# What I did (monke)
# Raise the matrix to the dth power (very slow)
A = pow(E, d)
# Undo the similarity transform
M = C^-1 * A * C
print(ltb(M[0][0]))

# The smart way
# Undo the similarity transform
mPe = C^-1 * E * C
# Get a nonzero element of the matrix
me = mPe[0][0]
# Raise it to the dth power
m = me^d
print(ltb(m))
```

This prints our flag.

## RSAtrix 3
"We've concluded that all our problems are the result of you whippersnappers having too much information at your disposal. As a result, we've stored the encoded message in a secret vault in this beta run. Enjoy the calculator demo!"

In this challenge, we are only given `rt3.sage` and a calculator netcat service: `nc crypto.bcactf.com 49156`. Starting up the calculator, we can see that we have access to the traces of stored matrices, the ability to add, multiply by a matrix, multiply by a constant, and exponentiate matrices. The catch is, that only the trace is returned, not the matrix itself. So, lets look at the code:
```python
#!/usr/bin/env -S sage --nodotsage
import binascii

p = 2118785735523620955301512231868734231925640292462405499978976981762557161416662496081983014179663
q = 1243737700428927574598968208586995066861594665591025213691894901887737529628559457923362470874703
n = p * q
e = 3
N = 31

R = Zmod(n)
MS = MatrixSpace(R, N, N)
s = PermutationGroupElement('(1,8,18)(2,24,14,22,25,6,9,13,31,15,21)(3,16,27,26,12,10,7,5,20,23)(4,29,28,11,19,17,30)')
P = MS(s.matrix())
with seed(1): C = MS([randrange(100) for i in range(N*N)])
G = C * P * C^-1

def encrypt(m):
    M = m * G
    return (M^e).list()
```
From this, we can see that we are given the means to calculate `d` once again, as well as the ability to raise the matrix to the `d`th power. So, our solution should be similar to last time, right?

First we calculate `d = inverse_mod(e, (p-1)*(q-1))`, go into the calculator, and choose to exponentiate the matrix `E` to the `d`th power. This is the monke method, and thus takes quite a while to calculate. Thus, we get the trace `49950804502047051227137104580045215724336659140015649493235377279128780499418717912205545795127744212022566085276888178843266423`. This, however, isn't our message.

Looking at the definition of the trace on Wikipedia, we see that it's just the sum of the elements on the diagonal of the matrix. Since our elements are all our message `m`, this must be some small multiple of `m` (up to 31*m). So, we see that our trace divided by 3 gives us the correct flag.
