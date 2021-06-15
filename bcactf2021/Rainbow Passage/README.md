# Rainbow Passage

"I'm pretty sure my friend has been communicating with the trickster god by beaming encrypted message at rainbows every time it rains. I've intercepted one of his messages along with its plaintext; can you help me figure out the password he uses so I can talk to the shape shifter myself?"

In this challenge, you are given `rp.py`, `enc_rp.txt`, `message_rp.txt`, and a challenge service, and from that need to recover the key.

So, lets look at the code:
```python
def encode_block(m, pm):
    # m is a block of 16 bytes
    # pm is a set of 16 word pairs, sent as 16-long strings of bits
    m = [i for i in m]
    c = [0] * 16
    # i is index, w is word (in bits)
    for i, w in enumerate(pm):
        for j, l in enumerate(w):
            if l == '1':
                c[j] ^= m[i]
    # c[j] is the xor of each m[i] such that pm[i][j] == 1
    return binascii.hexlify(bytes(c))

def encode(m, pwd):
    # pm is a list of the binary representation of pwd grouped by 2 bytes
    # padded with zeroes per byte to word length.
    pm = []
    while pwd:
      a = '0'*8 + bin(ord(pwd[0]))[2:]
      a = a[-8:]
      b = '0'*8 + bin(ord(pwd[1]))[2:]
      b = b[-8:]
      pm.append(a + b)
      pwd = pwd[2:]
    c = b""
    # encodes message in blocks of 16
    while m:
        c += encode_block(m[:16], pm)
        m = m[16:]
    return c
```

There are a few other things below this, like that you can only encrypt things on the challenge service, not decrypt.

We can see a few things from this code: we are dealing with some sort of block cipher; it splits our password into bits in groups of two bytes; each block is 16 bytes long; every word in the password is applied to a block of ciphertext one after another.

So, where does that leave us? Well, this is a bit confusing, so lets look at the ciphertext and plaintext to get some more intuition:
```python
message = "When sunlight strikes raindrops in the air, they act like a prism and form a rainbow. The rainbow is a division of white light into many beautiful colors. These take the shape of a long round arch, with its path high above, and its two ends apparently beyond the horizon. There is, according to legend, a boiling pot of gold at one end. People look but no one ever finds it. When a man looks for something beyond his reach, his friends say he is looking for the pot of gold at the end of
the rainbow."
enc = "0074252538126d030056257867484f6400070806330a06660078081c5d571a140018081064105e28006d0841101c4c43000e0408364f1122003f04005b48541d00040b4169050e60007c0b5c471a531600647a4e002d7d2600587a5319391b6c001e054f2e5a502d002405445f1f0c47005a594531575d2d006559555e064947001b06116f0305770076060c4c18501a007076444a470217000f761b61633b2d00160d11230a417d007d0d1b07111f12000c004d715a5776002a004a0d121f140047085b25531c77007708150f074f40004900587211403000210041475f181b000b551c7842142d00365558180f4f1a0011095434135e7200740944134b401a00411a562519037800321a564d5649110023606e780d214b0018607065191c75005e17402c101729006f17015b154a5c004a0a5475440661006f0a13570d530f0011100235135d6e003a104c0e590b540073676a235c304a000067675d3c131a004a00517a0f0d2a006000521c415d4d00317d1f6e164f0700447d67574c3217005e554c2d064c340038550249011e480003151a790950630073155950054e1e00091b527953123f00631b150f0e1c48000206036a001f71003906504616564200155954770e1072006e590a474c5c09000f111c2a1c537c002d11454e52424800130b442a43183e00230b12451e1e4a0076540d2e590d580058540d373a2237"
len(message) = 500
len(enc) == 1024
```
One thing we notice is that every 8th hex byte starting from the first is zero. What does this mean? Well, looking at the plaintext, every character is in the ASCII alphanumeric + punctuation range, so it only uses 7 bits, leaving the leading byte null. But what about the other bytes?

Here's what I ended up coming up with after some trial and error:
```
c[0] = 0 because each word has a zero here
c[8] = 0 "  "

c[1] = m[k1] ^ m[k2] ^ ... ^ m[kn], such that pm[ki][1] is 1
c[2] = m[k1] ^ m[k2] ^ ... ^ m[kn], such that pm[ki][2] is 1
c[3] = m[k1] ^ m[k2] ^ ... ^ m[kn], such that pm[ki][3] is 1
```

But what does that let us do? Well, since `pm` is a list of binary words (groups of 2 bytes) in our password, we can just come up with candidates that meet the criteria for each byte of ciphertext, and get their intersections with the corresponding ciphertext bytes from the next block, so on and so forth until you have only one candidate.

```python
from itertools import product
from Crypto.Util.number import long_to_bytes, bytes_to_long

f = open('message_rp.txt', 'rb')
msg = f.read().strip()
f.close()
f = open('enc_rp.txt')
ct = bytes.fromhex(f.read())
f.close()

# Where we're going to store our plaintext.
plaintext = []
# n is the offset from zero in a block
for n in range(16):
    # Our list of candidates
    candidates = set()
    # Iterate through each nth byte of every ciphertext block
    for ind in range(n, len(msg) - 16, 16):
        if len(candidates) == 1:
            plaintext.append(candidates.pop())
            break
        cur = set()
        # For each possible 2-byte word
        for i in product('01', repeat=16):
            out = 0
            # j is the index of the bit, k is the bit itself
            for j, k in enumerate(list(i)):
                if int(k) == 1:
                    out ^= msg[ind-n+j]
            # If we picked a possible word
            if out == ct[ind]:
                cur.add(long_to_bytes(int("".join(list(i)), 2)))
        # If this is the first iteration
        if len(candidates) == 0:
            candidates = cur
        candidates = candidates.intersection(cur)

# We are now left with `pm`, and so we need to reverse the encode() step to get us our password.

# From StackOverflow
def transpose(l1, l2):
    # iterate over list l1 to the length of an item
    for i in range(len(l1[0])):
        # print(i)
        row =[]
        for item in l1:
            # appending to new list with values and index positions
            # i contains index position and item contains values
            row.append(item[i])
        l2.append(row)
    return l2

p = transpose([bin(bytes_to_long(i))[2:].zfill(16) for i in plaintext], [])
print(b''.join([long_to_bytes(int(''.join(i), 2)) for i in p]))
```

This gets the possible candidate words for `pm` and tries it on consecutive ciphertext blocks until it ends up with only one candidate. Then it reverses the `encode()` step on `pm` to get the password.
