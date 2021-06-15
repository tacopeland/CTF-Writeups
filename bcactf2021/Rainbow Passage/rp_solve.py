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
