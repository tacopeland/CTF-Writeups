# Just Take Your Time

In this challenge, with the description "Let's go. In and out. 2 second adventure.", you are given a Python script `just-take-your-time.py` and a link to a server running that script, and are required to get the flag.

Looking in `just-take-your-time.py`, we see it first gives you a simple preliminary challenge (recieve two numbers and send their product), and then gives you the real challenge if you can pass that:

```python
# Preliminary
a = randint(1000000000000000, 9999999999999999)
b = randint(1000000000000000, 9999999999999999)

print("Show me you are worthy and solve for x! You have one second.")
print("{} * {} = ".format(a, b))
 ...
assert(a*b == int(answ))
```

This can be solved with a simple application of pwntools:
```python
from pwn import *

r = remote('dctf-chall-just-take-your-time.westeurope.azurecontainer.io', 9999)
r.recvline() # Eat up the "Show me you are worthy" line
question = r.recvline() # a + b = c
parts = question.split()
a = int(parts[0])
b = int(parts[2])

r.sendline(str(a * b))
```


Now, on to the real challenge.

While this challenge may seem hard to read, what it does is simple; here is the pseudocode:
```
secret = ...  // Line 28
key = derive key from the current time in seconds  // Line 27

send encrypt(secret, key)  // Line 32

repeat 3 times:  // Line 35
    value = recieve input  // Line 37
    if this value is the secret, then print the flag  // Line 40-41 then line 53
```

While the encryption method is DES3, we don't need to break the crypto to solve this challenge.
All we need to do is do exactly the same thing as the server, but decrypt the recieved value instead of encrypting the secret.
We need to do this at most 3 seconds before the server derives the key, because we only have 3 guesses.

So, here is what we would do: finish the preliminary task, but before sending the result we save the time in the same format as the server (`int(time())`) so that our calculation of the time is done slightly before the server's calculation. Then, we must recieve the encrypted secret from the server, and use our previously recorded time to derive a key. We will try decrypting the ciphertext with that key and sending it to the server. If the secret doesn't match our decryption, then we will try this two more times, with the previously recorded time plus one and two seconds respectively. Here is how that looks in Python:

```python
from pwn import *
from Crypto.Cipher import DES3
from time import time

...

time = int(time())
r.sendline(str(a * b))

r.recvline() # eat the unneeded line
ct_hex = r.recvline()
r.recvuntil('> ') # eat the prompt
ct = bytes.fromhex(ct_hex.decode())

for i in range(3):
    key = str(time + i).zfill(16).encode("utf-8")
    cipher = DES3.new(key, DES3.MODE_CFB, b"00000000") # code taken from the server
    res = cipher.decrypt(ct)
    r.sendline(res)

print(r.recvall().decode())
```

This prints our flag, without needing to break any cryptography. We just needed to match the timings.
