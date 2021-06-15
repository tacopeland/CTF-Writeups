# FNES

In these challenges you are given an online encryption/decryption service and need to leverage that to get the flag.

## FNES 1
"My friend developed this encryption service, and he's been trying to get us all to use it. Sure, it's convenient and easy to use, and it allows you to send encrypted messages easily, and...

Well, I want to get control of his service so I can monitor all the messages! I think he's hidden some features and files behind a secret admin passphrase. Can you help me access those hidden files?"

In this challenge you are given `fnes1.py` and an online challenge service `nc crypto.bcactf.com 49153`. So, lets look at the code:

```python
target_query = "Open sesame... Flag please!"

# ...

tempkey = SHA.new(int(key + int(time.time() / 10)).to_bytes(64, 'big')).digest()[0:16]
cipher = ARC4.new(tempkey)

while True:
    print("Would you like to encrypt (E), decrypt (D), or quit (Q)?", flush=True)
    l = input(">>> ").strip().upper()
    # ...
    elif (l == "E"):
        print("What would you like to encrypt?", flush=True)
        I = input(">>> ").strip()
        if (set(I.lower()) & set("flg!")): # You're not allowed to encrypt any of the characters in "flg!"
            print("You're never getting my flag!", flush=True)
            exit()
        else:
            print("Here's your message:", flush=True)
            c = str(binascii.hexlify(cipher.encrypt(str.encode(I))))[2:-1]
            print(c, flush=True)
    elif (l == "D"):
        print("What was the message?", flush=True)
        I = input(">>> ").strip()
        m = str(cipher.decrypt(binascii.unhexlify(I)))[2:-1]
        if (m == target_query):
            print("Passphrase accepted. Here's your flag:", flush=True)
            print(str(flag)[2:-1], flush=True)
            exit()
        else:
            print("Here's the decoded message:", flush=True)
            print(m, flush=True)
```

What does this mean? Well, we have our target_query, `"Open sesame... Flag please!"`, and we have our cipher `ARC4`, and we have the following logic: we can encrypt anything that doesn't have the characters `flg!` in it, but we need a ciphertext that decrypts to our target_query.

Luckily, we have two things that let us solve this quite easily: within a 5 second window, this challenge uses the same key, and it newly derives the key each time, so whenever you connect two times within 5 seconds, the keystream will be initialized in the exact same way both times. What this means is if you encrypt two things on each connection, they will have the same ciphertext. And, if you encrypt something on one side and decrypt on the other side, the decryption will work. This happens because ARC4 is a stream cipher, and all it does is generate a pad to xor the plaintext with, it doesn't do any fancy transposition.

So, how do we do this? First, we connect to the challenge server and encrypt a string of null bytes. This means that our ciphertext will be the string of null bytes xor'd with the keystream, which will just be the keystream bytes. To leverage this, we make another connection within 5 seconds and send plaintext such that when it is xor'd with the keystream that we got before, the result is our target.

So, lets convert this to python:
```python
# IDEA: Just encrypt something, xor it with the ciphertext to get the keystream
# then xor 'Open sesame... Flag please!' with the keystream to get your ct
# then decrypt that.
from Crypto.Util.strxor import strxor
from pwn import *

TARGET = b"Open sesame... Flag please!"
LENGTH = len(TARGET)

r = remote('crypto.bcactf.com', 49153)

# Encrypt a string of zeros the same length as the target
r.recvuntil(b'>>> ')
r.sendline(b'E')
r.recvuntil(b'>>> ')
r.sendline(b'\x00' * LENGTH)
r.recvuntil(b'Here\'s your message:\n')
keystream = bytes.fromhex(r.recvline().decode())

# Construct our ciphertext
ct = strxor(keystream, TARGET)

# Send it
r = remote('crypto.bcactf.com', 49153)
r.recvuntil(b'>>> ')
r.sendline(b'D')
r.recvuntil(b'>>> ')
r.sendline(ct.hex())
r.interactive()
```

You may have to run this script multiple times to get two connections in the 5-second window.


## FNES 2
"After FNES got cracked, my friend enlisted his ex-girlfriend to help him improve his service. She majored in cryptography, so it should theoretically be quite a bit better now. Unless she installed a backdoor, that is..."
**HINT**: "I think his ex's name was Pythia..."

In this challenge, we are again given the source, `fnes2.py`, and a challenge service. We are also given a hint, implying that this challenge requires an oracle attack (Pythia was an oracle in ancient Greek mythology).

Now, let's look at the code:
```python
# ...

target_query = "Open sesame... Flag please!"

tempkey = SHA.new(int(key + int(time.time() / 10)).to_bytes(64, 'big')).digest()[0:16]

while True:
    print("Would you like to encrypt (E), decrypt (D), or quit (Q)?", flush=True)
    l = input(">>> ").strip().upper()
    # ...
    elif (l == "E"):
        print("What would you like to encrypt?", flush=True)
        I = input(">>> ").strip()
        if (set(I.lower()) & set("flg!nsm")): # Disallowed characters changed to make the target query more difficult
            print("You're never getting my flag!", flush=True)
            exit()
        else:
            iv = secrets.token_bytes(16)
            cipher = AES.new(tempkey, AES.MODE_CBC, iv)
            c = str(binascii.hexlify(iv + cipher.encrypt(pad(str.encode(I), 16))))[2:-1]
            print("Here's your message:", flush=True)
            print(c, flush=True)
    elif (l == "D"):
        print("What was the message?", flush=True)
        I = input(">>> ").strip()
        iv = I[:32]
        I = I[32:]
        try:
            cipher = AES.new(tempkey, AES.MODE_CBC, binascii.unhexlify(iv))
            m = str(unpad(cipher.decrypt(binascii.unhexlify(I)), 16))[2:-1]
            if (m == target_query):
                print("\nPassphrase accepted. Here's your flag:\n", flush=True)
                print(str(flag)[2:-1], flush=True)
                try:
                    with open("advertisement.txt", "r") as ff:
                        print(ff.read(), flush=True)
                except:
                    pass
                exit()
            else:
                print("Here's the decoded message:", flush=True)
                print(m, flush=True)
        except ValueError:
            print("I can't read that!", flush=True)
```

We have a lot here implying a padding oracle attack: we're using AES-CBC, we have different error messages depending on whether the padding is correct or not, and so on. First, however, let's look at the CBC cipher mode in more detail:

### Encryption
![CBC Encryption](https://upload.wikimedia.org/wikipedia/commons/8/80/CBC_encryption.svg)

### Decryption
![CBC Decryption](https://upload.wikimedia.org/wikipedia/commons/2/2a/CBC_decryption.svg)

So, what can we see from these? Well, this means that if we can control the IV and ciphertext, and can also encrypt arbitrary plaintexts that don't contain the illegal characters `flg!nsm`, then we can easily construct an IV and ciphertext that returns our target_query as plaintext.

Here's how:
- First, we replace every illegal byte in `target_query` with `\x00` and name this new version `target_query_fixed`. This gives us the closest plaintext to our target query that still encrypts.
- Then, we connect to the challenge server and encrypt the last 16 bytes of `target_query_fixed`. The IV used in the encryption is given to us as the first 16 bytes of the returned message, with the ciphertext being everything after that.
- This leaves us with an IV and a block of ciphertext. Our block of plaintext is the AES decryption of the ciphertext, xor'd with the IV. Thus, if we xor the IV with the xor of the second block of `target_query` and the second block of `target_query_fixed`, we end up with an IV such that decrypting the block of ciphertext recieved with this IV gives us our desired second block of plaintext.
- Now, this IV is going to be our first block of plaintext. So, we need to know the decryption output of this block of ciphertext so we can construct an IV to make the plaintext what we want. To do this, just send `'\x00' * 16 + iv + ct` to the challenge server for decryption. Then, the first plaintext block returned will be the raw decryption output (since our IV was null).
- Thus, we can xor the output with our desired target query and save that as the IV. Using this is as the IV, we now have a ciphertext that decrypts to our target_query, and thus have the flag.

Here is a python script that implements this:
```python
from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

r = remote('crypto.bcactf.com', 49154)

# What we want to decrypt to
target_query = pad(b"Open sesame... Flag please!", 16)
# The closest thing we can encrypt
target_query_fixed = pad(b"Ope\x00 \x00e\x00a\x00e... \x00\x00a\x00 p\x00ea\x00e\x00", 16)

# Encrypt the second block of our fixed target query
r.recvuntil('>>> ')
r.sendline('E')
r.recvuntil('>>> ')
msg2 = target_query_fixed[16:]
r.sendline(msg2)
r.recvline()
enc2 = bytes.fromhex(r.recvline().decode())
iv2 = enc2[:16]
ct2 = enc2[16:32]

# Fix the IV so that, when encrypted, it gives our target query
ct1 = strxor(strxor(target_query[16:], target_query_fixed[16:]), iv2)

# Decrypt using a zero IV and our two constructed ciphertext blocks
r.recvuntil('>>> ')
r.sendline('D')
r.recvuntil('>>> ')
r.sendline('00' * 16 + ct1.hex() + ct2.hex())
r.recvline()

# Convert result from str(bytes(...))
tmp1 = r.recvline().replace(b'\\\\', b'\\')[:-1]
tmp2 = "b'{}'".format(tmp1.decode())
dec1 = eval(tmp2)[:16]
print("dec1: ", dec1)

# Get an IV such that the first block decrypts to the correct plaintext
iv = strxor(target_query[:16], dec1)

# Decrypt using this new IV
r.recvuntil('>>> ')
r.sendline('D')
r.recvuntil('>>> ')
print("iv: ", iv.hex())
print("ct1: ", ct1.hex())
print("ct2: ", ct2.hex())
r.sendline(iv.hex() + ct1.hex() + ct2.hex())
r.interactive()
```

This returns our flag.
