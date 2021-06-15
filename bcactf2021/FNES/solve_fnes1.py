# IDEA: Just encrypt something, xor it with the ciphertext to get the keystream
# then xor 'Open sesame... Flag please!' with the keystream to get your ct
# then decrypt that.


from pwn import *


TARGET = b"Open sesame... Flag please!"
LENGTH = len(TARGET)

r = remote('crypto.bcactf.com', 49153)

r.recvuntil(b'>>> ')
r.sendline(b'E')
r.recvuntil(b'>>> ')
r.sendline(b'\x00' * LENGTH)
r.recvuntil(b'Here\'s your message:\n')
keystream = bytes.fromhex(r.recvline().decode())


r = remote('crypto.bcactf.com', 49153)
ct = bytes([a ^ b for a, b in zip(keystream, TARGET)])
r.recvuntil(b'>>> ')
r.sendline(b'D')
r.recvuntil(b'>>> ')
r.sendline(ct.hex())
r.interactive()
