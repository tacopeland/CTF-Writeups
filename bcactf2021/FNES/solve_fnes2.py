from pwn import *
from Crypto.Util.Padding import pad, unpad
from Crypto.Util.strxor import strxor

r = remote('crypto.bcactf.com', 49154)

target_query = pad(b"Open sesame... Flag please!", 16)
target_query_fixed = pad(b"Ope\x00 \x00e\x00a\x00e... \x00\x00a\x00 p\x00ea\x00e\x00", 16)


r.recvuntil('>>> ')
r.sendline('E')
r.recvuntil('>>> ')
msg2 = target_query_fixed[16:]
r.sendline(msg2)
r.recvline()
enc2 = bytes.fromhex(r.recvline().decode())
iv2 = enc2[:16]
ct2 = enc2[16:32]

ct1 = strxor(strxor(target_query[16:], target_query_fixed[16:]), iv2)

r.recvuntil('>>> ')
r.sendline('D')
r.recvuntil('>>> ')
r.sendline('00' * 16 + ct1.hex() + ct2.hex())
r.recvline()


tmp1 = r.recvline().replace(b'\\\\', b'\\')[:-1]
tmp2 = "b'{}'".format(tmp1.decode())
dec1 = eval(tmp2)[:16]
print("dec1: ", dec1)

iv = strxor(target_query[:16], dec1)

r.recvuntil('>>> ')
r.sendline('D')
r.recvuntil('>>> ')
print("iv: ", iv.hex())
print("ct1: ", ct1.hex())
print("ct2: ", ct2.hex())
r.sendline(iv.hex() + ct1.hex() + ct2.hex())
r.interactive()
