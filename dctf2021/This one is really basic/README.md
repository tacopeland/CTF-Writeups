# This one is really basic

This was a really basic challenge. You are given a very large ciphertext that notably looks like base64 in `cipher.txt`.

After running `base64 -d cipher.txt`, we are left with another base64 string. Now, the hint for this challenge mentioned the meaning of life, which is obviously 42, so this should be a 42-iterated base64 encoding of our flag.

I made a quick script to solve it.

```python
from base64 import b64decode

fp = open('cipher.txt')

res = fp.read()
for _ in range(42):
    res = b64decode(res)

print(res)
```

This returned the flag.
