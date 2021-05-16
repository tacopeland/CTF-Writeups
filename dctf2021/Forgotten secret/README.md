# Forgotten secret

For this challenge you were given a docker image and a hint that it doesn't follow best practices.
To get the files from the image, you just need to untar it:
```
tar xf image
for f in `ls */layer.tar`; do tar xf $f; done
```
This leaves us with 3 files of interest among the extracted files: `7dabd7d32d701c6380d8e9f053d83d050569b063fbcf7ebc65e69404bed867a5.json`, `root/.ssh/id_rsa` and `home/alice/cipher.bin`.
After viewing the SSH private key in `id_rsa` and the ciphertext in `cipher.bin`, I had a look in `7dabd7d32d701c6380d8e9f053d83d050569b063fbcf7ebc65e69404bed867a5.json`. In this file, everything is normal except for a leaked environment variable, `SECRET_KEY`. But how can this help us?

So, after trying to open `id_rsa` in the python interpreter, we get an invalid key format error. So, that must mean that `id_rsa` is encrypted. But with which key? Luckily we have `SECRET_KEY` from before.

```python
from Crypto.PublicKey import RSA
from Crypto.Util.number import bytes_to_long, long_to_bytes

SECRET_KEY = '58703273357638792F423F4528482B4D6251655468566D597133743677397A24'
f_key = open('root/.ssh/id_rsa')
f_ct = open('home/alice/cipher.bin', 'rb')
key_txt = f_key.read()
ct = f_ct.read()

key = RSA.import_key(key_txt, passphrase=SECRET_KEY)
pt = long_to_bytes(pow(bytes_to_long(ct), key.d, key.n))
print(pt)
```

As there were only three files of interest, is was obvious that `cipher.bin` would be what needs decryption. After unlocking the SSH private key `id_rsa`, I just converted the ciphertext to an integer, and manually decrypted it with `c^d mod n`.
