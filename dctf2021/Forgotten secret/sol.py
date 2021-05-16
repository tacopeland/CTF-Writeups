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
