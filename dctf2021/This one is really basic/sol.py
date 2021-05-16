from base64 import b64decode

fp = open('cipher.txt')


res = fp.read()
for _ in range(42):
    res = b64decode(res)

print(res)
