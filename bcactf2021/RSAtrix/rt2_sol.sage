from Crypto.Util.number import long_to_bytes

p = 94653748632775872562206813156858988240379536044871601072940225022186828970998253
q = 47982815420210848939631963090916124891858755590019708758250635504732488148835047
n = p * q
e = 3
N = 23

R = Zmod(n)
MS = MatrixSpace(R, N, N)
s = PermutationGroupElement('(1,6,8)(2,3,4,5,7)(9,11,13,15,17,19,21,23)(10,12,14,16,18,20,22)')
P = MS(s.matrix())
# They seeded it so this is easy
with seed(1): C = MS([randrange(100) for i in range(N*N)])
G = C * P * C^-1

# Calculate RSA params
phi = (p-1)*(q-1)
d = inverse_mod(e, phi)

# Get ciphertext array
f = open('enc_rt2.txt')
tmp = eval(f.read())
CT = MS(tmp)
del(tmp)

CT = pow(CT, d)

M = C^-1 * CT * C
print(long_to_bytes(M[0][0]))
