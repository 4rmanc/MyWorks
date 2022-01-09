import hashlib
import random
from bn254 import point_add, scalar_mult, curve, make_keypair


def noncevalue():
    nonce_value = random.randrange(1, curve.n)
    R_value = scalar_mult(nonce_value, curve.g)
    return nonce_value, R_value

def schnorring(con_hashvalue, private_key, r_value):
    siglet_value = (con_hashvalue*private_key) + r_value
    return siglet_value

def hash(message, nonce_hash):
    concatenating = message + str(nonce_hash).encode()
    concatenated_hash = hashlib.sha512(concatenating).digest()
    e = int.from_bytes(concatenated_hash, 'big')
    z = e 
    return z 

def validating_schnorr(R_value, siglet_value, public_key):
    con_hash = hash(message, R_value)
    Sx, Sy = scalar_mult(siglet_value, curve.g)
    verifierx, verifiery = point_add(scalar_mult(con_hash, public_key), R_value)
    if Sx == verifierx:
        return 'Signature matches'
    else:
        return 'Invalid signature'



private, public = make_keypair()
message = b'Crypto Is The Future :)'
nonce, R = noncevalue()
con_hash = hash(message, R)
siglet = schnorring(con_hash, private, nonce)

print('Curve:', curve.name)
print("Private key:", hex(private))
print("Public key: (0x{:x}, 0x{:x})".format(*public))
print("Siglet:", hex(siglet))
print("R value(rG): (0x{:x}, 0x{:x})".format(*R))
print("Message: ", message)
print('Verification:', validating_schnorr(R, siglet, public))


