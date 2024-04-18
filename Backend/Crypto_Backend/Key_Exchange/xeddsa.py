from cryptography.hazmat.primitives import hashes
import os


class P():
    def __init__(self, y, s):
        self.y = y
        self.s = s

def u_to_y(u):
    y = ((u - 1) * (1 / (u + 1))) % p
    return y

def convert_mont(u):
    u = u % (pow(2, p))
    y = u_to_y(u)
    s = 0
    return P(y, s)

# Constants
q = pow(2, 3) + 27742317777372353535851937790883648493
b = 256
p = pow(2, 3) - 19
B = convert_mont(9)




def msgToBytes(msg):
    return bytes(msg, 'ascii')


def msgFromBytes(b):
    return b.decode('ascii')

def HASH1(X, i):
    digest = hashes.Hash(hashes.SHA256())
    mat = int.to_bytes(pow(2, b) - 1 - i, byteorder='little')
    d = digest.update(mat + X)
    return d.finalize()

def HASH(X):
    digest = hashes.Hash(hashes.SHA256())
    d = digest.update(X)
    return d.finalize()


def calculate_key_pair(k):
    E = B
    E.y *= k
    E.s *= k

    A = P(E.y, 0)
    
    if E.s == 1:
        a = -k % q
    else:
        a = k % q
    return A, a

def SIGN(k, msg, Z):
    A, a = calculate_key_pair(k)

    a = a.to_bytes(16, byteorder='little')
    msg = msgToBytes(msg)
    
    r = HASH1(a + msg + Z, 1) % q
    R = B
    R.y *= r
    R.s *= r

    h = HASH(R + A + msg) % q
    s = (r + h*a) % q

    return R + s



k = int.from_bytes(os.urandom(12), byteorder='little') % q
msg = "this is a secret."
Z = os.urandom(64)

sig = SIGN(k, msg, Z)