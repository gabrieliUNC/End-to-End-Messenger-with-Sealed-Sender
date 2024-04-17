# Constants
q = pow(2, 252) + 27742317777372353535851937790883648493
b = 256
p = pow(2, 255) - 19

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
    


def calculate_key_pair(k):
    B = convert_mont(9)
    B.y *= k

    A = P(B.y, 0)
    
    if B.s == 1:
        a = -k % q
    else:
        a = k % q
    return A, a

def SIGN(k, msg, Z):
    A, a 