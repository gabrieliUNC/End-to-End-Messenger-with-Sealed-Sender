from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import xeddsa
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from helper_funcs import pkFromBytes, pkToBytes, skToBytes
import os
from constants import CIPHER_NONCE

INFO = b'MessengerProtocol'
F = b'FF' * 32
HKDF_SALT = b'0' * 32
FIRST_MSG = b'First message'


class State:
    def __init__(self, Ipk, preKeyPK, preKeySig, OPKs):
        self.Ipk = Ipk
        self.preKeyPK = preKeyPK
        self.preKeySig = preKeySig
        self.OPKs = OPKs

class KeyExchangeServer:
    def __init__(self):
        self.conns = {}

    def receivePreKeys(self, name, Ipk, preKeyPK, preKeySig, OPKs):
        self.conns[name] = State(Ipk, preKeyPK, preKeySig, OPKs)

    
    def sendPreKeys(self, name):
        i = (int.from_bytes(os.urandom(2), byteorder='little')) % len(self.conns[name].OPKs)
        return self.conns[name].Ipk, self.conns[name].preKeyPK, self.conns[name].preKeySig, self.conns[name].OPKs[i], i
        


    
class KeyExchangeClient:
    def __init__(self, name):
        self.name = name
        self.i = -1
        self.Isk, self.Ipk = self.generateKeys()

        self.preKeySK, self.preKeyPK = self.generateKeys()
        self.preKeySig = self.SIGN(self.Isk, pkToBytes(self.preKeyPK))

        self.OPKs = []
        # n = int.from_bytes(os.urandom(2), byteorder='little')
        n = 5
        for i in range(n):
            self.OPKs.append(self.generateKeys())


    def publishKeys(self):
        return self.name, self.Ipk, self.preKeyPK, self.preKeySig, [ _[1] for _ in self.OPKs]
    

    def sendMessage(self, Ipk, preKeyPK, preKeySig, opk = None):
        try:
            self.VERIFY(Ipk, pkToBytes(preKeyPK), preKeySig)
        except Exception:
            raise ValueError("Verification failed!")
        
        AD = pkToBytes(self.Ipk) + pkToBytes(Ipk)
        # print(AD)
        # print(self.Ipk)
        # print(Ipk)
        
        EKsk, EKpk = self.generateKeys()
        
        preKeyPK = xeddsa.bindings.ed25519_pub_to_curve25519_pub(pkToBytes(preKeyPK))
        Ipk = xeddsa.bindings.ed25519_pub_to_curve25519_pub(pkToBytes(Ipk))
        
        DH1 = xeddsa.bindings.x25519(skToBytes(self.Isk), preKeyPK)
        print(DH1)
        DH2 = xeddsa.bindings.x25519(skToBytes(EKsk), Ipk)
        DH3 = xeddsa.bindings.x25519(skToBytes(EKsk), preKeyPK)


        if opk:
            opk = xeddsa.bindings.ed25519_pub_to_curve25519_pub(pkToBytes(opk))
            DH4 = xeddsa.bindings.x25519(skToBytes(EKsk), opk)
            self.SK = self.KDF(DH1 + DH2 + DH3 + DH4)
        else:
            self.SK = self.KDF(DH1 + DH2 + DH3)
        
        # print(self.SK)

        aesgcm = AESGCM(self.SK)
        ct = aesgcm.encrypt(CIPHER_NONCE, FIRST_MSG, AD)

        return self.Ipk, EKpk, self.i, ct
    
    
    def receiveMessage(self, Ipk, EKpk, i, ct):
        # print(self.Ipk)
        # print(Ipk)
        AD = pkToBytes(Ipk) + pkToBytes(self.Ipk)
        # print(AD)
        
        Ipk = xeddsa.bindings.ed25519_pub_to_curve25519_pub(pkToBytes(Ipk))
        EKpk = xeddsa.bindings.ed25519_pub_to_curve25519_pub(pkToBytes(EKpk))
        
        DH1 = xeddsa.bindings.x25519(skToBytes(self.preKeySK), Ipk)
        print(DH1)
        DH2 = xeddsa.bindings.x25519(skToBytes(self.Isk), EKpk)
        DH3 = xeddsa.bindings.x25519(skToBytes(self.preKeySK), EKpk)
        
        if i != -1:
            opk = self.OPKs[i]
            DH4 = xeddsa.bindings.x25519(skToBytes(opk[0]), EKpk)
            self.SK = self.KDF(DH1 + DH2 + DH3 + DH4)
        else:
            self.SK = self.KDF(DH1 + DH2 + DH3)
        
        # print(self.SK)
        
        aesgcm = AESGCM(self.SK)
        
        # pt = aesgcm.decrypt(CIPHER_NONCE, ct, AD)
        
        return


    def generateKeys(self):
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key


    def DH(self, private_key, peer_pk):
        shared_key = private_key.exchange(peer_pk)
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=64,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        return derived_key
    

    def SIGN(self, signing_key, msg):
        # msg = bytes(msg, 'ascii')
        sig = signing_key.sign(msg)
        return sig
    

    def VERIFY(self, public_key, msg, sig):
        # msg = bytes(msg, 'ascii')
        try:
            public_key.verify(sig, msg)
        except Exception:
            raise ValueError("Verification failed!")        
        

    def KDF(self, IKM):
        derived_key = HKDF(
            algorithm=hashes.SHA512(),
            length=32,
            salt=HKDF_SALT,
            info=INFO,
        ).derive(F + IKM)

        return derived_key
        


bob = KeyExchangeClient('bob')


name, Ipk, preKeyPK, preKeySig, OPKs = bob.publishKeys()



server = KeyExchangeServer()
server.receivePreKeys(name, Ipk, preKeyPK, preKeySig, OPKs)

Ipk, preKeyPK, preKeySig, opk, i = server.sendPreKeys(name)

alice = KeyExchangeClient('alice')
Ipk, EKpk, i, ct = alice.sendMessage(Ipk, preKeyPK, preKeySig, opk)
alice.i = i

bob.receiveMessage(Ipk, EKpk, i, ct)
