from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from helper_funcs import pkFromBytes, pkToBytes
import os
from constants import CIPHER_NONCE

INFO = 'MessengerProtocol'
F = b'FF' * 32
HKDF_SALT = b'0' * 64
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
        return self.conns[name].Ipk, self.conns[name].preKeyPK, self.conns[name].preKeySig, self.conns[name].OPKs[i]
        


    
class KeyExchangeClient:
    def __init__(self, name):
        self.name = name
        self.Isk, self.Ipk = self.generateKeys()

        self.preKeySK, self.preKeyPK = self.generateKeys()
        self.preKeySig = self.SIGN(self.Isk, pkToBytes(self.preKeyPK))

        self.OPKs = []
        # n = int.from_bytes(os.urandom(2), byteorder='little')
        n = 5
        for i in range(n):
            self.OPKs.append(self.generateKeys())


    def publishKeys(self):
        return self.name, self.Ipk, self.preKeyPK, self.preKeySig, self.OPKs
    

    def receiveKeys(self, Ipk, preKeyPK, preKeySig, opk = None):
        try:
            self.VERIFY(Ipk, pkToBytes(preKeyPK), preKeySig)
        except Exception:
            raise ValueError("Verification failed!")
        
        EKsk, EKpk = self.generateKeys()

        DH1, DH2, DH3 = self.DH(self.Isk, preKeyPK), self.DH(self.EKsk, Ipk), self.DH(self.EKsk, preKeyPK) 

        if opk:
            DH4 = self.DH(self.EKsk, opk)
            SK = self.KDF(DH1 + DH2 + DH3 + DH4)
        else:
            SK = self.KDF(DH1 + DH2 + DH3)


        AD = pkToBytes(self.Ipk) + pkToBytes(Ipk)

        aesgcm = AESGCM(SK)
        ct = aesgcm.encrypt(CIPHER_NONCE, FIRST_MSG, AD)

        return self.Ipk, EKpk, opk, ct


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
            length=64,
            salt=HKDF_SALT,
            info=INFO,
        ).derive(F + IKM)

        return derived_key
        


bob = KeyExchangeClient('bob')


name, Ipk, preKeyPK, preKeySig, OPKs = bob.publishKeys()



server = KeyExchangeServer()
server.receivePreKeys(name, Ipk, preKeyPK, preKeySig, OPKs)

Ipk, preKeyPK, preKeySig, opk = server.sendPreKeys(name)

alice = KeyExchangeClient('alice')
Ipk, EKpk, opk, ct = alice.receiveKeys(Ipk, preKeyPK, preKeySig, opk)