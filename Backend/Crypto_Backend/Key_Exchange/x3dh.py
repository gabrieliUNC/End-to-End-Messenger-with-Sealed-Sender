from cryptography import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from helper_funcs import pkFromBytes, pkToBytes

INFO = 'MessengerProtocol'

class KeyExchangeClient:

    def __init__(self):
        self.sk, self.pk = self.generateKeys()


    def generateKeys(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    

    def DH(self, private_key, peer_pk):
        shared_key = private_key.exchange(peer_pk)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        return derived_key
    

