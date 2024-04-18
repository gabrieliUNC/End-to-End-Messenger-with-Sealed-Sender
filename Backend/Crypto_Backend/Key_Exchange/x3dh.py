from cryptography import hashes
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from helper_funcs import pkFromBytes, pkToBytes

INFO = 'MessengerProtocol'

class KeyExchangeClient:

    def __init__(self):
        self.sk, self.pk = self.generateKeys()

    # Generate public and private keys with X25519 curve
    def generateKeys(self):
        private_key = X25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    # Encode public key into byte sequence
    def encode(self, private_key):
        curve_byte = b'\x01'
        pk_bytes = pkToBytes(private_key)
        encoded_pk = pk_bytes + curve_byte
        return encoded_pk
    
    # Establish Diffie-Hellman shared secret output
    def DH(self, private_key, peer_pk):
        shared_key = private_key.exchange(peer_pk)
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=None,
            info=b'handshake data',
        ).derive(shared_key)
        
        return derived_key
    
    # Sign message using private key and return signature
    def Sig(self, private_key, message):
        signature = private_key.sign(message)
        return signature
    
    # Verify signature
    def verify(self, public_key, signature, message):
        try:
            public_key.verify(message, signature)
            return True
        except Exception as e:
            return False
