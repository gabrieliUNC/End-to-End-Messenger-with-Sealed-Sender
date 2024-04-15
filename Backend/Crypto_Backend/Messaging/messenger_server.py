from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from helper_funcs import DECRYPT, pkToBytes, pad

class MessengerServer:
    def __init__(self, server_signing_key, server_decryption_key):
        self.server_signing_key = server_signing_key
        self.server_decryption_key = server_decryption_key

    def decryptReport(self, ct):
        """Given an encrypted reported message, decrypt the message."""

        u, ct = ct[0], ct[1]
        v = self.server_decryption_key.exchange(ec.ECDH(), u)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pkToBytes(u) + v)
        k = digest.finalize()
        
        return DECRYPT(k, ct, None)

    def signCert(self, cert):
        """Given a certificate from a user, sign that this is there public key and name."""

        cert_str = str(cert)
        cert_bytes = cert_str.encode('utf-8')
        signature = self.server_signing_key.sign(cert_bytes, ec.ECDSA(hashes.SHA256()))
        signature = pad(signature)
        
        return signature