from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from constants import DH_NONCE, RK_NONCE, CK_NONCE_1, CK_NONCE_2, CIPHER_NONCE
from helper_funcs import DECRYPT, pkToBytes, unpad
from sealed_sender import SealedSender
from state import state

class MessengerClient:

    def __init__(self, name, server_signing_pk, server_encryption_pk):
        self.name = name
        self.server_signing_pk = server_signing_pk
        self.server_encryption_pk = server_encryption_pk
        self.conns = {}
        self.certs = {}

        sk, pk = self.GENERATE_DH()
        self.sk = sk
        self.pk = pk
        self.sealedSender = SealedSender(self.sk, self.pk, self.server_signing_pk)


    def generateCertificate(self):
        """Generate a certificate for a user."""

        certificate = {
            "name": self.name,
            "pk": self.pk
        }
        return certificate


    def receiveCertificate(self, certificate, signature):
        """Verify a certificate received from another user."""

        name, publicKey = certificate["name"], certificate["pk"]
        try:
            self.verifySignature(certificate,signature,self.server_signing_pk)
        except:
            raise ValueError("Invalid signature.")
        
        if name == self.name:
            self.sealedSender.cert = certificate
            self.sealedSender.sig = signature
        else:
            self.certs[name] = certificate

    
    def sendSealedMessage(self, name, message):
        """Given a recipient and a message, create an envelope and sealed message to anonymously send."""

        recipient_pub = self.certs[name]['pk']
        header, message_ct = self.sendMessage(name, message)
        sender_ephemeral_pub, e_chainKey, envelope_ct, envelope_mac = self.sealedSender.makeEnvelope(recipient_pub)
        sealed_ct, sealed_mac = self.sealedSender.sealMessage(message_ct, recipient_pub, e_chainKey, envelope_ct, envelope_mac)

        return header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac
    

    def receiveSealedMessage(self, header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac):
        """Given an envelope and sealed message, retrieve the senders public identity and unseal the message."""

        try:
            sender_pub, d_chainKey = self.sealedSender.unSealEnvelope(sender_ephemeral_pub, envelope_ct, envelope_mac)
            name, message_ct = self.sealedSender.decryptSealedMessage(sender_pub, d_chainKey, envelope_ct, envelope_mac, sealed_ct, sealed_mac)

            pt = self.receiveMessage(name, header, message_ct)
        except Exception:
            return None
        return pt


    def sendMessage(self, name, message):
        """End-2-End encrypted messaging sender."""

        publicKey = self.certs[name]["pk"]

        if name not in self.conns:
            SK = self.DH((self.sk, self.pk), publicKey)
            self.startSending(name, SK)

            ct = self.RatchetENCRYPT(message, self.conns[name].DHs, name)

            return self.pk, ct
        
        pk = self.conns[name].DHs[1]

        ct = self.RatchetENCRYPT(message, self.conns[name].DHs, name)

        # print(len(pkToBytes(pk) + ct))
        
        return pk, ct


    def receiveMessage(self, name, header, ciphertext):
        """End-2-End encrypted messaging receiver."""

        if name not in self.conns:
            SK = self.DH((self.sk,self.pk), header)
            self.startReceiving(name, SK)
        try:
            pt = self.RatchetDecrypt(ciphertext, header, name)
        except Exception:
            return None
        
        return pt


    def report(self, name, message):
        """Given a sender and message, encrypt the message to be reported."""

        sk, u = self.GENERATE_DH()
        v = sk.exchange(ec.ECDH(), self.server_encryption_pk)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pkToBytes(u) + v)
        k = digest.finalize()

        textReport = "Inappropriate message by " + name + ": " + message
        ct = self.ENCRYPT(textReport, None, k)
        return textReport, (u, ct)

    #===========================================Helper Methods===========================================#


    def GENERATE_DH(self):
        """Generate a DH private key, public key pair."""

        private_key = ec.generate_private_key(
            ec.SECP256R1()
        )
        public_key = private_key.public_key()
        return private_key, public_key
        

    def DH(self, dh_pair, dh_pub):
        """Perform DH key exchange."""

        rootKey = dh_pair[0].exchange(ec.ECDH(), dh_pub)
        sharedKey = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=DH_NONCE,
        ).derive(rootKey)
        return sharedKey


    def KDF_RK(self, rootKey, dh_out):
        """Perform key derivation on a root key."""

        hkdf = HKDF(
            algorithm=hashes.SHA256(),
            length=64,
            salt=rootKey,
            info=RK_NONCE
        )
        key = hkdf.derive(dh_out)
        rootKey = key[:32]
        chainKey = key[32:]
        return rootKey, chainKey

    def KDF_CK(self, ck):
        """Perform key derivation on a chain key."""

        h = hmac.HMAC(ck, hashes.SHA256())
        h.update(CK_NONCE_1)
        chainKey = h.finalize()

        h = hmac.HMAC(ck, hashes.SHA256())
        h.update(CK_NONCE_2)
        messageKey = h.finalize()

        return chainKey, messageKey

    def verifySignature(self, message, signature, vk):
        """Verify a signature on a message."""

        msg_str = str(message)
        msg_bytes = msg_str.encode('utf-8')
        signature = unpad(signature)
        vk.verify(signature, msg_bytes, ec.ECDSA(hashes.SHA256()))

    def ENCRYPT(self, msg, header, key):
        """Encrypt a message and associated data (header) using AES-GCM."""

        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(CIPHER_NONCE, self.msgToBytes(msg), pkToBytes(header))
        return ct
    
    def RatchetENCRYPT(self, msg, header, name):
        """Perform the Double Ratchet step for End-2-End Encryption and encrypt message."""

        header = header[1]
        self.conns[name].CKs, mk = self.KDF_CK(self.conns[name].CKs)
        return self.ENCRYPT(msg, header, mk)
    
    def RatchetDecrypt(self, ct, header, name):
        """Perform the Double Ratchet step for End-2-End Encryption and decrypt message."""

        if header != self.conns[name].DHr:
            self.DHRatchet(name, header)
        self.conns[name].CKr, mk = self.KDF_CK(self.conns[name].CKr)
        return DECRYPT(mk, ct, header)

    def msgToBytes(self, msg):
        return bytes(msg, 'ascii')
    
    def DHRatchet(self, name, header):
        """Perform the Diffie-Helman ratchet step."""

        self.conns[name].DHr = header
        self.conns[name].rk, self.conns[name].CKr = self.KDF_RK(self.conns[name].rk, self.DH(self.conns[name].DHs, self.conns[name].DHr))
        self.conns[name].DHs = self.GENERATE_DH()
        self.conns[name].rk, self.conns[name].CKs = self.KDF_RK(self.conns[name].rk, self.DH(self.conns[name].DHs, self.conns[name].DHr))

    def startSending(self, name, SK):
        """Establish a connection on first message sent."""

        self.conns[name] = state()
        self.conns[name].DHs = self.sk, self.pk
        self.conns[name].DHr = self.certs[name]["pk"]
        self.conns[name].rk, self.conns[name].CKs = self.KDF_RK(SK, SK)
        self.conns[name].CKr = None

    def startReceiving(self, name, SK):
        """Establish a connection on first message received."""

        self.conns[name] = state()
        self.conns[name].DHs = self.sk, self.pk
        self.conns[name].DHr = None
        self.conns[name].rk = SK
        self.conns[name].CKs = None
        self.conns[name].CKr = None
