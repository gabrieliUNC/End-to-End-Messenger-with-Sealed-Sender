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
        self.__name = name
        self.__server_signing_pk = server_signing_pk
        self.__server_encryption_pk = server_encryption_pk
        self.__conns = {}
        self.certs = {}
        self.__messages = {}

        sk, pk = self.__GENERATE_DH()
        self.__sk = sk
        self.__pk = pk
        self.__sealedSender = SealedSender(self.__sk, self.__pk, self.__server_signing_pk)


    def generateCertificate(self):
        """Generate a certificate for a user."""

        certificate = {
            "name": self.__name,
            "pk": self.__pk
        }
        return certificate
    
    def publicMessages(self):
        return self.__messages


    def receiveCertificate(self, certificate, signature):
        """Verify a certificate received from another user."""

        name, publicKey = certificate["name"], certificate["pk"]
        try:
            self.__verifySignature(certificate,signature,self.__server_signing_pk)
        except:
            raise ValueError("Invalid signature.")
        
        if name == self.__name:
            self.__sealedSender.cert = certificate
            self.__sealedSender.sig = signature
        else:
            self.certs[name] = certificate

    
    def sendSealedMessage(self, name, message):
        """Given a recipient and a message, create an envelope and sealed message to anonymously send."""

        recipient_pub = self.certs[name]['pk']
        header, message_ct = self.__sendMessage(name, message)
        sender_ephemeral_pub, e_chainKey, envelope_ct, envelope_mac = self.__sealedSender.makeEnvelope(recipient_pub)
        sealed_ct, sealed_mac = self.__sealedSender.sealMessage(message_ct, recipient_pub, e_chainKey, envelope_ct, envelope_mac)

        return header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac
    

    def __receiveSealedMessage(self, header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac):
        """Given an envelope and sealed message, retrieve the senders public identity and unseal the message."""

        try:
            sender_pub, d_chainKey = self.__sealedSender.unSealEnvelope(sender_ephemeral_pub, envelope_ct, envelope_mac)
            name, message_ct = self.__sealedSender.decryptSealedMessage(sender_pub, d_chainKey, envelope_ct, envelope_mac, sealed_ct, sealed_mac)

            pt = self.__receiveMessage(name, header, message_ct)
        except Exception:
            return None
        
        if name in self.__messages:
            self.__messages[name].append(pt)
        else:
            self.__messages[name] = []
            self.__messages[name].append(pt)

        return pt
    

    def receiveMail(self, header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac):
        self.__receiveSealedMessage(header, sender_ephemeral_pub, envelope_ct, envelope_mac, sealed_ct, sealed_mac)
        

    def __sendMessage(self, name, message):
        """End-2-End encrypted messaging sender."""

        publicKey = self.certs[name]["pk"]

        if name not in self.__conns:
            SK = self.__DH((self.__sk, self.__pk), publicKey)
            self.__startSending(name, SK)

            ct = self.__RatchetENCRYPT(message, self.__conns[name].DHs, name)

            return self.__pk, ct
        
        pk = self.__conns[name].DHs[1]

        ct = self.__RatchetENCRYPT(message, self.__conns[name].DHs, name)

        # print(len(pkToBytes(pk) + ct))
        
        return pk, ct


    def __receiveMessage(self, name, header, ciphertext):
        """End-2-End encrypted messaging receiver."""

        if name not in self.__conns:
            SK = self.__DH((self.__sk,self.__pk), header)
            self.__startReceiving(name, SK)
        try:
            pt = self.__RatchetDecrypt(ciphertext, header, name)
        except Exception:
            return None
        
        return pt


    def __report(self, name, message):
        """Given a sender and message, encrypt the message to be reported."""

        sk, u = self.__GENERATE_DH()
        v = sk.exchange(ec.ECDH(), self.__server_encryption_pk)
        digest = hashes.Hash(hashes.SHA256())
        digest.update(pkToBytes(u) + v)
        k = digest.finalize()

        textReport = "Inappropriate message by " + name + ": " + message
        ct = self.__ENCRYPT(textReport, None, k)
        return textReport, (u, ct)

    #===========================================Helper Methods===========================================#


    def __GENERATE_DH(self):
        """Generate a DH private key, public key pair."""

        private_key = ec.generate_private_key(
            ec.SECP256R1()
        )
        public_key = private_key.public_key()
        return private_key, public_key
        

    def __DH(self, dh_pair, dh_pub):
        """Perform DH key exchange."""

        rootKey = dh_pair[0].exchange(ec.ECDH(), dh_pub)
        sharedKey = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=DH_NONCE,
        ).derive(rootKey)
        return sharedKey


    def __KDF_RK(self, rootKey, dh_out):
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

    def __KDF_CK(self, ck):
        """Perform key derivation on a chain key."""

        h = hmac.HMAC(ck, hashes.SHA256())
        h.update(CK_NONCE_1)
        chainKey = h.finalize()

        h = hmac.HMAC(ck, hashes.SHA256())
        h.update(CK_NONCE_2)
        messageKey = h.finalize()

        return chainKey, messageKey

    def __verifySignature(self, message, signature, vk):
        """Verify a signature on a message."""

        msg_str = str(message)
        msg_bytes = msg_str.encode('utf-8')
        signature = unpad(signature)
        vk.verify(signature, msg_bytes, ec.ECDSA(hashes.SHA256()))

    def __ENCRYPT(self, msg, header, key):
        """Encrypt a message and associated data (header) using AES-GCM."""

        aesgcm = AESGCM(key)
        ct = aesgcm.encrypt(CIPHER_NONCE, self.msgToBytes(msg), pkToBytes(header))
        return ct
    
    def __RatchetENCRYPT(self, msg, header, name):
        """Perform the Double Ratchet step for End-2-End Encryption and encrypt message."""

        header = header[1]
        self.__conns[name].CKs, mk = self.__KDF_CK(self.__conns[name].CKs)
        return self.__ENCRYPT(msg, header, mk)
    
    def __RatchetDecrypt(self, ct, header, name):
        """Perform the Double Ratchet step for End-2-End Encryption and decrypt message."""

        if header != self.__conns[name].DHr:
            self.__DHRatchet(name, header)
        self.__conns[name].CKr, mk = self.__KDF_CK(self.__conns[name].CKr)
        return DECRYPT(mk, ct, header)

    def msgToBytes(self, msg):
        return bytes(msg, 'ascii')
    
    def __DHRatchet(self, name, header):
        """Perform the Diffie-Helman ratchet step."""

        self.__conns[name].DHr = header
        self.__conns[name].rk, self.__conns[name].CKr = self.__KDF_RK(self.__conns[name].rk, self.__DH(self.__conns[name].DHs, self.__conns[name].DHr))
        self.__conns[name].DHs = self.__GENERATE_DH()
        self.__conns[name].rk, self.__conns[name].CKs = self.__KDF_RK(self.__conns[name].rk, self.__DH(self.__conns[name].DHs, self.__conns[name].DHr))

    def __startSending(self, name, SK):
        """Establish a connection on first message sent."""

        self.__conns[name] = state()
        self.__conns[name].DHs = self.__sk, self.__pk
        self.__conns[name].DHr = self.certs[name]["pk"]
        self.__conns[name].rk, self.__conns[name].CKs = self.__KDF_RK(SK, SK)
        self.__conns[name].CKr = None

    def __startReceiving(self, name, SK):
        """Establish a connection on first message received."""

        self.__conns[name] = state()
        self.__conns[name].DHs = self.__sk, self.__pk
        self.__conns[name].DHr = None
        self.__conns[name].rk = SK
        self.__conns[name].CKs = None
        self.__conns[name].CKr = None
