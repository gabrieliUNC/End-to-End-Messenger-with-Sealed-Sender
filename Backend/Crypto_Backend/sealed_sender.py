from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from constants import DH_NONCE, AES_NONCE
from helper_funcs import pkFromBytes, pkToBytes, pad, unpad, deriveEnvelopeKeys, deriveSealKeys, MAC, VERIFY

class SealedSender:

    def __init__(self, sk, pk, server_signing_pk):
        self.sk = sk
        self.pk = pk
        self.server_signing_pk = server_signing_pk


    def makeEnvelope(self, recipient_pub):
        """Encrypt sender public key in envelope."""

        # Step One: Generate ephemeral Sending Keys for DH key exchange
        sender_ephemeral_priv = ec.generate_private_key(ec.SECP256R1())
        sender_ephemeral_pub = sender_ephemeral_priv.public_key()

        # Step Two: Derive envelope chain, cipher, and mac keys
        ikm = self.DH((sender_ephemeral_priv, sender_ephemeral_pub), recipient_pub)
        salt = pkToBytes(recipient_pub) + pkToBytes(sender_ephemeral_pub)
        e_chainKey, e_cipherKey, e_macKey = deriveEnvelopeKeys(salt=salt, key_material=ikm)


        # Step Three: Encrypt Sender Identity and place in envelope
        nonce = AES_NONCE
        aes = Cipher(algorithms.AES256(e_cipherKey), modes.CTR(nonce))
        aes = aes.encryptor()
        envelope_ct = aes.update(pkToBytes(self.pk)) + aes.finalize()

        # Step Four: MAC envelope ciphertext
        envelope_mac = MAC(e_macKey, envelope_ct)

        return sender_ephemeral_pub, e_chainKey, envelope_ct, envelope_mac


    def unSealEnvelope(self, sender_ephemeral_pub, envelope_ct, envelope_mac):
        """Decrypt sender public key from envelope."""

        # Step one: Perform DH key exchange to recover shared secret
        ikm = self.DH((self.sk, self.pk), sender_ephemeral_pub)

        # Step Two: Derive envelope chain, cipher, and mac keys
        salt = pkToBytes(self.pk) + pkToBytes(sender_ephemeral_pub)
        d_chainKey, d_cipherKey, d_macKey = deriveEnvelopeKeys(salt=salt, key_material=ikm)

        # Step Three: Verify MAC
        if not VERIFY(msg = envelope_ct, key = d_macKey, tag = envelope_mac):
            raise ValueError("Tag did not verify correctly.")

        # Step Four: Decrypt Sender Identity
        nonce = AES_NONCE
        aes = Cipher(algorithms.AES256(d_cipherKey), modes.CTR(nonce))
        aes = aes.decryptor()
        sender_pub = aes.update(envelope_ct) + aes.finalize()

        return sender_pub, d_chainKey


    def sealMessage(self, message_ct, recipient_pub, e_chainKey, envelope_ct, envelope_mac):
        """Encrypt sender certificate, signature, and message ciphertext in package."""

        # Step One: perform DH key exchange and key derivation
        ikm = self.DH((self.sk, self.pk), recipient_pub)
        sealed_cipherKey, sealedMacKey = deriveSealKeys(salt=e_chainKey + envelope_ct + envelope_mac, key_material=ikm)

        # Step Two: Encrypt Sender Certificate and place in envelope
        nonce = AES_NONCE
        aes = Cipher(algorithms.AES256(sealed_cipherKey), modes.CTR(nonce))
        aes = aes.encryptor()

        sender_cert = (str(self.cert)).encode('utf-8') 
        sender_cert = pad(sender_cert)
        # print(len(sender_cert), len(sender_sig))
        sealed_ct = aes.update(sender_cert + self.sig + message_ct) + aes.finalize()

        # Step Three: MAC sealed ciphertext
        sealed_mac = MAC(sealedMacKey, sealed_ct)

        return sealed_ct, sealed_mac


    def decryptSealedMessage(self, sender_pub, d_chainKey, envelope_ct, envelope_mac, sealed_ct, sealed_mac):
        """Decrypt a given package from sealed sender."""

        # Step One: Perform DH Key exchange
        sender_pub = pkFromBytes(sender_pub)
        ikm = self.DH((self.sk, self.pk), sender_pub)


        # Step Two: Derive Sealed keys
        sealed_cipherKey, sealedMacKey = deriveSealKeys(salt=d_chainKey + envelope_ct + envelope_mac, key_material=ikm)


        #Step Three: Verify Seal
        if not VERIFY(msg = sealed_ct, key = sealedMacKey, tag = sealed_mac):
            raise ValueError("Tag did not verify correctly.")


        # Step Four: Decrypt Sender cert
        nonce = AES_NONCE
        aes = Cipher(algorithms.AES256(sealed_cipherKey), modes.CTR(nonce))
        aes = aes.decryptor()
        seal = aes.update(sealed_ct) + aes.finalize()


        # Step Five: Break seal into sender cert and message ct
        sender_cert, sender_sig, message_ct = seal[:128], seal[128:128 + 80], seal[128 + 80:]
        sender_cert = unpad(sender_cert)
        sender_cert = sender_cert.decode('ascii')
        # sender_cert = json.loads(sender_cert)
        name = sender_cert.split(',')[0].split(':')[1].strip()


        # Step Six: Verify sender cert
        try:
            self.verifySignature(sender_cert, sender_sig, self.server_signing_pk)
        except Exception:
            raise ValueError("Signature Verification Failed!")


        # Step Seven: return message ct
        return name, message_ct
    
    
    #========================================Helper Methods==============================================#

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
    
    
    def verifySignature(self, message, signature, vk):
        """Verify signature on a message."""

        msg_str = str(message)
        msg_bytes = msg_str.encode('utf-8')
        signature = unpad(signature)
        vk.verify(signature, msg_bytes, ec.ECDSA(hashes.SHA256()))