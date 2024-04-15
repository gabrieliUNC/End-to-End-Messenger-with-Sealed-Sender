from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from constants import CIPHER_NONCE


def pkToBytes(public_key):
    """Takes an EC public key and converts it to bytes format for crypto functions."""

    if public_key == None:
        return None
    serialized_public = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    return serialized_public


def bytesToPt(t):
    """Decodes bytes into ascii."""

    return t.decode('ascii')


def DECRYPT(key, ct, header):
    """Performs AES-GCM decryption on ciphertext with associated data (header)."""

    aesgcm = AESGCM(key)
    pt = aesgcm.decrypt(CIPHER_NONCE, ct, pkToBytes(header))
    return bytesToPt(pt)


def pad(msg):
    """Pads a message to 128 bytes."""

    padder = padding.PKCS7(128).padder()
    padded_data = padder.update(msg)
    padded_data += padder.finalize()
    return padded_data

    
def unpad(padded_msg):
    """Unpads a padded message."""

    unpadder = padding.PKCS7(128).unpadder()
    data = unpadder.update(padded_msg)
    data += unpadder.finalize()
    return data


def deriveEnvelopeKeys(salt, key_material):
    """Generates the keys for encryption / MAC in makeEnvelope()."""

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=96,
        salt=salt,
        info=b''
    )
    key = hkdf.derive(key_material)

    return key[:32], key[32:64], key[64:]


def MAC(key, ct):
    """Generates the Message Authentication Code (tag) for a ciphertext."""

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(ct)
    return h.finalize()


def VERIFY(msg, key, tag):
    """Verifies a Message Authentication Code (tag) on a message / ciphertext."""

    h = hmac.HMAC(key, hashes.SHA256())
    h.update(msg)
    
    try:
        h.verify(tag)
    except Exception:
        return False
    
    return True


def deriveSealKeys(salt, key_material):
    """Generates the seal keys for sealMessage()."""

    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=64,
        salt=salt,
        info=b''
    )
    key = hkdf.derive(key_material)

    return key[:32], key[32:]


def pkFromBytes(public_key):
    """Derives a public key from the encoded bytes."""

    return load_pem_public_key(public_key)   