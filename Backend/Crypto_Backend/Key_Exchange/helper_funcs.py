from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import x25519


def pkToBytes(public_key):
    public_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )
    return public_bytes


def pkFromBytes(public_bytes):
    return x25519.X25519PublicKey.from_public_bytes(public_bytes)
