"""Low-level crypto primitives used by MeshCore channels.

These are deliberately tiny wrappers so the channel hash, AES key and MAC stay
byte-for-byte consistent between encoding and decoding.
"""

import hashlib
import hmac
import ucryptolib as cryptolib


def sha256(data: bytes) -> bytes:
    return hashlib.sha256(data).digest()


def hmac_sha256(key: bytes, msg: bytes) -> bytes:
    return hmac.new(key, msg, hashlib.sha256).digest()


def encrypt_aes_ecb(key: bytes, plaintext: bytes) -> bytes:
    # ucryptolib.aes expects a 16/24/32-byte key; mode 1 is ECB.
    return cryptolib.aes(key[:16], 1).encrypt(plaintext)


def decrypt_aes_ecb(key: bytes, ciphertext: bytes) -> bytes:
    return cryptolib.aes(key[:16], 1).decrypt(ciphertext)
