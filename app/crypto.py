import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes

from app.config import settings

_aes_key: bytes | None = None


def derive_key() -> bytes:
    """Derive a 256-bit AES key from master secret using PBKDF2."""
    global _aes_key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=settings.pbkdf2_salt.encode(),
        iterations=settings.pbkdf2_iterations,
    )
    _aes_key = kdf.derive(settings.master_secret.encode())
    return _aes_key


def get_key() -> bytes:
    if _aes_key is None:
        return derive_key()
    return _aes_key


def encrypt_file(plaintext: bytes) -> tuple[bytes, bytes]:
    """Encrypt plaintext with AES-256-GCM. Returns (nonce, ciphertext)."""
    nonce = os.urandom(12)
    aesgcm = AESGCM(get_key())
    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    return nonce, ciphertext


def decrypt_file(nonce: bytes, ciphertext: bytes) -> bytes:
    """Decrypt ciphertext with AES-256-GCM."""
    aesgcm = AESGCM(get_key())
    return aesgcm.decrypt(nonce, ciphertext, None)
