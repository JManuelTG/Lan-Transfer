import base64
import secrets
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, hmac

def generate_credentials():
    """Generates a 4-digit PIN and an AES-256 base64 key."""
    pin = str(secrets.randbelow(10000)).zfill(4)
    key_bytes = secrets.token_bytes(32)
    key_b64 = base64.b64encode(key_bytes).decode('utf-8')
    return pin, key_bytes, key_b64

def get_key_verification_hash(key_bytes):
    """Generates an HMAC-SHA256 hash to verify the key without exposing it."""
    h = hmac.HMAC(key_bytes, hashes.SHA256())
    h.update(b"LAN-TRANSFER-AUTH")
    return base64.b64encode(h.finalize()).decode('utf-8')

def verify_key(key_bytes, expected_hash_b64):
    """Verifies if the provided key matches the expected hash."""
    h = hmac.HMAC(key_bytes, hashes.SHA256())
    h.update(b"LAN-TRANSFER-AUTH")
    try:
        h.verify(base64.b64decode(expected_hash_b64))
        return True
    except Exception:
        return False

def get_encryptor(key_bytes, nonce):
    """Returns an AES-CTR encryptor."""
    return Cipher(algorithms.AES(key_bytes), modes.CTR(nonce)).encryptor()

def get_decryptor(key_bytes, nonce):
    """Returns an AES-CTR decryptor."""
    return Cipher(algorithms.AES(key_bytes), modes.CTR(nonce)).decryptor()
