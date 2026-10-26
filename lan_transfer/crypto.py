from __future__ import annotations

import base64
import binascii
import secrets
from cryptography.hazmat.primitives import hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

AES_KEY_SIZE = 32
CTR_NONCE_SIZE = 16
AES_BLOCK_SIZE = 16


def generate_credentials() -> tuple[str, bytes, str]:
    """Generates a CSPRNG 4-digit PIN and an AES-256 Base64 key."""
    pin = str(secrets.randbelow(10000)).zfill(4)
    key_bytes = secrets.token_bytes(AES_KEY_SIZE)
    key_b64 = base64.b64encode(key_bytes).decode("utf-8")
    return pin, key_bytes, key_b64


def verify_pin(provided_pin: str | None, expected_pin: str) -> bool:
    """Verifies a PIN in constant time to prevent timing side-channel attacks."""
    if not isinstance(provided_pin, str) or not isinstance(expected_pin, str):
        return False
    try:
        return secrets.compare_digest(provided_pin.encode("utf-8"), expected_pin.encode("utf-8"))
    except Exception:
        return False


def decode_and_validate_key(key_b64: str) -> bytes:
    """Decodes and validates a Base64-encoded 32-byte AES-256 key."""
    if not key_b64 or not key_b64.strip():
        raise ValueError("Encryption key cannot be empty.")
    cleaned = key_b64.strip()
    try:
        key_bytes = base64.b64decode(cleaned, validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ValueError("Invalid Base64 encryption key format.") from exc

    if len(key_bytes) != AES_KEY_SIZE:
        raise ValueError(f"Invalid key length ({len(key_bytes)} bytes); expected {AES_KEY_SIZE} bytes for AES-256.")
    return key_bytes


def get_key_verification_hash(key_bytes: bytes) -> str:
    """Generates a server HMAC-SHA256 tag to prove key possession to the receiver."""
    h = hmac.HMAC(key_bytes, hashes.SHA256())
    h.update(b"LAN-TRANSFER-SERVER-AUTH")
    return base64.b64encode(h.finalize()).decode("utf-8")


def get_client_auth_token(key_bytes: bytes) -> str:
    """Generates a client HMAC-SHA256 tag to prove key possession to the sender before streaming."""
    h = hmac.HMAC(key_bytes, hashes.SHA256())
    h.update(b"LAN-TRANSFER-CLIENT-AUTH")
    return base64.b64encode(h.finalize()).decode("utf-8")


def verify_key(key_bytes: bytes, expected_hash_b64: str) -> bool:
    """Verifies if the server's HMAC-SHA256 tag matches our key."""
    if len(key_bytes) != AES_KEY_SIZE or not expected_hash_b64:
        return False
    h = hmac.HMAC(key_bytes, hashes.SHA256())
    h.update(b"LAN-TRANSFER-SERVER-AUTH")
    try:
        h.verify(base64.b64decode(expected_hash_b64))
        return True
    except Exception:
        return False


def advance_nonce(nonce: bytes, block_offset: int) -> bytes:
    """Advances a 16-byte big-endian AES-CTR nonce counter by block_offset 16-byte blocks."""
    if len(nonce) != CTR_NONCE_SIZE:
        raise ValueError(f"Invalid nonce length ({len(nonce)} bytes); expected {CTR_NONCE_SIZE} bytes.")
    if block_offset < 0:
        raise ValueError("block_offset must be non-negative.")
    counter = (int.from_bytes(nonce, byteorder="big") + block_offset) & ((1 << 128) - 1)
    return counter.to_bytes(CTR_NONCE_SIZE, byteorder="big")


def get_encryptor(key_bytes: bytes, nonce: bytes, byte_offset: int = 0):
    """Returns an AES-256-CTR encryptor positioned at the exact byte_offset."""
    if byte_offset < 0:
        raise ValueError("byte_offset must be non-negative.")
    block_offset, sub_offset = divmod(byte_offset, AES_BLOCK_SIZE)
    adjusted_nonce = advance_nonce(nonce, block_offset) if block_offset else nonce
    encryptor = Cipher(algorithms.AES(key_bytes), modes.CTR(adjusted_nonce)).encryptor()
    if sub_offset:
        encryptor.update(b"\x00" * sub_offset)
    return encryptor


def get_decryptor(key_bytes: bytes, nonce: bytes, byte_offset: int = 0):
    """Returns an AES-256-CTR decryptor positioned at the exact byte_offset."""
    if byte_offset < 0:
        raise ValueError("byte_offset must be non-negative.")
    block_offset, sub_offset = divmod(byte_offset, AES_BLOCK_SIZE)
    adjusted_nonce = advance_nonce(nonce, block_offset) if block_offset else nonce
    decryptor = Cipher(algorithms.AES(key_bytes), modes.CTR(adjusted_nonce)).decryptor()
    if sub_offset:
        decryptor.update(b"\x00" * sub_offset)
    return decryptor
