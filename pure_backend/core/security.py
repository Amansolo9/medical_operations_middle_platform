import base64
import hashlib
import os
import re
import secrets

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

PASSWORD_PATTERN = re.compile(r"^(?=.*[A-Za-z])(?=.*\d)[A-Za-z\d]{8,}$")


def password_is_valid(password: str) -> bool:
    return bool(PASSWORD_PATTERN.fullmatch(password))


def hash_password(password: str, salt: bytes | None = None) -> str:
    local_salt = salt or os.urandom(16)
    digest = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), local_salt, 120000)
    return f"{local_salt.hex()}:{digest.hex()}"


def verify_password(password: str, encoded: str) -> bool:
    salt_hex, digest_hex = encoded.split(":", 1)
    salt = bytes.fromhex(salt_hex)
    computed = hash_password(password, salt).split(":", 1)[1]
    return secrets.compare_digest(computed, digest_hex)


def _aes_key_from_secret(secret: str) -> bytes:
    return hashlib.sha256(secret.encode("utf-8")).digest()


def encrypt_value(plain_text: str, secret: str) -> str:
    nonce = os.urandom(12)
    aesgcm = AESGCM(_aes_key_from_secret(secret))
    encrypted = aesgcm.encrypt(nonce, plain_text.encode("utf-8"), None)
    return base64.urlsafe_b64encode(nonce + encrypted).decode("utf-8")


def decrypt_value(cipher_text: str, secret: str) -> str:
    payload = base64.urlsafe_b64decode(cipher_text.encode("utf-8"))
    nonce, encrypted = payload[:12], payload[12:]
    aesgcm = AESGCM(_aes_key_from_secret(secret))
    return aesgcm.decrypt(nonce, encrypted, None).decode("utf-8")


def random_token() -> str:
    return secrets.token_urlsafe(32)
