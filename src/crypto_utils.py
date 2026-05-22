"""
crypto_utils.py
Shared cryptographic helper functions for the CSV Secure File Sync prototype.

Uses Python Cryptography HAZMAT primitives only.
Supported local file encryption ciphers:
    1. AES-GCM
    2. ChaCha20-Poly1305
Supported client/server key exchange:
    X25519 ephemeral Diffie-Hellman, followed by HKDF-SHA256.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path
from typing import Dict, Tuple

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

APP_VERSION = "1.0"
SALT_SIZE = 16
NONCE_SIZE = 12
KEY_SIZE = 32
PBKDF2_ITERATIONS = 390_000

SUPPORTED_CIPHERS = {"aesgcm", "chacha20"}


def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def derive_file_key(password: str, salt: bytes) -> bytes:
    if not password:
        raise ValueError("Password cannot be empty.")

    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=salt,
        iterations=PBKDF2_ITERATIONS,
    )
    return kdf.derive(password.encode("utf-8"))


def _get_aead(cipher_name: str, key: bytes):
    cipher_name = cipher_name.lower()

    if cipher_name == "aesgcm":
        return AESGCM(key)

    if cipher_name == "chacha20":
        return ChaCha20Poly1305(key)

    raise ValueError("Unsupported cipher. Use aesgcm or chacha20.")


def encrypt_file_bytes(plaintext: bytes, password: str, cipher_name: str) -> Dict[str, str]:
    cipher_name = cipher_name.lower()

    if cipher_name not in SUPPORTED_CIPHERS:
        raise ValueError("Cipher must be either aesgcm or chacha20.")

    salt = os.urandom(SALT_SIZE)
    nonce = os.urandom(NONCE_SIZE)
    key = derive_file_key(password, salt)
    aead = _get_aead(cipher_name, key)

    aad = f"csv-secure-file-sync:{APP_VERSION}:{cipher_name}".encode("utf-8")
    ciphertext = aead.encrypt(nonce, plaintext, aad)

    return {
        "format": "CSV-Secure-File-Sync",
        "version": APP_VERSION,
        "cipher": cipher_name,
        "kdf": "PBKDF2HMAC-SHA256",
        "iterations": str(PBKDF2_ITERATIONS),
        "salt_b64": b64e(salt),
        "nonce_b64": b64e(nonce),
        "aad": aad.decode("utf-8"),
        "ciphertext_b64": b64e(ciphertext),
    }


def decrypt_file_package(package: Dict[str, str], password: str) -> bytes:
    required = ["cipher", "salt_b64", "nonce_b64", "ciphertext_b64", "aad"]

    for field in required:
        if field not in package:
            raise ValueError(f"Encrypted file is missing field: {field}")

    cipher_name = package["cipher"].lower()
    salt = b64d(package["salt_b64"])
    nonce = b64d(package["nonce_b64"])
    ciphertext = b64d(package["ciphertext_b64"])
    aad = package["aad"].encode("utf-8")

    key = derive_file_key(password, salt)
    aead = _get_aead(cipher_name, key)

    try:
        return aead.decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError(
            "Decryption failed. The password may be wrong or the encrypted file may be tampered."
        ) from exc


def encrypt_file(input_path: Path, output_path: Path, password: str, cipher_name: str) -> None:
    plaintext = input_path.read_bytes()
    package = encrypt_file_bytes(plaintext, password, cipher_name)
    output_path.write_text(json.dumps(package, indent=2), encoding="utf-8")


def decrypt_file(input_path: Path, output_path: Path, password: str) -> None:
    package = json.loads(input_path.read_text(encoding="utf-8"))
    plaintext = decrypt_file_package(package, password)
    output_path.write_bytes(plaintext)


def generate_x25519_keypair() -> Tuple[x25519.X25519PrivateKey, str]:
    private_key = x25519.X25519PrivateKey.generate()
    public_key_b64 = public_key_to_b64(private_key.public_key())
    return private_key, public_key_b64


def public_key_to_b64(public_key: x25519.X25519PublicKey) -> str:
    raw = public_key.public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    return b64e(raw)


def public_key_from_b64(public_key_b64: str) -> x25519.X25519PublicKey:
    return x25519.X25519PublicKey.from_public_bytes(b64d(public_key_b64))


def derive_session_key(
    private_key: x25519.X25519PrivateKey,
    peer_public_key_b64: str,
    session_id: str,
) -> bytes:
    peer_public_key = public_key_from_b64(peer_public_key_b64)
    shared_secret = private_key.exchange(peer_public_key)

    return HKDF(
        algorithm=hashes.SHA256(),
        length=KEY_SIZE,
        salt=session_id.encode("utf-8"),
        info=b"csv-secure-file-sync-http-session",
    ).derive(shared_secret)


def encrypt_session_message(message: bytes, session_key: bytes) -> Dict[str, str]:
    nonce = os.urandom(NONCE_SIZE)
    aad = b"csv-secure-file-sync-upload-v1"
    ciphertext = AESGCM(session_key).encrypt(nonce, message, aad)

    return {
        "nonce_b64": b64e(nonce),
        "aad": aad.decode("utf-8"),
        "ciphertext_b64": b64e(ciphertext),
    }


def decrypt_session_message(package: Dict[str, str], session_key: bytes) -> bytes:
    required = ["nonce_b64", "aad", "ciphertext_b64"]

    for field in required:
        if field not in package:
            raise ValueError(f"Encrypted message is missing field: {field}")

    nonce = b64d(package["nonce_b64"])
    aad = package["aad"].encode("utf-8")
    ciphertext = b64d(package["ciphertext_b64"])

    try:
        return AESGCM(session_key).decrypt(nonce, ciphertext, aad)
    except InvalidTag as exc:
        raise ValueError("Session message authentication failed.") from exc


def safe_filename(name: str) -> str:
    name = Path(name).name
    allowed = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._-"
    cleaned = "".join(ch if ch in allowed else "_" for ch in name)
    return cleaned or "uploaded_file.enc"