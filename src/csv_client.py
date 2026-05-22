"""
csv_client.py
Command-line client for the CSV Secure File Sync prototype.

Features:
    encrypt: encrypt a local CSV file using AES-GCM or ChaCha20-Poly1305
    decrypt: decrypt a local encrypted CSV file
    upload : upload an encrypted file to the Python server using HTTP plus X25519 DH session encryption
"""

from __future__ import annotations

import argparse
import getpass
import json
from pathlib import Path

import requests

from crypto_utils import (
    b64e,
    derive_session_key,
    encrypt_file,
    encrypt_session_message,
    generate_x25519_keypair,
)
from crypto_utils import decrypt_file as decrypt_local_file


def ask_password(password_arg: str | None, confirm: bool = False) -> str:
    if password_arg:
        return password_arg

    password = getpass.getpass("Password: ")

    if confirm:
        password2 = getpass.getpass("Confirm password: ")
        if password != password2:
            raise SystemExit("Passwords do not match.")

    return password


def default_encrypt_output(input_path: Path) -> Path:
    return input_path.with_name(input_path.name + ".enc")


def default_decrypt_output(input_path: Path) -> Path:
    if input_path.name.endswith(".enc"):
        return input_path.with_name(input_path.name[:-4])

    return input_path.with_name(input_path.stem + ".decrypted.csv")


def command_encrypt(args: argparse.Namespace) -> None:
    input_path = Path(args.input_file)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    output_path = Path(args.output) if args.output else default_encrypt_output(input_path)
    password = ask_password(args.password, confirm=True)

    encrypt_file(input_path, output_path, password, args.cipher)

    print(f"Encrypted successfully: {output_path}")
    print(f"Cipher used: {args.cipher}")


def command_decrypt(args: argparse.Namespace) -> None:
    input_path = Path(args.input_file)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    output_path = Path(args.output) if args.output else default_decrypt_output(input_path)
    password = ask_password(args.password, confirm=False)

    decrypt_local_file(input_path, output_path, password)

    print(f"Decrypted successfully: {output_path}")


def normalise_server_url(server: str) -> str:
    return server.rstrip("/")


def create_session(server: str) -> tuple[str, bytes]:
    client_private, client_public_b64 = generate_x25519_keypair()

    response = requests.post(
        f"{server}/api/handshake",
        json={"client_public_key_b64": client_public_b64},
        timeout=15,
    )

    response.raise_for_status()
    data = response.json()

    session_id = data["session_id"]
    server_public_b64 = data["server_public_key_b64"]

    session_key = derive_session_key(client_private, server_public_b64, session_id)

    return session_id, session_key


def command_upload(args: argparse.Namespace) -> None:
    input_path = Path(args.input_file)

    if not input_path.exists():
        raise SystemExit(f"Input file not found: {input_path}")

    server = normalise_server_url(args.server)

    print("Starting Diffie-Hellman handshake with server...")
    session_id, session_key = create_session(server)
    print(f"Session created: {session_id}")

    file_bytes = input_path.read_bytes()

    upload_payload = {
        "filename": input_path.name,
        "file_b64": b64e(file_bytes),
        "note": "Uploaded file is locally encrypted. HTTP payload is also session-encrypted.",
    }

    encrypted_message = encrypt_session_message(
        json.dumps(upload_payload).encode("utf-8"),
        session_key,
    )

    response = requests.post(
        f"{server}/api/upload",
        json={
            "session_id": session_id,
            "encrypted_message": encrypted_message,
        },
        timeout=30,
    )

    response.raise_for_status()

    print("Upload response:")
    print(json.dumps(response.json(), indent=2))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CSV Secure File Sync client")

    subparsers = parser.add_subparsers(dest="command", required=True)

    encrypt_parser = subparsers.add_parser("encrypt", help="Encrypt a local CSV file")
    encrypt_parser.add_argument("input_file", help="Path to CSV file")
    encrypt_parser.add_argument("--output", "-o", help="Output encrypted file path")
    encrypt_parser.add_argument(
        "--cipher",
        choices=["aesgcm", "chacha20"],
        default="aesgcm",
        help="Symmetric cipher for local file encryption",
    )
    encrypt_parser.add_argument(
        "--password",
        help="Password. If omitted, you will be prompted securely.",
    )
    encrypt_parser.set_defaults(func=command_encrypt)

    decrypt_parser = subparsers.add_parser("decrypt", help="Decrypt a local encrypted CSV file")
    decrypt_parser.add_argument("input_file", help="Path to encrypted .enc file")
    decrypt_parser.add_argument("--output", "-o", help="Output decrypted CSV path")
    decrypt_parser.add_argument(
        "--password",
        help="Password. If omitted, you will be prompted securely.",
    )
    decrypt_parser.set_defaults(func=command_decrypt)

    upload_parser = subparsers.add_parser("upload", help="Upload encrypted file to server")
    upload_parser.add_argument("input_file", help="Path to encrypted .enc file")
    upload_parser.add_argument(
        "--server",
        required=True,
        help="Server base URL, e.g. http://SERVER_IP:5000",
    )
    upload_parser.set_defaults(func=command_upload)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    args.func(args)


if __name__ == "__main__":
    main()