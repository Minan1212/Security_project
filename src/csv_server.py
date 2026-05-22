"""
csv_server.py
Python server for the CSV Secure File Sync prototype.

Modes:
    serve : run the HTTP server with X25519 DH handshake and encrypted upload endpoint
    report: decrypt all received encrypted CSV files into received_files/decrypted_report/
"""

from __future__ import annotations

import argparse
import getpass
import json
import time
import uuid
from pathlib import Path
from typing import Dict

from flask import Flask, jsonify, request

from crypto_utils import (
    b64d,
    decrypt_file,
    decrypt_session_message,
    derive_session_key,
    generate_x25519_keypair,
    safe_filename,
)

BASE_DIR = Path(__file__).resolve().parent
RECEIVED_DIR = BASE_DIR / "received_files"
DECRYPTED_REPORT_DIR = RECEIVED_DIR / "decrypted_report"

app = Flask(__name__)

SESSIONS: Dict[str, bytes] = {}


@app.route("/health", methods=["GET"])
def health():
    return jsonify(
        {
            "status": "ok",
            "service": "CSV Secure File Sync Server",
        }
    )


@app.route("/api/handshake", methods=["POST"])
def handshake():
    try:
        data = request.get_json(force=True)
        client_public_key_b64 = data["client_public_key_b64"]

        server_private, server_public_b64 = generate_x25519_keypair()
        session_id = str(uuid.uuid4())

        session_key = derive_session_key(
            server_private,
            client_public_key_b64,
            session_id,
        )

        SESSIONS[session_id] = session_key

        return jsonify(
            {
                "session_id": session_id,
                "server_public_key_b64": server_public_b64,
                "key_exchange": "X25519 Diffie-Hellman + HKDF-SHA256",
            }
        )

    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


@app.route("/api/upload", methods=["POST"])
def upload():
    try:
        data = request.get_json(force=True)

        session_id = data["session_id"]
        encrypted_message = data["encrypted_message"]

        if session_id not in SESSIONS:
            return jsonify({"error": "Unknown or expired session_id."}), 403

        session_key = SESSIONS[session_id]
        plaintext = decrypt_session_message(encrypted_message, session_key)

        upload_payload = json.loads(plaintext.decode("utf-8"))

        original_filename = safe_filename(upload_payload["filename"])
        file_bytes = b64d(upload_payload["file_b64"])

        RECEIVED_DIR.mkdir(parents=True, exist_ok=True)

        timestamp = time.strftime("%Y%m%d-%H%M%S")
        saved_name = f"{timestamp}_{original_filename}"
        saved_path = RECEIVED_DIR / saved_name

        saved_path.write_bytes(file_bytes)

        return jsonify(
            {
                "status": "received",
                "saved_as": str(saved_path),
                "bytes_received": len(file_bytes),
            }
        )

    except Exception as exc:
        return jsonify({"error": str(exc)}), 400


def ask_password(password_arg: str | None) -> str:
    if password_arg:
        return password_arg
    return getpass.getpass("Password for decrypting received files: ")


def command_serve(args: argparse.Namespace) -> None:
    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    print(f"Receiving encrypted files into: {RECEIVED_DIR}")
    print(f"Starting server on http://{args.host}:{args.port}")
    app.run(host=args.host, port=args.port, debug=args.debug)


def command_report(args: argparse.Namespace) -> None:
    password = ask_password(args.password)

    RECEIVED_DIR.mkdir(parents=True, exist_ok=True)
    DECRYPTED_REPORT_DIR.mkdir(parents=True, exist_ok=True)

    encrypted_files = sorted(RECEIVED_DIR.glob("*.enc"))

    if not encrypted_files:
        print(f"No .enc files found in {RECEIVED_DIR}")
        return

    success_count = 0
    fail_count = 0

    for enc_file in encrypted_files:
        if enc_file.name.endswith(".enc"):
            output_name = enc_file.name[:-4]
        else:
            output_name = enc_file.stem + ".csv"

        output_path = DECRYPTED_REPORT_DIR / output_name

        try:
            decrypt_file(enc_file, output_path, password)
            success_count += 1
            print(f"OK: {enc_file.name} -> {output_path}")
        except Exception as exc:
            fail_count += 1
            print(f"FAIL: {enc_file.name}: {exc}")

    print("\nReport summary")
    print(f"Encrypted files checked: {len(encrypted_files)}")
    print(f"Successfully decrypted: {success_count}")
    print(f"Failed: {fail_count}")
    print(f"Decrypted files saved in: {DECRYPTED_REPORT_DIR}")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="CSV Secure File Sync server")

    subparsers = parser.add_subparsers(dest="command", required=False)  # NOT required anymore
    # If no command, we default to serve

    serve_parser = subparsers.add_parser("serve", help="Start HTTP server")
    serve_parser.add_argument("--host", default="0.0.0.0", help="Host/IP to bind")
    serve_parser.add_argument("--port", type=int, default=5000, help="Port to bind")
    serve_parser.add_argument("--debug", action="store_true", help="Enable Flask debug mode")
    serve_parser.set_defaults(func=command_serve)

    report_parser = subparsers.add_parser("report", help="Decrypt received encrypted CSV files")
    report_parser.add_argument("--password", help="Password used when files were encrypted")
    report_parser.set_defaults(func=command_report)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    # If no subcommand given (args.command is None), default to 'serve'
    if args.command is None:
        # Create a fake args namespace for serve with default values
        args = argparse.Namespace(
            command="serve",
            host="0.0.0.0",
            port=5000,
            debug=False,
            func=command_serve
        )
    args.func(args)


if __name__ == "__main__":
    main()