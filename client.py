"""
client.py -- Interactive end-to-end encrypted TCP chat client.

Features:
  - Diffie-Hellman key exchange (per peer) for shared AES key
  - AES encryption in ECB or CBC mode (128 / 192 / 256 bit keys)
  - Text messaging and file transfer (images, docs, any file type)
  - Per-pair logging of encrypted / decrypted messages and files

Usage:
    python client.py
"""

import socket
import threading
import struct
import json
import os
import sys
import hashlib
import time

from aes import normalize_key
from aes_cipher import (
    ecb_encrypt, ecb_decrypt,
    cbc_encrypt, cbc_decrypt,
    _format_hex,
)
from diffie_hellman import (
    generate_safe_primes,
    find_generator,
    generate_keys,
    compute_shared_secret,
)

HOST = "127.0.0.1"
PORT = 65432
CHAT_LOG_DIR = "chat_logs"


# ── Helper: length-prefixed send / recv ───────────────────────────────────

def send_msg(sock, data: bytes):
    """Send a message prefixed with its 4-byte big-endian length."""
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)


def recv_msg(sock) -> bytes:
    """Receive a length-prefixed message. Returns None on disconnect."""
    raw_len = recv_exact(sock, 4)
    if raw_len is None:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return recv_exact(sock, msg_len)


def recv_exact(sock, n: int) -> bytes:
    """Read exactly n bytes from a socket."""
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


# ── Pair directory and logging helpers ────────────────────────────────────

def pair_dir(user_a: str, user_b: str) -> str:
    """Return (and create) the log directory for a sender-receiver pair."""
    # Sort names so both sides use the same directory
    pair_name = "_".join(sorted([user_a, user_b]))
    path = os.path.join(CHAT_LOG_DIR, pair_name)
    os.makedirs(path, exist_ok=True)
    return path


def log_message(user_a: str, user_b: str, direction: str,
                plaintext: str, ciphertext_hex: str):
    """Append a message entry to the pair's messages.txt."""
    directory = pair_dir(user_a, user_b)
    filepath = os.path.join(directory, "messages.txt")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(filepath, "a") as f:
        f.write(f"[{timestamp}] {direction}\n")
        f.write(f"  Plaintext : {plaintext}\n")
        f.write(f"  Ciphertext: {ciphertext_hex}\n")
        f.write(f"  Decrypted : {plaintext}\n")
        f.write("\n")


def save_file_versions(user_a: str, user_b: str, filename: str,
                       original_data: bytes, encrypted_data: bytes,
                       decrypted_data: bytes):
    """Save original, encrypted, and decrypted versions of a transferred file."""
    directory = pair_dir(user_a, user_b)

    orig_path = os.path.join(directory, "original_" + filename)
    enc_path = os.path.join(directory, "encrypted_" + filename + ".enc")
    dec_path = os.path.join(directory, "decrypted_" + filename)

    with open(orig_path, "wb") as f:
        f.write(original_data)
    with open(enc_path, "wb") as f:
        f.write(encrypted_data)
    with open(dec_path, "wb") as f:
        f.write(decrypted_data)

    # Also log the file transfer in messages.txt
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    log_path = os.path.join(directory, "messages.txt")
    with open(log_path, "a") as f:
        f.write(f"[{timestamp}] FILE TRANSFER: {filename}\n")
        f.write(f"  Original size : {len(original_data)} bytes\n")
        f.write(f"  Encrypted size: {len(encrypted_data)} bytes\n")
        f.write(f"  Decrypted size: {len(decrypted_data)} bytes\n")
        f.write(f"  Files saved in: {directory}/\n")
        f.write(f"    - original_{filename}\n")
        f.write(f"    - encrypted_{filename}.enc\n")
        f.write(f"    - decrypted_{filename}\n")
        f.write("\n")

    return orig_path, enc_path, dec_path


# ── Diffie-Hellman key derivation ────────────────────────────────────────

def derive_aes_key(shared_secret: int, key_size_bytes: int) -> bytes:
    """
    Derive an AES key from the DH shared secret.
    Uses SHA-256 hash of the shared secret, then truncates to key_size_bytes.
    This is a simple key derivation -- no external libraries needed.
    """
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, byteorder="big"
    )
    # Simple hash-based derivation using SHA-256 (built into Python)
    hash_bytes = hashlib.sha256(secret_bytes).digest()  # 32 bytes

    # For 128-bit key: first 16 bytes
    # For 192-bit key: first 24 bytes
    # For 256-bit key: all 32 bytes
    return hash_bytes[:key_size_bytes]


# ── The Client class ─────────────────────────────────────────────────────

class ChatClient:
    def __init__(self, username: str, key_size: int, mode: str):
        self.username = username
        self.key_size = key_size                # 128, 192, or 256
        self.key_size_bytes = key_size // 8      # 16, 24, or 32
        self.mode = mode.lower()                 # "ecb" or "cbc"
        self.sock = None
        self.online_users = []

        # Per-peer crypto state
        # peer_keys[peer_username] = bytes (the derived AES key)
        self.peer_keys = {}

        # DH state for ongoing key exchanges
        # dh_state[peer] = {"private": int, "P": int, "g": int, ...}
        self.dh_state = {}

        self.running = True

    # ── Connection ────────────────────────────────────────────────────
    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        # Register username
        send_msg(self.sock, self.username.encode("utf-8"))
        reply = recv_msg(self.sock)
        if reply != b"OK":
            print("[ERROR] Server rejected connection.")
            sys.exit(1)

        print(f"[CONNECTED] Registered as '{self.username}'")
        print(f"[CONFIG] Key size: {self.key_size}-bit | Mode: {self.mode.upper()}")
        print(f"[INFO] Type '@username message' to send a text message")
        print(f"[INFO] Type '@username /sendfile <filepath>' to send a file")
        print(f"[INFO] Type '/users' to see online users")
        print(f"[INFO] Type '/quit' to exit\n")

    # ── Encrypt / Decrypt wrappers ────────────────────────────────────
    def encrypt(self, plaintext_bytes: bytes, key: bytes) -> bytes:
        if self.mode == "ecb":
            return ecb_encrypt(plaintext_bytes, key)
        else:
            return cbc_encrypt(plaintext_bytes, key)

    def decrypt(self, ciphertext_bytes: bytes, key: bytes) -> bytes:
        if self.mode == "ecb":
            return ecb_decrypt(ciphertext_bytes, key)
        else:
            return cbc_decrypt(ciphertext_bytes, key)

    # ── Diffie-Hellman key exchange ───────────────────────────────────
    def initiate_key_exchange(self, peer: str):
        """Start a DH key exchange with a peer."""
        print(f"[KEY EXCHANGE] Generating DH parameters for {peer}...")
        # Use 128-bit safe primes (fast enough for demo)
        P, q = generate_safe_primes(128)
        g = find_generator(P, q)
        private, public = generate_keys(g, P)

        self.dh_state[peer] = {
            "private": private,
            "P": P,
            "g": g,
            "my_public": public,
        }

        # Send DH parameters + our public key to peer
        header = json.dumps({
            "sender": self.username,
            "recipient": peer,
            "msg_type": "dh_init",
            "P": str(P),
            "g": str(g),
            "public_key": str(public),
            "key_size": self.key_size,
            "mode": self.mode,
        }).encode("utf-8")

        send_msg(self.sock, header + b"\n")
        print(f"[KEY EXCHANGE] Sent DH parameters to {peer}, waiting for reply...")

    def handle_dh_init(self, header: dict):
        """Respond to an incoming DH key exchange initiation."""
        peer = header["sender"]
        P = int(header["P"])
        g = int(header["g"])
        their_public = int(header["public_key"])

        # Generate our own key pair using their P and g
        private, public = generate_keys(g, P)

        # Compute shared secret
        shared_secret = compute_shared_secret(their_public, private, P)
        aes_key = derive_aes_key(shared_secret, self.key_size_bytes)
        self.peer_keys[peer] = aes_key

        print(f"\n[KEY EXCHANGE] Received DH parameters from {peer}")
        print(f"[KEY EXCHANGE] Shared key established with {peer}!")

        # Send back our public key
        reply_header = json.dumps({
            "sender": self.username,
            "recipient": peer,
            "msg_type": "dh_reply",
            "public_key": str(public),
        }).encode("utf-8")

        send_msg(self.sock, reply_header + b"\n")
        print(f">> ", end="", flush=True)

    def handle_dh_reply(self, header: dict):
        """Complete the DH key exchange when we receive the peer's public key."""
        peer = header["sender"]
        their_public = int(header["public_key"])

        state = self.dh_state.get(peer)
        if state is None:
            print(f"\n[ERROR] Unexpected DH reply from {peer}")
            return

        # Compute shared secret
        shared_secret = compute_shared_secret(
            their_public, state["private"], state["P"]
        )
        aes_key = derive_aes_key(shared_secret, self.key_size_bytes)
        self.peer_keys[peer] = aes_key

        print(f"\n[KEY EXCHANGE] Shared key established with {peer}!")
        print(f"[KEY EXCHANGE] You can now send encrypted messages to {peer}")
        print(f">> ", end="", flush=True)

        # Clean up DH state
        del self.dh_state[peer]

    # ── Send text message ─────────────────────────────────────────────
    def send_text(self, peer: str, message: str):
        """Encrypt and send a text message to a peer."""
        if peer not in self.peer_keys:
            print(f"[INFO] No shared key with {peer}. Initiating key exchange...")
            self.initiate_key_exchange(peer)
            # Queue the message -- it will be sent after key exchange
            # For simplicity, we ask the user to retry
            print(f"[INFO] Please wait for key exchange to complete, then resend.")
            return

        key = self.peer_keys[peer]
        plaintext_bytes = message.encode("utf-8")
        ciphertext = self.encrypt(plaintext_bytes, key)

        # Log the sent message
        log_message(self.username, peer,
                    f"SENT ({self.username} -> {peer})",
                    message, _format_hex(ciphertext))

        # Build the wire message
        header = json.dumps({
            "sender": self.username,
            "recipient": peer,
            "msg_type": "text",
            "mode": self.mode,
        }).encode("utf-8")

        send_msg(self.sock, header + b"\n" + ciphertext)
        print(f"[SENT to {peer}] (encrypted {len(ciphertext)} bytes)")

    # ── Send file ─────────────────────────────────────────────────────
    def send_file(self, peer: str, filepath: str):
        """Encrypt and send a file to a peer."""
        if peer not in self.peer_keys:
            print(f"[INFO] No shared key with {peer}. Initiating key exchange...")
            self.initiate_key_exchange(peer)
            print(f"[INFO] Please wait for key exchange to complete, then resend.")
            return

        if not os.path.isfile(filepath):
            print(f"[ERROR] File not found: {filepath}")
            return

        filename = os.path.basename(filepath)
        with open(filepath, "rb") as f:
            file_data = f.read()

        key = self.peer_keys[peer]
        ciphertext = self.encrypt(file_data, key)

        # Save original and encrypted on sender side
        directory = pair_dir(self.username, peer)
        orig_path = os.path.join(directory, "original_" + filename)
        enc_path = os.path.join(directory, "encrypted_" + filename + ".enc")
        with open(orig_path, "wb") as f:
            f.write(file_data)
        with open(enc_path, "wb") as f:
            f.write(ciphertext)

        # Log the file transfer
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
        log_path = os.path.join(directory, "messages.txt")
        with open(log_path, "a") as f:
            f.write(f"[{timestamp}] FILE SENT ({self.username} -> {peer}): {filename}\n")
            f.write(f"  Original size : {len(file_data)} bytes\n")
            f.write(f"  Encrypted size: {len(ciphertext)} bytes\n")
            f.write(f"  Saved: original_{filename}, encrypted_{filename}.enc\n\n")

        # Build the wire message
        header = json.dumps({
            "sender": self.username,
            "recipient": peer,
            "msg_type": "file",
            "filename": filename,
            "original_size": len(file_data),
            "mode": self.mode,
        }).encode("utf-8")

        send_msg(self.sock, header + b"\n" + ciphertext)
        print(f"[FILE SENT to {peer}] {filename} ({len(file_data)} bytes -> "
              f"{len(ciphertext)} encrypted bytes)")

    # ── Receive handlers ──────────────────────────────────────────────
    def handle_text(self, header: dict, payload: bytes):
        """Decrypt and display a received text message."""
        sender = header["sender"]
        if sender not in self.peer_keys:
            print(f"\n[ERROR] Received message from {sender} but no shared key!")
            print(f">> ", end="", flush=True)
            return

        key = self.peer_keys[sender]
        try:
            plaintext_bytes = self.decrypt(payload, key)
            message = plaintext_bytes.decode("utf-8")
        except Exception as e:
            print(f"\n[ERROR] Failed to decrypt message from {sender}: {e}")
            print(f">> ", end="", flush=True)
            return

        # Log the received message
        log_message(self.username, sender,
                    f"RECEIVED ({sender} -> {self.username})",
                    message, _format_hex(payload))

        print(f"\n[{sender}] {message}")
        print(f">> ", end="", flush=True)

    def handle_file(self, header: dict, payload: bytes):
        """Decrypt and save a received file."""
        sender = header["sender"]
        filename = header.get("filename", "unknown_file")

        if sender not in self.peer_keys:
            print(f"\n[ERROR] Received file from {sender} but no shared key!")
            print(f">> ", end="", flush=True)
            return

        key = self.peer_keys[sender]
        try:
            decrypted_data = self.decrypt(payload, key)
        except Exception as e:
            print(f"\n[ERROR] Failed to decrypt file from {sender}: {e}")
            print(f">> ", end="", flush=True)
            return

        # Save all three versions
        orig_path, enc_path, dec_path = save_file_versions(
            self.username, sender, filename,
            decrypted_data,  # on receiver side, original = decrypted
            payload,         # the encrypted bytes
            decrypted_data   # decrypted bytes
        )

        print(f"\n[{sender}] Sent file: {filename} ({len(decrypted_data)} bytes)")
        print(f"  Saved to: {dec_path}")
        print(f">> ", end="", flush=True)

    # ── Receiver thread ───────────────────────────────────────────────
    def receive_loop(self):
        """Background thread that receives and processes incoming messages."""
        while self.running:
            try:
                raw = recv_msg(self.sock)
                if raw is None:
                    print("\n[DISCONNECTED] Server closed the connection.")
                    self.running = False
                    break

                # Split header from payload
                newline_pos = raw.find(b"\n")
                if newline_pos == -1:
                    continue

                header_bytes = raw[:newline_pos]
                payload = raw[newline_pos + 1:]

                try:
                    header = json.loads(header_bytes.decode("utf-8"))
                except (json.JSONDecodeError, UnicodeDecodeError):
                    continue

                msg_type = header.get("msg_type", "")

                if msg_type == "text":
                    self.handle_text(header, payload)

                elif msg_type == "file":
                    self.handle_file(header, payload)

                elif msg_type == "dh_init":
                    self.handle_dh_init(header)

                elif msg_type == "dh_reply":
                    self.handle_dh_reply(header)

                elif msg_type == "user_list":
                    self.online_users = header.get("users", [])
                    others = [u for u in self.online_users if u != self.username]
                    if others:
                        print(f"\n[ONLINE] Users: {', '.join(others)}")
                    print(f">> ", end="", flush=True)

                elif msg_type == "error":
                    error_msg = header.get("error", "Unknown error")
                    print(f"\n[SERVER ERROR] {error_msg}")
                    print(f">> ", end="", flush=True)

            except (ConnectionResetError, BrokenPipeError, OSError):
                if self.running:
                    print("\n[DISCONNECTED] Connection lost.")
                    self.running = False
                break

    # ── Main input loop ───────────────────────────────────────────────
    def input_loop(self):
        """Read user input and dispatch commands."""
        while self.running:
            try:
                user_input = input(">> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[QUIT] Goodbye!")
                self.running = False
                break

            if not user_input:
                continue

            # ── Commands ──
            if user_input.lower() == "/quit":
                print("[QUIT] Goodbye!")
                self.running = False
                break

            if user_input.lower() == "/users":
                others = [u for u in self.online_users if u != self.username]
                if others:
                    print(f"[ONLINE] Users: {', '.join(others)}")
                else:
                    print("[ONLINE] No other users online.")
                continue

            # ── Message to a peer: @username message ──
            if user_input.startswith("@"):
                space_pos = user_input.find(" ")
                if space_pos == -1:
                    print("[USAGE] @username <message>  or  @username /sendfile <path>")
                    continue

                peer = user_input[1:space_pos]
                content = user_input[space_pos + 1:].strip()

                if peer == self.username:
                    print("[ERROR] You cannot send messages to yourself.")
                    continue

                if content.startswith("/sendfile"):
                    # File send
                    parts = content.split(maxsplit=1)
                    if len(parts) < 2:
                        print("[USAGE] @username /sendfile <filepath>")
                        continue
                    filepath = parts[1].strip()
                    self.send_file(peer, filepath)
                else:
                    # Text message
                    self.send_text(peer, content)
            else:
                print("[USAGE] @username <message>")
                print("        @username /sendfile <filepath>")
                print("        /users    -- list online users")
                print("        /quit     -- disconnect")

    # ── Run ───────────────────────────────────────────────────────────
    def run(self):
        """Connect to server and start send/receive loops."""
        self.connect()

        # Start receiver thread
        recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        recv_thread.start()

        # Input loop on main thread
        self.input_loop()

        # Cleanup
        try:
            self.sock.close()
        except Exception:
            pass


# ── Main ──────────────────────────────────────────────────────────────────

def main():
    print("=" * 55)
    print("   End-to-End Encrypted Chat Client")
    print("   AES Encryption + Diffie-Hellman Key Exchange")
    print("=" * 55)
    print()

    # Get username
    username = input("Enter your username: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)

    # Get key size
    while True:
        key_input = input("Key size (128 / 192 / 256): ").strip()
        if key_input in ("128", "192", "256"):
            key_size = int(key_input)
            break
        print("Invalid key size. Please enter 128, 192, or 256.")

    # Get mode
    while True:
        mode_input = input("Encryption mode (ecb / cbc): ").strip().lower()
        if mode_input in ("ecb", "cbc"):
            mode = mode_input
            break
        print("Invalid mode. Please enter 'ecb' or 'cbc'.")

    print()

    client = ChatClient(username, key_size, mode)
    client.run()


if __name__ == "__main__":
    main()
