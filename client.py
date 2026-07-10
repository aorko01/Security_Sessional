
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

def send_msg(sock, data: bytes):
    length = struct.pack("!I", len(data))
    sock.sendall(length + data)


def recv_msg(sock) -> bytes:
    raw_len = recv_exact(sock, 4)
    if raw_len is None:
        return None
    msg_len = struct.unpack("!I", raw_len)[0]
    return recv_exact(sock, msg_len)


def recv_exact(sock, n: int) -> bytes:
    data = b""
    while len(data) < n:
        chunk = sock.recv(n - len(data))
        if not chunk:
            return None
        data += chunk
    return data


def pair_dir(user_a: str, user_b: str) -> str:
    pair_name = "_".join(sorted([user_a, user_b]))
    path = os.path.join(CHAT_LOG_DIR, pair_name)
    os.makedirs(path, exist_ok=True)
    return path


def log_message(user_a: str, user_b: str, direction: str,
                 plaintext: str, ciphertext_hex: str):
    directory = pair_dir(user_a, user_b)
    filepath = os.path.join(directory, "messages.txt")
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    with open(filepath, "a") as f:
        f.write(f"[{timestamp}] {direction}\n")
        f.write(f"  Plaintext : {plaintext}\n")
        f.write(f"  Ciphertext: {ciphertext_hex}\n")
        f.write(f"  Decrypted : {plaintext}\n")
        f.write("\n")



def derive_aes_key(shared_secret: int, key_size_bytes: int) -> bytes:
    secret_bytes = shared_secret.to_bytes(
        (shared_secret.bit_length() + 7) // 8, byteorder="big"
    )
    hash_bytes = hashlib.sha256(secret_bytes).digest()  # 32 bytes
    return hash_bytes[:key_size_bytes]


class ChatClient:
    def __init__(self, username: str, key_size: int, mode: str):
        self.username = username
        self.key_size = key_size                # 128, 192, or 256
        self.key_size_bytes = key_size // 8      # 16, 24, or 32
        self.mode = mode.lower()                 # "ecb" or "cbc"
        self.sock = None
        self.online_users = []

        # Per-peer crypto state
        self.peer_keys = {}      # peer_username -> derived AES key (bytes)
        self.dh_state = {}       # peer_username -> in-progress DH state

        self.running = True

    def connect(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.connect((HOST, PORT))

        send_msg(self.sock, self.username.encode("utf-8"))
        reply = recv_msg(self.sock)
        if reply != b"OK":
            print("[ERROR] Server rejected connection.")
            sys.exit(1)

        print(f"[CONNECTED] Registered as '{self.username}'")
        print(f"[CONFIG] Key size: {self.key_size}-bit | Mode: {self.mode.upper()}")
        print(f"[INFO] Type '@username message' to send a text message")
        print(f"[INFO] Type '/users' to see online users")
        print(f"[INFO] Type '/quit' to exit\n")

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

    def initiate_key_exchange(self, peer: str):
        print(f"[KEY EXCHANGE] Generating DH parameters for {peer}...")
        P, q = generate_safe_primes(128)
        g = find_generator(P, q)
        private, public = generate_keys(g, P)

        self.dh_state[peer] = {
            "private": private,
            "P": P,
            "g": g,
            "my_public": public,
        }

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

        private, public = generate_keys(g, P)

        shared_secret = compute_shared_secret(their_public, private, P)
        aes_key = derive_aes_key(shared_secret, self.key_size_bytes)
        self.peer_keys[peer] = aes_key

        print(f"\n[KEY EXCHANGE] Received DH parameters from {peer}")
        print(f"[KEY EXCHANGE] Shared key established with {peer}!")

        reply_header = json.dumps({
            "sender": self.username,
            "recipient": peer,
            "msg_type": "dh_reply",
            "public_key": str(public),
        }).encode("utf-8")

        send_msg(self.sock, reply_header + b"\n")
        print(f">> ", end="", flush=True)

    def handle_dh_reply(self, header: dict):
        peer = header["sender"]
        their_public = int(header["public_key"])

        state = self.dh_state.get(peer)
        if state is None:
            print(f"\n[ERROR] Unexpected DH reply from {peer}")
            return

        shared_secret = compute_shared_secret(
            their_public, state["private"], state["P"]
        )
        aes_key = derive_aes_key(shared_secret, self.key_size_bytes)
        self.peer_keys[peer] = aes_key

        print(f"\n[KEY EXCHANGE] Shared key established with {peer}!")
        print(f"[KEY EXCHANGE] You can now send encrypted messages to {peer}")
        print(f">> ", end="", flush=True)

        del self.dh_state[peer]

    def send_text(self, peer: str, message: str):
        if peer not in self.peer_keys:
            print(f"[INFO] No shared key with {peer}. Initiating key exchange...")
            self.initiate_key_exchange(peer)
            print(f"[INFO] Please wait for key exchange to complete, then resend.")
            return

        key = self.peer_keys[peer]
        plaintext_bytes = message.encode("utf-8")
        ciphertext = self.encrypt(plaintext_bytes, key)

        log_message(self.username, peer,
                    f"SENT ({self.username} -> {peer})",
                    message, _format_hex(ciphertext))

        header = json.dumps({
            "sender": self.username,
            "recipient": peer,
            "msg_type": "text",
            "mode": self.mode,
        }).encode("utf-8")

        send_msg(self.sock, header + b"\n" + ciphertext)
        print(f"[SENT to {peer}] (encrypted {len(ciphertext)} bytes)")

    def handle_text(self, header: dict, payload: bytes):
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

        log_message(self.username, sender,
                    f"RECEIVED ({sender} -> {self.username})",
                    message, _format_hex(payload))

        print(f"\n[{sender}] {message}")
        print(f">> ", end="", flush=True)

    def receive_loop(self):
        while self.running:
            try:
                raw = recv_msg(self.sock)
                if raw is None:
                    print("\n[DISCONNECTED] Server closed the connection.")
                    self.running = False
                    break

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

    def input_loop(self):
        while self.running:
            try:
                user_input = input(">> ").strip()
            except (EOFError, KeyboardInterrupt):
                print("\n[QUIT] Goodbye!")
                self.running = False
                break

            if not user_input:
                continue

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

            if user_input.startswith("@"):
                space_pos = user_input.find(" ")
                if space_pos == -1:
                    print("[USAGE] @username <message>")
                    continue

                peer = user_input[1:space_pos]
                content = user_input[space_pos + 1:].strip()

                if peer == self.username:
                    print("[ERROR] You cannot send messages to yourself.")
                    continue

                self.send_text(peer, content)
            else:
                print("[USAGE] @username <message>")
                print("        /users    -- list online users")
                print("        /quit     -- disconnect")

    def run(self):
        """Connect to server and start send/receive loops."""
        self.connect()

        recv_thread = threading.Thread(target=self.receive_loop, daemon=True)
        recv_thread.start()

        self.input_loop()

        try:
            self.sock.close()
        except Exception:
            pass



def main():
    print("=" * 55)
    print("   End-to-End Encrypted Text Chat Client")
    print("   AES Encryption + Diffie-Hellman Key Exchange")
    print("=" * 55)
    print()

    username = input("Enter your username: ").strip()
    if not username:
        print("Username cannot be empty.")
        sys.exit(1)

    while True:
        key_input = input("Key size (128 / 192 / 256): ").strip()
        if key_input in ("128", "192", "256"):
            key_size = int(key_input)
            break
        print("Invalid key size. Please enter 128, 192, or 256.")


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