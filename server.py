"""
server.py -- TCP relay server for end-to-end encrypted chat.

The server only forwards encrypted messages between clients.
It NEVER has access to decryption keys -- true end-to-end encryption.

Usage:
    python server.py
"""

import socket
import threading
import struct
import json
import sys

HOST = "127.0.0.1"
PORT = 65432

# ── Global state ──────────────────────────────────────────────────────────
clients = {}        # username -> socket
clients_lock = threading.Lock()


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


# ── Client handler ────────────────────────────────────────────────────────
def handle_client(conn, addr):
    """Handle one connected client."""
    username = None
    try:
        # Step 1: Client sends its username as the first message
        raw = recv_msg(conn)
        if raw is None:
            return
        username = raw.decode("utf-8")
        print(f"[SERVER] {username} connected from {addr}", flush=True)

        with clients_lock:
            clients[username] = conn

        # Tell the client their registration succeeded
        send_msg(conn, b"OK")

        # Broadcast updated user list to everyone
        broadcast_user_list()

        # Step 2: Relay loop
        while True:
            raw = recv_msg(conn)
            if raw is None:
                break

            # The first part is a JSON header (up to the first newline)
            # followed by the binary payload
            newline_pos = raw.find(b"\n")
            if newline_pos == -1:
                # Malformed – skip
                continue

            header_bytes = raw[:newline_pos]
            payload = raw[newline_pos + 1:]

            try:
                header = json.loads(header_bytes.decode("utf-8"))
            except (json.JSONDecodeError, UnicodeDecodeError):
                continue

            recipient = header.get("recipient")
            sender = header.get("sender", username)
            msg_type = header.get("msg_type", "text")

            print(f"[SERVER] Relay {msg_type} from {sender} -> {recipient}  "
                  f"({len(payload)} encrypted bytes)", flush=True)

            with clients_lock:
                target_sock = clients.get(recipient)

            if target_sock is not None:
                try:
                    send_msg(target_sock, raw)
                except Exception:
                    print(f"[SERVER] Failed to relay to {recipient}", flush=True)
            else:
                # Tell sender that recipient is offline
                err_header = json.dumps({
                    "sender": "SERVER",
                    "recipient": sender,
                    "msg_type": "error",
                    "error": f"User '{recipient}' is not online."
                }).encode("utf-8")
                try:
                    send_msg(conn, err_header + b"\n")
                except Exception:
                    pass

    except (ConnectionResetError, BrokenPipeError, OSError):
        pass
    finally:
        if username:
            print(f"[SERVER] {username} disconnected", flush=True)
            with clients_lock:
                clients.pop(username, None)
            broadcast_user_list()
        conn.close()


def broadcast_user_list():
    """Send the current user list to all connected clients."""
    with clients_lock:
        user_list = list(clients.keys())
        header = json.dumps({
            "sender": "SERVER",
            "recipient": "ALL",
            "msg_type": "user_list",
            "users": user_list
        }).encode("utf-8")
        msg = header + b"\n"
        for uname, sock in list(clients.items()):
            try:
                send_msg(sock, msg)
            except Exception:
                pass


# ── Main ──────────────────────────────────────────────────────────────────
def main():
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server_sock.bind((HOST, PORT))
    server_sock.listen(5)
    print(f"[SERVER] Listening on {HOST}:{PORT}", flush=True)
    print(f"[SERVER] This server is a RELAY ONLY -- it cannot read encrypted messages.\n", flush=True)

    try:
        while True:
            conn, addr = server_sock.accept()
            t = threading.Thread(target=handle_client, args=(conn, addr), daemon=True)
            t.start()
    except KeyboardInterrupt:
        print("\n[SERVER] Shutting down.", flush=True)
    finally:
        server_sock.close()


if __name__ == "__main__":
    main()
