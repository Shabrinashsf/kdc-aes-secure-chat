import json
import socket
import struct
import threading

# Transport layer: message framing and channel
# Each frame = 4 bytes in length (unsigned and big-endian) + JSON in UTF-8
# This module is unaware of the payload's contents; it only transfers the envelope.

MAX_FRAME = 1024 * 1024  # 1 MB
ENVELOPE_FIELDS = ("type", "from", "to", "payload")

# Read n bytes from the socket. TCP is a stream, so a single recv() call may be truncated
def recv_exact(sock: socket.socket, n: int) -> bytes | None:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            return None 
        buf.extend(chunk)
    return bytes(buf)

def send_frame(sock: socket.socket, obj: dict) -> None:
    data = json.dumps(obj).encode("utf-8")
    if len(data) > MAX_FRAME:
        raise ValueError(f"frame terlalu besar: {len(data)} byte")
    sock.sendall(struct.pack(">I", len(data)) + data)

# Return an envelope dictionary or `None` if the connection is closed
def recv_frame(sock: socket.socket) -> dict | None:
    header = recv_exact(sock, 4)
    if header is None:
        return None
    (length,) = struct.unpack(">I", header)
    if length > MAX_FRAME:
        raise ValueError(f"frame terlalu besar: {length} byte")
    data = recv_exact(sock, length)
    if data is None:
        return None
    try:
        msg = json.loads(data.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as e:
        raise ValueError(f"frame bukan JSON valid: {e}") from e
    if not isinstance(msg, dict) or not all(isinstance(msg.get(f), str) for f in ENVELOPE_FIELDS):
        raise ValueError(f"envelope tidak valid: {msg!r}")
    return msg

# one TCP connection to the other party
# send() can be called from multiple threads
# recv() should only be called by one thread at a time; if two threads read from the same socket, the bytes in the frame may become mixed up
class Channel:
    def __init__(self, sock: socket.socket, me: str):
        self.sock = sock
        self.me = me
        self._send_lock = threading.Lock()

    def send(self, type: str, to: str, payload: str = "") -> None:
        msg = {"type": type, "from": self.me, "to": to, "payload": payload}
        with self._send_lock:
            send_frame(self.sock, msg)

    def recv(self) -> dict | None:
        try:
            return recv_frame(self.sock)
        except OSError:
            return None

    def close(self) -> None:
        try:
            # Wake up another thread that is currently blocked in recv()
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

def connect(host: str, port: int, me: str) -> Channel:
    return Channel(socket.create_connection((host, port)), me)

def listen(host: str, port: int) -> socket.socket:
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind((host, port))
    server.listen()
    return server

def accept(server: socket.socket, me: str) -> tuple[Channel, tuple[str, int]]:
    sock, addr = server.accept()
    return Channel(sock, me), addr

# Parse "host:port" from the command line into (host, port)
def parse_addr(text: str) -> tuple[str, int]:
    host, sep, port = text.rpartition(":")
    if not sep or not host or not port.isdigit() or not 0 < int(port) < 65536:
        raise ValueError(f"alamat harus berformat host:port, diterima '{text}'")
    return host, int(port)
