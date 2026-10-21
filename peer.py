import argparse
import socket

from kdc_chat import net, protocol
from kdc_chat.net import Channel
from kdc_chat.protocol import HandshakeError

# Alice/Bob entry point. With --connect this peer is the initiator (Alice):
# it asks the KDC for a session key and connects to the responder (Bob)
# Without --connect it is the responder and waits for the initiator

# TODO integrasi: ganti ke `console.ask` (dan panggil console.start() di main)
ask = input

class Peer:
    def __init__(self, me: str, key: str, initiator: bool):
        self.me = me
        self.key = key
        self.initiator = initiator

    def set_key(self, key: str) -> None:
        error = protocol.check_key(key)
        if error is not None:
            print(f"  ✗ {error}")
            return
        self.key = key
        print(f"  ✓ master key {self.me} diganti, berlaku di handshake berikutnya")

    # Commands that also work during a chat session; passed to the chat as on_command.
    # Returns "rekey" to end the chat and redo the handshake, otherwise None.
    def on_command(self, line: str) -> str | None:
        cmd, _, arg = line.strip().partition(" ")
        if cmd == "/setkey":
            self.set_key(arg.strip())
        elif cmd == "/rekey":
            if self.initiator:
                return "rekey"
            print("  ✗ hanya initiator (yang terhubung ke KDC) yang bisa /rekey")
        else:
            print(f"  ✗ command tidak dikenal: {cmd}")
        return None

# TODO integrasi: ganti dengan ChatSession(ch, ks, me, peer, on_command).run() dari chat.py (milik A).

# Placeholder that only handles the control messages (REKEY, REKEY_ACK, BYE) so the
# handshake -> chat -> /rekey flow can be tested. It does not send chat messages.
def dummy_chat(ch: Channel, ks: str, me: str, peer: str, initiator: bool, on_command) -> str:
    print(f"[chat dummy] sesi {me} <-> {peer} aktif. Chat terenkripsi menunggu chat.py.")
    try:
        if not initiator:
            print("[chat dummy] responder hanya menunggu pesan kontrol dari initiator.")
            while True:
                msg = ch.recv()
                if msg is None or msg["type"] == "BYE":
                    return "closed"
                if msg["type"] == "REKEY":
                    ch.send("REKEY_ACK", peer)
                    return "rekey"

        print("[chat dummy] command: /rekey, /setkey <key>, /quit")
        while True:
            line = ask(f"[{me}] ").strip()
            if line == "/quit":
                ch.send("BYE", peer)
                return "quit"
            if not line.startswith("/"):
                print("[chat dummy] pesan belum dikirim, chat.py belum tersedia")
                continue
            if on_command(line) == "rekey":
                ch.send("REKEY", peer)
                msg = ch.recv()
                return "rekey" if msg is not None and msg["type"] == "REKEY_ACK" else "closed"
    except OSError:
        return "closed"

# Handshake then chat, repeated while the chat ends with "rekey"
def run_session(p: Peer, ch: Channel, kdc_addr, peer_id: str | None) -> None:
    try:
        while True:
            if p.initiator:
                ks = protocol.alice_handshake(kdc_addr, ch, p.me, peer_id, p.key)
            else:
                ks, peer_id = protocol.bob_handshake(ch, p.me, p.key)
            reason = dummy_chat(ch, ks, p.me, peer_id, p.initiator, p.on_command)
            if reason != "rekey":
                print(f"Sesi selesai ({reason}).")
                return
            print("Rekey: handshake ulang untuk session key baru...")
    except HandshakeError as e:
        print(f"✗ Handshake gagal: {e}")
    finally:
        ch.close()

HELP_INITIATOR = """Command:
  /start          hubungi peer dan mulai handshake
  /setkey <key>   ganti master key sendiri
  /quit           keluar"""

HELP_RESPONDER = """Command:
  /start          tunggu koneksi dari initiator
  /setkey <key>   ganti master key sendiri
  /quit           keluar"""

def menu(p: Peer, args, server: socket.socket | None) -> None:
    print(HELP_INITIATOR if p.initiator else HELP_RESPONDER)
    while True:
        cmd, _, arg = ask(f"{p.me}> ").strip().partition(" ")
        if cmd == "":
            continue
        elif cmd == "/start":
            if p.initiator:
                try:
                    ch = net.connect(*args.connect, p.me)
                except OSError as e:
                    print(f"✗ tidak bisa terhubung ke {args.connect[0]}:{args.connect[1]}: {e}")
                    continue
                run_session(p, ch, args.kdc, args.peer)
            else:
                print(f"Menunggu initiator di {args.listen[0]}:{args.listen[1]}...")
                ch, addr = net.accept(server, p.me)
                print(f"Koneksi dari {addr[0]}:{addr[1]}")
                run_session(p, ch, None, None)
        elif cmd == "/setkey":
            p.set_key(arg.strip())
        elif cmd == "/quit":
            return
        elif cmd == "/help":
            print(HELP_INITIATOR if p.initiator else HELP_RESPONDER)
        else:
            print(f"  ✗ command tidak dikenal: {cmd} (ketik /help)")

def addr_arg(text: str) -> tuple[str, int]:
    try:
        return net.parse_addr(text)
    except ValueError as e:
        raise argparse.ArgumentTypeError(str(e))

def main() -> None:
    parser = argparse.ArgumentParser(description="Peer Alice/Bob")
    parser.add_argument("--name", required=True, help="ID peer ini, mis. alice atau bob")
    parser.add_argument("--connect", type=addr_arg, help="host:port peer tujuan (membuat peer ini jadi initiator)")
    parser.add_argument("--kdc", type=addr_arg, help="host:port KDC (wajib untuk initiator)")
    parser.add_argument("--peer", default="bob", help="ID peer tujuan (initiator, default bob)")
    parser.add_argument("--listen", type=addr_arg, default="0.0.0.0:6000", help="host:port responder (default 0.0.0.0:6000)")
    parser.add_argument("--verbose", action="store_true", help="tampilkan session key dan nonce di log")
    args = parser.parse_args()

    initiator = args.connect is not None
    if initiator and args.kdc is None:
        parser.error("initiator (--connect) wajib memakai --kdc")
    for id_ in (args.name, args.peer):
        if not protocol.check_id(id_):
            parser.error(f"ID '{id_}' harus huruf kecil alfanumerik")
    if initiator and args.name == args.peer:
        parser.error("--name dan --peer tidak boleh sama")
    protocol.VERBOSE = args.verbose

    server = None
    try:
        key = ask(f"Master key untuk {args.name} ({protocol.KEY_LENGTH} karakter): ")
        while (error := protocol.check_key(key)) is not None:
            print(f"  ✗ {error}")
            key = ask(f"Master key untuk {args.name} ({protocol.KEY_LENGTH} karakter): ")
        p = Peer(args.name, key, initiator)
        if not initiator:
            server = net.listen(*args.listen)
        role = "initiator" if initiator else f"responder, listening di {args.listen[0]}:{args.listen[1]}"
        print(f"{args.name} siap ({role}).")
        menu(p, args, server)
    except (KeyboardInterrupt, EOFError):
        print()
    finally:
        if server is not None:
            server.close()
        print("Keluar.")

if __name__ == "__main__":
    main()
