import argparse
import threading

from kdc_chat import net, protocol

# KDC entry point: stores master keys and serves key requests

def ask_key(id_: str) -> str:
    while True:
        key = input(f"Master key untuk {id_} ({protocol.KEY_LENGTH} karakter): ")
        error = protocol.check_key(key)
        if error is None:
            return key
        print(f"  ✗ {error}")

def main() -> None:
    parser = argparse.ArgumentParser(description="Key Distribution Center")
    parser.add_argument("--listen", default="0.0.0.0:5000", help="host:port (default 0.0.0.0:5000)")
    parser.add_argument("--users", default="alice,bob", help="ID yang terdaftar, dipisah koma")
    parser.add_argument("--verbose", action="store_true", help="tampilkan session key di log")
    args = parser.parse_args()

    try:
        host, port = net.parse_addr(args.listen)
    except ValueError as e:
        parser.error(str(e))
    protocol.VERBOSE = args.verbose
    users = [u.strip() for u in args.users.split(",") if u.strip()]
    for u in users:
        if not protocol.check_id(u):
            parser.error(f"ID '{u}' harus huruf kecil alfanumerik")

    keys = {u: ask_key(u) for u in users}

    server = net.listen(host, port)
    print(f"KDC listening di {host}:{port}, terdaftar: {', '.join(keys)}", flush=True)
    try:
        while True:
            ch, addr = net.accept(server, "kdc")
            print(f"Koneksi dari {addr[0]}:{addr[1]}", flush=True)
            # One thread per connection so a slow client does not block others
            threading.Thread(target=protocol.kdc_handle, args=(ch, keys), daemon=True).start()
    except KeyboardInterrupt:
        print("\nKDC berhenti.")
    finally:
        server.close()

if __name__ == "__main__":
    main()
