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

def accept_loop(server, keys: dict[str, str]) -> None:
    while True:
        try:
            ch, addr = net.accept(server, "kdc")
        except OSError:
            return  # server closed by /quit
        print(f"Koneksi dari {addr[0]}:{addr[1]}", flush=True)
        # One thread per connection so a slow client does not block others
        threading.Thread(target=protocol.kdc_handle, args=(ch, keys), daemon=True).start()

HELP = """Command KDC:
  /setkey <id> <key>  ganti master key <id> (atau daftarkan ID baru)
  /list               tampilkan ID dan master key yang terdaftar
  /quit               hentikan KDC"""

def console_loop(keys: dict[str, str]) -> None:
    while True:
        cmd, _, arg = input().strip().partition(" ")
        if cmd == "":
            continue
        elif cmd == "/setkey":
            id_, _, key = arg.strip().partition(" ")
            if not protocol.check_id(id_):
                print("  ✗ format: /setkey <id> <key>, id huruf kecil alfanumerik")
            elif (error := protocol.check_key(key)) is not None:
                print(f"  ✗ {error}")
            else:
                action = "diganti" if id_ in keys else "didaftarkan"
                keys[id_] = key
                print(f"  ✓ master key {id_} {action}, berlaku untuk request berikutnya")
        elif cmd == "/list":
            for id_, key in keys.items():
                print(f"  {id_:<10} {key}")
        elif cmd == "/quit":
            return
        elif cmd == "/help":
            print(HELP)
        else:
            print(f"  ✗ command tidak dikenal: {cmd} (ketik /help)")

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
    # Accept connections in the background so the main thread can read commands
    threading.Thread(target=accept_loop, args=(server, keys), daemon=True).start()
    print("Ketik /help untuk daftar command.")
    try:
        console_loop(keys)
    except (KeyboardInterrupt, EOFError):
        pass
    finally:
        server.close()
        print("\nKDC berhenti.")

if __name__ == "__main__":
    main()
