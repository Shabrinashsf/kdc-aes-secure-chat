import secrets
import string

# TODO integrasi: ganti ke `from kdc_chat import cipher`
from kdc_chat import cipher_stub as cipher  
from kdc_chat.net import Channel

# Key distribution protocol

DELIM = "|"
KEY_LENGTH = 16
KS_ALPHABET = string.ascii_letters + string.digits

# When True, the session key is printed in the logs (handy for the demo)
VERBOSE = False

class HandshakeError(Exception):
    pass

def new_nonce() -> str:
    return str(secrets.randbelow(10**9))

def new_session_key() -> str:
    return "".join(secrets.choice(KS_ALPHABET) for _ in range(KEY_LENGTH))

# Return an error message, or None if the key is valid
def check_key(key: str) -> str | None:
    if len(key) != KEY_LENGTH:
        return f"key harus tepat {KEY_LENGTH} karakter (sekarang {len(key)})"
    if not all(32 <= ord(c) < 127 for c in key):
        return "key hanya boleh berisi karakter ASCII yang bisa dicetak"
    return None

def check_id(id_: str) -> bool:
    return id_.isascii() and id_.isalnum() and id_.islower()

def short(s: str, limit: int = 48) -> str:
    return s if len(s) <= limit else f"{s[:limit]}...({len(s)} char)"

def log(step: int | str, text: str) -> None:
    print(f"[STEP {step}] {text}" if isinstance(step, int) else f"[{step}] {text}", flush=True)

def log_msg(step: int, msg: dict) -> None:
    log(step, f"{msg['from']:<5} -> {msg['to']:<5} {msg['type']:<13} {short(msg['payload'])}")

# KDC side: serve one key request (step 1 -> step 2), then close the connection.
# `keys` maps ID -> master key and may be changed by another thread (/setkey),
# so each key is read once.
def kdc_handle(ch: Channel, keys: dict[str, str]) -> None:
    msg = None
    try:
        msg = ch.recv()
        if msg is None:
            return
        log_msg(1, msg)
        if msg["type"] != "KEY_REQUEST":
            raise HandshakeError(f"diharapkan KEY_REQUEST, diterima {msg['type']}")

        fields = msg["payload"].split(DELIM)
        if len(fields) != 3:
            raise HandshakeError("format langkah 1 harus IDa|IDb|N1")
        id_a, id_b, n1 = fields
        if id_a != msg["from"]:
            raise HandshakeError(f"IDa ({id_a}) tidak sama dengan pengirim ({msg['from']})")
        if id_a == id_b:
            raise HandshakeError("IDa dan IDb tidak boleh sama")
        if not n1.isdigit():
            raise HandshakeError("N1 harus berupa angka")
        ka, kb = keys.get(id_a), keys.get(id_b)
        for id_, k in ((id_a, ka), (id_b, kb)):
            if k is None:
                raise HandshakeError(f"ID '{id_}' tidak terdaftar di KDC")

        ks = new_session_key()
        if VERBOSE:
            log("KDC", f"Ks baru untuk {id_a}<->{id_b}: {ks}")
        # Two separate parts, as in the class slides: E(Ka, ...) || E(Kb, ...)
        part1 = cipher.encrypt(DELIM.join((ks, id_a, id_b, n1)), ka)
        ticket = cipher.encrypt(DELIM.join((ks, id_a)), kb)
        ch.send("KEY_RESPONSE", id_a, part1 + DELIM + ticket)
        log(2, f"{'kdc':<5} -> {id_a:<5} {'KEY_RESPONSE':<13} E(Ka,[Ks|IDa|IDb|N1]) | E(Kb,[Ks|IDa])")
    except HandshakeError as e:
        log("ERROR", str(e))
        try:
            ch.send("ERROR", msg["from"], str(e))
        except OSError:
            pass
    except (ValueError, OSError) as e:
        log("ERROR", f"koneksi bermasalah: {e}")
    finally:
        ch.close()
