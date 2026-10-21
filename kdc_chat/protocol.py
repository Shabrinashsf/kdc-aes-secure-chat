import secrets
import string

# TODO integrasi: ganti ke `from kdc_chat import cipher`
from kdc_chat import cipher_stub as cipher  
from kdc_chat import net
from kdc_chat.net import Channel

# Key distribution protocol

DELIM = "|"
KEY_LENGTH = 16
KS_ALPHABET = string.ascii_letters + string.digits

# When True, the session key is printed in the logs (handy for the demo)
VERBOSE = False

# `remote` = True when the other side reported the error (an ERROR message), so we must not answer it with another ERROR
class HandshakeError(Exception):
    def __init__(self, reason: str, remote: bool = False):
        super().__init__(reason)
        self.remote = remote

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
    log(step, f"{msg['from']:<5} -> {msg['to']:<5} {msg['type']:<18} {short(msg['payload'])}")

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
        log(2, f"{'kdc':<5} -> {id_a:<5} {'KEY_RESPONSE':<18} E(Ka,[Ks|IDa|IDb|N1]) | E(Kb,[Ks|IDa])")
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

def f(n2: str) -> str:
    return str(int(n2) + 1)

def _send(ch: Channel, step: int, type_: str, to: str, payload: str) -> None:
    try:
        ch.send(type_, to, payload)
    except OSError as e:
        raise HandshakeError(f"gagal mengirim {type_} ke {to}: {e}") from e
    log_msg(step, {"type": type_, "from": ch.me, "to": to, "payload": payload})

# Receive the next message and make sure it is the expected type
def _expect(ch: Channel, step: int, type_: str) -> dict:
    try:
        msg = ch.recv()
    except ValueError as e:
        raise HandshakeError(f"pesan rusak saat menunggu {type_}: {e}") from e
    if msg is None:
        raise HandshakeError(f"koneksi ditutup saat menunggu {type_}", remote=True)
    if msg["type"] == "ERROR":
        raise HandshakeError(f"{msg['from']} menolak: {msg['payload']}", remote=True)
    log_msg(step, msg)
    if msg["type"] != type_:
        raise HandshakeError(f"diharapkan {type_}, diterima {msg['type']}")
    return msg

def _decrypt(cipher_hex: str, key: str, what: str) -> str:
    try:
        return cipher.decrypt(cipher_hex, key)
    except ValueError as e:
        raise HandshakeError(f"{what} gagal dibuka: {e}") from e

def _fail(ch: Channel, to: str, e: HandshakeError) -> None:
    log("ERROR", str(e))
    if not e.remote:
        try:
            ch.send("ERROR", to, str(e))
        except OSError:
            pass

# Alice side: steps 1-2 with the KDC, then steps 3-5 with Bob
# Returns Ks. Raises HandshakeError on failure; closing bob_ch is up to the caller
def alice_handshake(kdc_addr: tuple[str, int], bob_ch: Channel,
                    me: str, peer: str, ka: str) -> str:
    # Steps 1-2: ask the KDC for a session key
    try:
        kdc_ch = net.connect(*kdc_addr, me)
    except OSError as e:
        raise HandshakeError(f"tidak bisa terhubung ke KDC {kdc_addr[0]}:{kdc_addr[1]}: {e}") from e
    try:
        n1 = new_nonce()
        _send(kdc_ch, 1, "KEY_REQUEST", "kdc", DELIM.join((me, peer, n1)))
        reply = _expect(kdc_ch, 2, "KEY_RESPONSE")
    except HandshakeError as e:
        _fail(kdc_ch, "kdc", e)
        raise
    finally:
        kdc_ch.close()

    try:
        parts = reply["payload"].split(DELIM)
        if len(parts) != 2:
            raise HandshakeError("format langkah 2 harus E(Ka,...)|E(Kb,...)")
        part1, ticket = parts
        fields = _decrypt(part1, ka, "E(Ka,...) dengan master key Alice").split(DELIM)
        if len(fields) != 4:
            raise HandshakeError("isi E(Ka,...) harus Ks|IDa|IDb|N1")
        ks, id_a, id_b, n1_reply = fields
        if (id_a, id_b) != (me, peer):
            raise HandshakeError(f"ID di jawaban KDC ({id_a}, {id_b}) bukan ({me}, {peer})")
        # N1 proves this answer belongs to our request and is not a replay
        if n1_reply != n1:
            raise HandshakeError(f"N1 tidak cocok (dikirim {n1}, diterima {n1_reply})")
        if check_key(ks) is not None:
            raise HandshakeError("Ks dari KDC tidak valid")
        log(2, f"{me}: N1 cocok ✓  Ks diterima" + (f": {ks}" if VERBOSE else ""))
    except HandshakeError as e:
        # The KDC connection is already closed and Bob has not been contacted yet
        log("ERROR", str(e))
        raise

    # Steps 3-5: hand the ticket to Bob and answer his challenge
    try:
        _send(bob_ch, 3, "TICKET", peer, ticket)
        challenge = _expect(bob_ch, 4, "CHALLENGE")
        n2 = _decrypt(challenge["payload"], ks, "E(Ks, N2)")
        if not n2.isdigit():
            raise HandshakeError("N2 harus berupa angka")
        if VERBOSE:
            log(4, f"{me}: N2 = {n2}")
        _send(bob_ch, 5, "CHALLENGE_RESPONSE", peer, cipher.encrypt(f(n2), ks))
        _expect(bob_ch, 5, "HANDSHAKE_OK")
    except HandshakeError as e:
        _fail(bob_ch, peer, e)
        raise
    log("OK", f"handshake {me} <-> {peer} selesai" + (f", Ks = {ks}" if VERBOSE else ""))
    return ks

# Bob side: steps 3-5. Returns (Ks, Alice's ID)
# Raises HandshakeError on failure; closing alice_ch is up to the caller
def bob_handshake(alice_ch: Channel, me: str, kb: str,
                  first_msg: dict | None = None) -> tuple[str, str]:
    peer = first_msg["from"] if first_msg else "?"
    try:
        if first_msg is None:
            msg = _expect(alice_ch, 3, "TICKET")
        else:
            msg = first_msg
            log_msg(3, msg)
            if msg["type"] != "TICKET":
                raise HandshakeError(f"diharapkan TICKET, diterima {msg['type']}")
        peer = msg["from"]

        fields = _decrypt(msg["payload"], kb, "tiket E(Kb,...) dengan master key Bob").split(DELIM)
        if len(fields) != 2:
            raise HandshakeError("isi tiket harus Ks|IDa")
        ks, id_a = fields
        if id_a != peer:
            raise HandshakeError(f"IDa di tiket ({id_a}) tidak sama dengan pengirim ({peer})")
        if check_key(ks) is not None:
            raise HandshakeError("Ks di tiket tidak valid")
        log(3, f"{me}: tiket valid ✓  Ks diterima dari {id_a}" + (f": {ks}" if VERBOSE else ""))

        # Steps 4-5: prove that Alice really holds Ks (and is not replaying an old ticket)
        n2 = new_nonce()
        if VERBOSE:
            log(4, f"{me}: N2 = {n2}")
        _send(alice_ch, 4, "CHALLENGE", peer, cipher.encrypt(n2, ks))
        answer = _expect(alice_ch, 5, "CHALLENGE_RESPONSE")
        if _decrypt(answer["payload"], ks, "E(Ks, f(N2))") != f(n2):
            raise HandshakeError("f(N2) salah")
        log(5, f"{me}: f(N2) cocok ✓")
        _send(alice_ch, 5, "HANDSHAKE_OK", peer, "")
    except HandshakeError as e:
        _fail(alice_ch, peer, e)
        raise
    log("OK", f"handshake {me} <-> {peer} selesai" + (f", Ks = {ks}" if VERBOSE else ""))
    return ks, peer
