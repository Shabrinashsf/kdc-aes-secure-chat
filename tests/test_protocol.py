import contextlib
import io
import threading
import unittest

# TODO integrasi: ganti ke `from kdc_chat import cipher`
from kdc_chat import cipher_stub as cipher  
from kdc_chat import net, protocol
from kdc_chat.protocol import HandshakeError

KA = "kunciAlice123456"
KB = "kunciBob12345678"

# Run `handler(ch)` for exactly one incoming connection, in a background thread
# Returns the port and a dict that will hold the handler's result or exception
def serve_once(me: str, handler) -> tuple[int, dict, threading.Thread]:
    server = net.listen("127.0.0.1", 0)
    port = server.getsockname()[1]
    result = {}

    def run():
        ch, _ = net.accept(server, me)
        server.close()
        try:
            result["value"] = handler(ch)
        except Exception as e:
            result["error"] = e
        finally:
            ch.close()

    t = threading.Thread(target=run, daemon=True)
    t.start()
    return port, result, t

def real_kdc(keys: dict[str, str]):
    return serve_once("kdc", lambda ch: protocol.kdc_handle(ch, keys))

def fake_kdc(payload_for):
    # A KDC that answers step 1 with whatever payload_for(id_a, id_b, n1) returns
    def handle(ch):
        msg = ch.recv()
        id_a, id_b, n1 = msg["payload"].split("|")
        ch.send("KEY_RESPONSE", id_a, payload_for(id_a, id_b, n1))
    return serve_once("kdc", handle)

def bob(kb: str):
    return serve_once("bob", lambda ch: protocol.bob_handshake(ch, "bob", kb))

class HandshakeTest(unittest.TestCase):
    def setUp(self):
        # Keep the [STEP n] logs out of the test output
        self._quiet = contextlib.redirect_stdout(io.StringIO())
        self._quiet.__enter__()

    def tearDown(self):
        self._quiet.__exit__(None, None, None)

    # Run Alice against the given KDC and Bob; returns Alice's result and Bob's result dict
    def run_alice(self, kdc_port, bob_port, bob_result, bob_thread, ka=KA):
        bob_ch = net.connect("127.0.0.1", bob_port, "alice")
        try:
            ks = protocol.alice_handshake(("127.0.0.1", kdc_port), bob_ch, "alice", "bob", ka)
        finally:
            bob_ch.close()
            bob_thread.join(3)
        self.assertFalse(bob_thread.is_alive())
        return ks, bob_result

    def test_normal_handshake_gives_same_ks(self):
        kdc_port, _, _ = real_kdc({"alice": KA, "bob": KB})
        ks, bob_result = self.run_alice(kdc_port, *bob(KB))
        self.assertEqual(bob_result["value"], (ks, "alice"))
        self.assertIsNone(protocol.check_key(ks))

    def test_wrong_bob_key_fails_at_step_3(self):
        kdc_port, _, _ = real_kdc({"alice": KA, "bob": KB})
        with self.assertRaisesRegex(HandshakeError, "bob menolak: tiket"):
            self.run_alice(kdc_port, *bob("kunciBobSALAH123"))

    def test_wrong_alice_key_fails_at_step_2(self):
        kdc_port, _, _ = real_kdc({"alice": KA, "bob": KB})
        bob_port, bob_result, bob_thread = bob(KB)
        with self.assertRaisesRegex(HandshakeError, "master key Alice"):
            self.run_alice(kdc_port, bob_port, bob_result, bob_thread, ka="kunciAliceSALAH1")
        # Bob never received a ticket; he only sees the connection closing
        self.assertIsInstance(bob_result["error"], HandshakeError)

    def test_unregistered_id_is_rejected_by_kdc(self):
        kdc_port, _, _ = real_kdc({"alice": KA})
        with self.assertRaisesRegex(HandshakeError, "kdc menolak: ID 'bob' tidak terdaftar"):
            self.run_alice(kdc_port, *bob(KB))

    def test_wrong_n1_is_rejected(self):
        def payload(id_a, id_b, n1):
            ks = protocol.new_session_key()
            wrong_n1 = str(int(n1) + 1)
            return (cipher.encrypt(f"{ks}|{id_a}|{id_b}|{wrong_n1}", KA) + "|"
                    + cipher.encrypt(f"{ks}|{id_a}", KB))
        kdc_port, _, _ = fake_kdc(payload)
        with self.assertRaisesRegex(HandshakeError, "N1 tidak cocok"):
            self.run_alice(kdc_port, *bob(KB))

    def test_step_2_must_have_two_parts(self):
        kdc_port, _, _ = fake_kdc(lambda id_a, id_b, n1: cipher.encrypt(f"x|{id_a}|{id_b}|{n1}", KA))
        with self.assertRaisesRegex(HandshakeError, "format langkah 2"):
            self.run_alice(kdc_port, *bob(KB))

    def test_wrong_f_n2_is_rejected_by_bob(self):
        # Alice that answers the challenge with N2 itself instead of f(N2)
        ks = protocol.new_session_key()
        bob_port, bob_result, bob_thread = bob(KB)
        ch = net.connect("127.0.0.1", bob_port, "alice")
        ch.send("TICKET", "bob", cipher.encrypt(f"{ks}|alice", KB))
        n2 = cipher.decrypt(ch.recv()["payload"], ks)
        ch.send("CHALLENGE_RESPONSE", "bob", cipher.encrypt(n2, ks))
        reply = ch.recv()
        ch.close()
        bob_thread.join(3)
        self.assertEqual(reply["type"], "ERROR")
        self.assertIn("f(N2) salah", str(bob_result["error"]))

    def test_ticket_for_another_sender_is_rejected(self):
        # Ticket says IDa = carol, but it is sent by alice
        bob_port, bob_result, bob_thread = bob(KB)
        ch = net.connect("127.0.0.1", bob_port, "alice")
        ch.send("TICKET", "bob", cipher.encrypt(f"{protocol.new_session_key()}|carol", KB))
        reply = ch.recv()
        ch.close()
        bob_thread.join(3)
        self.assertEqual(reply["type"], "ERROR")
        self.assertIn("tidak sama dengan pengirim", str(bob_result["error"]))

    def test_kdc_unreachable(self):
        server = net.listen("127.0.0.1", 0)
        port = server.getsockname()[1]
        server.close()
        bob_port, bob_result, bob_thread = bob(KB)
        with self.assertRaisesRegex(HandshakeError, "tidak bisa terhubung ke KDC"):
            self.run_alice(port, bob_port, bob_result, bob_thread)

if __name__ == "__main__":
    unittest.main()
