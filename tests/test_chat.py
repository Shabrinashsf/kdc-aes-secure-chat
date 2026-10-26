
import queue
import unittest
from unittest.mock import patch

from kdc_chat.chat import ChatSession
from kdc_chat.cipher import encrypt, decrypt


class FakeChannel:
    """Simulasi Channel tanpa socket sungguhan."""

    def __init__(self, me, peer, auto_ack=False):
        self.me = me
        self.peer = peer
        self.incoming = queue.Queue()
        self.sent = []
        self.auto_ack = auto_ack

    def send(self, type, to, payload=""):
        self.sent.append((type, to, payload))

        if type == "REKEY" and self.auto_ack:
            self.incoming.put({
                "type": "REKEY_ACK",
                "from": self.peer,
                "to": self.me,
                "payload": ""
            })

    def recv(self):
        try:
            return self.incoming.get(timeout=2)
        except queue.Empty:
            return None

    def close(self):
        self.incoming.put(None)


class TestChatSession(unittest.TestCase):

    def setUp(self):
        self.key = "1234567890ABCDEF"

    def test_send_chat_and_quit(self):
        ch = FakeChannel("alice", "bob")

        inputs = iter([
            "/hex",
            "Halo Bob!",
            "/quit"
        ])

        with patch("kdc_chat.chat.console.start"), patch(
            "kdc_chat.chat.console.poll",
            side_effect=lambda t: next(inputs)
        ):
            result = ChatSession(
                ch, self.key, "alice", "bob"
            ).run()

        self.assertEqual(result, "quit")
        self.assertEqual(ch.sent[0][0], "CHAT")
        self.assertEqual(ch.sent[0][1], "bob")

        self.assertEqual(
            decrypt(ch.sent[0][2], self.key),
            "Halo Bob!"
        )

        self.assertEqual(ch.sent[1][0], "BYE")

    def test_receive_chat_and_bye(self):
        ch = FakeChannel("bob", "alice")

        ch.incoming.put({
            "type": "CHAT",
            "from": "alice",
            "to": "bob",
            "payload": encrypt("Halo!", self.key)
        })

        ch.incoming.put({
            "type": "BYE",
            "from": "alice",
            "to": "bob",
            "payload": ""
        })

        with patch("kdc_chat.chat.console.start"), patch(
            "kdc_chat.chat.console.poll",
            return_value=None
        ):
            result = ChatSession(
                ch, self.key, "bob", "alice"
            ).run()

        self.assertEqual(result, "closed")

    def test_alice_rekey(self):
        ch = FakeChannel(
            "alice", "bob", auto_ack=True
        )

        with patch("kdc_chat.chat.console.start"), patch(
            "kdc_chat.chat.console.poll",
            return_value="/rekey"
        ):
            result = ChatSession(
                ch,
                self.key,
                "alice",
                "bob",
                on_command=lambda cmd: (
                    "rekey" if cmd == "/rekey" else None
                )
            ).run()

        self.assertEqual(result, "rekey")
        self.assertEqual(
            ch.sent[0],
            ("REKEY", "bob", "")
        )

    def test_bob_accepts_rekey(self):
        ch = FakeChannel("bob", "alice")

        ch.incoming.put({
            "type": "REKEY",
            "from": "alice",
            "to": "bob",
            "payload": ""
        })

        with patch("kdc_chat.chat.console.start"), patch(
            "kdc_chat.chat.console.poll",
            return_value=None
        ):
            result = ChatSession(
                ch, self.key, "bob", "alice"
            ).run()

        self.assertEqual(result, "rekey")
        self.assertEqual(
            ch.sent[0],
            ("REKEY_ACK", "alice", "")
        )


if __name__ == "__main__":
    unittest.main()
