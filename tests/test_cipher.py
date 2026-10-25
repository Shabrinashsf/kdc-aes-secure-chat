
import unittest

from kdc_chat.cipher import encrypt, decrypt


class TestCipher(unittest.TestCase):

    def setUp(self):
        self.key = "1234567890ABCDEF"
        self.plaintext = "Halo Bob, apa kabar?"

    def test_encrypt_decrypt(self):
        cipher_hex = encrypt(self.plaintext, self.key)
        result = decrypt(cipher_hex, self.key)

        self.assertEqual(result, self.plaintext)

    def test_cipher_is_hex(self):
        cipher_hex = encrypt(self.plaintext, self.key)

        self.assertTrue(
            all(c in "0123456789abcdef" for c in cipher_hex)
        )

    def test_random_iv(self):
        cipher1 = encrypt(self.plaintext, self.key)
        cipher2 = encrypt(self.plaintext, self.key)

        self.assertNotEqual(cipher1, cipher2)
        self.assertEqual(
            decrypt(cipher1, self.key),
            self.plaintext
        )
        self.assertEqual(
            decrypt(cipher2, self.key),
            self.plaintext
        )

    def test_empty_plaintext(self):
        cipher_hex = encrypt("", self.key)
        self.assertEqual(decrypt(cipher_hex, self.key), "")

    def test_long_plaintext(self):
        text = "Alice mengirim pesan ke Bob. " * 20

        cipher_hex = encrypt(text, self.key)
        self.assertEqual(decrypt(cipher_hex, self.key), text)

    def test_exact_block_plaintext(self):
        text = "ABCDEFGHIJKLMNOP"

        cipher_hex = encrypt(text, self.key)
        self.assertEqual(decrypt(cipher_hex, self.key), text)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt("Halo Bob", "short")

    def test_non_ascii_plaintext(self):
        with self.assertRaises(ValueError):
            encrypt("Halo Bob 😊", self.key)

    def test_non_ascii_key(self):
        with self.assertRaises(ValueError):
            encrypt("Halo", "123456789012345é")

    def test_invalid_hex(self):
        with self.assertRaises(ValueError):
            decrypt("zz1234", self.key)

    def test_invalid_cipher_length(self):
        with self.assertRaises(ValueError):
            decrypt("aabbcc", self.key)

    def test_modified_padding(self):
        cipher_data = bytearray.fromhex(
            encrypt("Halo", self.key)
        )

        # Mengubah byte terakhir IV agar padding rusak
        cipher_data[15] ^= 0x01

        with self.assertRaises(ValueError):
            decrypt(cipher_data.hex(), self.key)


if __name__ == "__main__":
    unittest.main()
