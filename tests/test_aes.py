
import unittest

from kdc_chat.aes import (
    S_BOX,
    INV_S_BOX,
    expand_key,
    encrypt_block,
    decrypt_block
)


class TestAES128(unittest.TestCase):

    def setUp(self):
        # Test vector AES-128 sesuai CONTRACT.md
        self.key = bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
        )

        self.plaintext = bytes.fromhex(
            "00112233445566778899aabbccddeeff"
        )

        self.expected_cipher = bytes.fromhex(
            "69c4e0d86a7b0430d8cdb78070b4c55a"
        )

    def test_encrypt_standard_vector(self):
        result = encrypt_block(self.plaintext, self.key)
        self.assertEqual(result, self.expected_cipher)

    def test_decrypt_standard_vector(self):
        result = decrypt_block(
            self.expected_cipher,
            self.key
        )
        self.assertEqual(result, self.plaintext)

    def test_encrypt_decrypt_roundtrip(self):
        plaintext = b"Hello Alice Bob!"
        key = b"1234567890ABCDEF"

        encrypted = encrypt_block(plaintext, key)
        decrypted = decrypt_block(encrypted, key)

        self.assertEqual(decrypted, plaintext)
        self.assertNotEqual(encrypted, plaintext)

    def test_key_expansion(self):
        round_keys = expand_key(self.key)

        self.assertEqual(len(round_keys), 11)

        for round_key in round_keys:
            self.assertEqual(len(round_key), 16)

        self.assertEqual(round_keys[0], self.key)

    def test_sbox(self):
        self.assertEqual(S_BOX[0x53], 0xED)
        self.assertEqual(INV_S_BOX[0xED], 0x53)

    def test_invalid_key_length(self):
        with self.assertRaises(ValueError):
            encrypt_block(
                self.plaintext,
                b"short"
            )

    def test_invalid_block_length(self):
        with self.assertRaises(ValueError):
            encrypt_block(
                b"hello",
                self.key
            )


if __name__ == "__main__":
    unittest.main()
