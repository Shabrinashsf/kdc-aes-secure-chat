
"""AES-128 CBC dengan PKCS#7 dan format ASCII/Hex.

Menggunakan implementasi AES manual dari aes.py.
"""

import secrets

from kdc_chat.aes import encrypt_block, decrypt_block


BLOCK_SIZE = 16


# 1. VALIDASI ASCII DAN KEY
def _to_ascii(text: str, name: str) -> bytes:
    """Mengubah string ASCII menjadi bytes."""
    if not isinstance(text, str):
        raise ValueError(f"{name} harus berupa string ASCII")

    try:
        return text.encode("ascii")
    except UnicodeEncodeError:
        raise ValueError(
            f"{name} hanya boleh menggunakan karakter ASCII"
        ) from None


def _validate_key(key: str) -> bytes:
    """Memastikan key tepat 16 byte ASCII."""
    key_bytes = _to_ascii(key, "Key")

    if len(key_bytes) != BLOCK_SIZE:
        raise ValueError(
            "Key AES-128 harus tepat 16 karakter ASCII"
        )

    return key_bytes


# 2. PKCS#7 PADDING

def _pad(data: bytes) -> bytes:
    """Menambahkan padding hingga kelipatan 16 byte."""
    padding_length = BLOCK_SIZE - (len(data) % BLOCK_SIZE)

    return data + bytes([padding_length] * padding_length)


def _unpad(data: bytes) -> bytes:
    """Menghapus dan memvalidasi PKCS#7 padding."""
    if not data or len(data) % BLOCK_SIZE != 0:
        raise ValueError("Panjang data padding tidak valid")

    padding_length = data[-1]

    if not 1 <= padding_length <= BLOCK_SIZE:
        raise ValueError("PKCS#7 padding tidak valid")

    if data[-padding_length:] != bytes(
        [padding_length] * padding_length
    ):
        raise ValueError(
            "PKCS#7 padding salah: ciphertext atau key tidak valid"
        )

    return data[:-padding_length]


# 3. XOR BYTES

def _xor_bytes(a: bytes, b: bytes) -> bytes:
    """Operasi XOR untuk dua blok berukuran sama."""
    if len(a) != len(b):
        raise ValueError("Ukuran blok XOR harus sama")

    return bytes(x ^ y for x, y in zip(a, b))


# 4. AES-CBC ENCRYPT

def encrypt(plaintext: str, key: str) -> str:
    """Enkripsi plaintext ASCII menjadi ciphertext Hex.

    Format output: IV (16 byte) + ciphertext.
    """
    key_bytes = _validate_key(key)
    plaintext_bytes = _to_ascii(plaintext, "Plaintext")

    padded = _pad(plaintext_bytes)

    # IV acak sepanjang 16 byte
    iv = secrets.token_bytes(BLOCK_SIZE)

    previous_block = iv
    encrypted_blocks = []

    for i in range(0, len(padded), BLOCK_SIZE):
        block = padded[i:i + BLOCK_SIZE]

        # CBC: plaintext XOR ciphertext sebelumnya
        xor_block = _xor_bytes(block, previous_block)

        encrypted_block = encrypt_block(
            xor_block,
            key_bytes
        )

        encrypted_blocks.append(encrypted_block)
        previous_block = encrypted_block

    # IV dikirim bersama ciphertext
    result = iv + b"".join(encrypted_blocks)

    return result.hex()


# 5. AES-CBC DECRYPT

def decrypt(cipher_hex: str, key: str) -> str:
    """Dekripsi ciphertext Hex menjadi plaintext ASCII."""
    key_bytes = _validate_key(key)

    if not isinstance(cipher_hex, str):
        raise ValueError("Ciphertext harus berupa string Hex")

    # Validasi representasi hexadecimal
    allowed = "0123456789abcdefABCDEF"

    if (
        len(cipher_hex) % 2 != 0
        or any(c not in allowed for c in cipher_hex)
    ):
        raise ValueError("Format hexadecimal tidak valid")

    try:
        encrypted_data = bytes.fromhex(cipher_hex)
    except ValueError:
        raise ValueError("Format hexadecimal tidak valid") from None

    # Minimal 16 byte IV + 16 byte ciphertext
    if (
        len(encrypted_data) < 2 * BLOCK_SIZE
        or (len(encrypted_data) - BLOCK_SIZE) % BLOCK_SIZE != 0
    ):
        raise ValueError("Panjang ciphertext AES-CBC tidak valid")

    iv = encrypted_data[:BLOCK_SIZE]
    ciphertext = encrypted_data[BLOCK_SIZE:]

    previous_block = iv
    decrypted_blocks = []

    for i in range(0, len(ciphertext), BLOCK_SIZE):
        block = ciphertext[i:i + BLOCK_SIZE]

        decrypted_block = decrypt_block(
            block,
            key_bytes
        )

        plaintext_block = _xor_bytes(
            decrypted_block,
            previous_block
        )

        decrypted_blocks.append(plaintext_block)
        previous_block = block

    padded_plaintext = b"".join(decrypted_blocks)

    plaintext_bytes = _unpad(padded_plaintext)

    try:
        return plaintext_bytes.decode("ascii")
    except UnicodeDecodeError:
        raise ValueError(
            "Hasil dekripsi bukan ASCII: key atau ciphertext salah"
        ) from None
