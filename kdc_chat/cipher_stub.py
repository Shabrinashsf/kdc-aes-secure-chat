# TEMPORARY fake cipher with the same signature as cipher.py (CONTRACT §2)
# NOT encryption: it only lets the protocol be tested before the real AES is ready

def encrypt(plaintext: str, key: str) -> str:
    return (key + "|" + plaintext).encode().hex()

def decrypt(cipher_hex: str, key: str) -> str:
    try:
        s = bytes.fromhex(cipher_hex).decode()
    except (ValueError, UnicodeDecodeError) as e:
        raise ValueError(f"stub: ciphertext tidak valid: {e}") from e
    k, _, p = s.partition("|")
    # Mimic the real cipher: a wrong key must fail, not return garbage
    if k != key:
        raise ValueError("stub: key salah")
    return p
