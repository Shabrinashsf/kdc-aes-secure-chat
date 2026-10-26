
"""Implementasi AES-128 manual."""


# 1. OPERASI GALOIS FIELD GF(2^8)

def _gf_mul(a: int, b: int) -> int:
    """Perkalian pada GF(2^8) sesuai aturan AES."""
    result = 0

    for _ in range(8):
        if b & 1:
            result ^= a

        high_bit = a & 0x80
        a = (a << 1) & 0xFF

        if high_bit:
            a ^= 0x1B

        b >>= 1

    return result


def _gf_pow(base: int, exponent: int) -> int:
    """Perpangkatan menggunakan perkalian GF(2^8)."""
    result = 1

    while exponent:
        if exponent & 1:
            result = _gf_mul(result, base)

        base = _gf_mul(base, base)
        exponent >>= 1

    return result


def _rotl8(value: int, shift: int) -> int:
    """Rotasi bit 8-bit ke kiri."""
    return (
        (value << shift) | (value >> (8 - shift))
    ) & 0xFF


# 2. S-BOX DAN INVERSE S-BOX

def _generate_sboxes() -> tuple[list[int], list[int]]:
    """Membangkitkan S-Box AES dan inverse-nya."""
    sbox = []

    for value in range(256):
        inverse = _gf_pow(value, 254) if value else 0

        transformed = (
            inverse
            ^ _rotl8(inverse, 1)
            ^ _rotl8(inverse, 2)
            ^ _rotl8(inverse, 3)
            ^ _rotl8(inverse, 4)
            ^ 0x63
        )

        sbox.append(transformed)

    inv_sbox = [0] * 256

    for index, mapped in enumerate(sbox):
        inv_sbox[mapped] = index

    return sbox, inv_sbox


S_BOX, INV_S_BOX = _generate_sboxes()

RCON = [
    0x01, 0x02, 0x04, 0x08, 0x10,
    0x20, 0x40, 0x80, 0x1B, 0x36
]


# 3. VALIDASI INPUT

def _check_16_bytes(data: bytes, name: str) -> None:
    if not isinstance(data, bytes) or len(data) != 16:
        raise ValueError(
            f"{name} harus berupa bytes sepanjang 16 byte"
        )


# 4. KEY EXPANSION

def expand_key(key: bytes) -> list[bytes]:
    """Menghasilkan 11 round key AES-128."""
    _check_16_bytes(key, "Key")

    words = [
        list(key[i:i + 4])
        for i in range(0, 16, 4)
    ]

    for index in range(4, 44):
        temp = words[index - 1].copy()

        if index % 4 == 0:
            # RotWord
            temp = temp[1:] + temp[:1]

            # SubWord
            temp = [S_BOX[x] for x in temp]

            # Rcon
            temp[0] ^= RCON[index // 4 - 1]

        words.append([
            words[index - 4][j] ^ temp[j]
            for j in range(4)
        ])

    return [
        bytes(sum(words[r * 4:(r + 1) * 4], []))
        for r in range(11)
    ]


# 5. ADD ROUND KEY

def _add_round_key(
    state: list[int],
    round_key: bytes
) -> None:
    for i in range(16):
        state[i] ^= round_key[i]


# 6. SUB BYTES & INVERSE SUB BYTES

def _sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = S_BOX[state[i]]


def _inv_sub_bytes(state: list[int]) -> None:
    for i in range(16):
        state[i] = INV_S_BOX[state[i]]


# 7. SHIFT ROWS & INVERSE SHIFT ROWS

def _shift_rows(state: list[int]) -> None:
    # State disimpan column-major
    for row in range(1, 4):
        old = [
            state[4 * col + row]
            for col in range(4)
        ]

        for col in range(4):
            state[4 * col + row] = old[
                (col + row) % 4
            ]


def _inv_shift_rows(state: list[int]) -> None:
    for row in range(1, 4):
        old = [
            state[4 * col + row]
            for col in range(4)
        ]

        for col in range(4):
            state[4 * col + row] = old[
                (col - row) % 4
            ]

# 8. MIX COLUMNS & INVERSE MIX COLUMNS

def _mix_columns(state: list[int]) -> None:
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i:i + 4]

        state[i:i + 4] = [
            _gf_mul(a0, 2) ^ _gf_mul(a1, 3) ^ a2 ^ a3,
            a0 ^ _gf_mul(a1, 2) ^ _gf_mul(a2, 3) ^ a3,
            a0 ^ a1 ^ _gf_mul(a2, 2) ^ _gf_mul(a3, 3),
            _gf_mul(a0, 3) ^ a1 ^ a2 ^ _gf_mul(a3, 2)
        ]


def _inv_mix_columns(state: list[int]) -> None:
    for col in range(4):
        i = col * 4
        a0, a1, a2, a3 = state[i:i + 4]

        state[i:i + 4] = [
            _gf_mul(a0, 14) ^ _gf_mul(a1, 11)
            ^ _gf_mul(a2, 13) ^ _gf_mul(a3, 9),

            _gf_mul(a0, 9) ^ _gf_mul(a1, 14)
            ^ _gf_mul(a2, 11) ^ _gf_mul(a3, 13),

            _gf_mul(a0, 13) ^ _gf_mul(a1, 9)
            ^ _gf_mul(a2, 14) ^ _gf_mul(a3, 11),

            _gf_mul(a0, 11) ^ _gf_mul(a1, 13)
            ^ _gf_mul(a2, 9) ^ _gf_mul(a3, 14)
        ]


# 9. AES ENCRYPT BLOCK

def encrypt_block(block: bytes, key: bytes) -> bytes:
    """Enkripsi satu blok 16 byte dengan AES-128."""
    _check_16_bytes(block, "Block")

    round_keys = expand_key(key)
    state = list(block)

    # Initial round
    _add_round_key(state, round_keys[0])

    # Round 1 sampai 9
    for round_num in range(1, 10):
        _sub_bytes(state)
        _shift_rows(state)
        _mix_columns(state)
        _add_round_key(state, round_keys[round_num])

    # Final round (tanpa MixColumns)
    _sub_bytes(state)
    _shift_rows(state)
    _add_round_key(state, round_keys[10])

    return bytes(state)



# 10. AES DECRYPT BLOCK

def decrypt_block(block: bytes, key: bytes) -> bytes:
    """Dekripsi satu blok 16 byte dengan AES-128."""
    _check_16_bytes(block, "Block")

    round_keys = expand_key(key)
    state = list(block)

    # Mulai dari round key terakhir
    _add_round_key(state, round_keys[10])

    # Round inverse 9 sampai 1
    for round_num in range(9, 0, -1):
        _inv_shift_rows(state)
        _inv_sub_bytes(state)
        _add_round_key(state, round_keys[round_num])
        _inv_mix_columns(state)

    # Final inverse round
    _inv_shift_rows(state)
    _inv_sub_bytes(state)
    _add_round_key(state, round_keys[0])

    return bytes(state)
