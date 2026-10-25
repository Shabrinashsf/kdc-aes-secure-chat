# Modul A — AES-128 Manual & Encrypted Chat

> **Tugas 2 Keamanan Informasi** — implementasi kriptografi AES dan sesi chat terenkripsi untuk sistem **KDC–Alice–Bob**.
>
> **Branch pengembangan:** `feat/aes-core`  
> **Cakupan:** Modul A (AES, Cipher, Console, dan Chat)

## 1. Deskripsi

Modul A menyediakan enkripsi dan dekripsi **AES-128 yang diimplementasikan secara manual**, pembungkus **AES-CBC dengan PKCS#7 padding**, pengelolaan input terminal, serta sesi komunikasi dua arah antara Alice dan Bob. Modul ini akan digunakan setelah kedua pihak memperoleh *session key* melalui protokol distribusi kunci yang dikembangkan pada Modul B.

Modul A tidak menjalankan server KDC atau protokol handshake sendiri. Fitur tersebut menjadi tanggung jawab Modul B dan diintegrasikan melalui antarmuka yang disepakati dalam `CONTRACT.md`.

## 2. Fitur

- **AES-128 manual:** S-Box dan inverse S-Box, Key Expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, dan operasi inversnya.
- **Enkripsi satu blok:** `encrypt_block()` dan `decrypt_block()` untuk blok tepat 16 byte.
- **AES-CBC:** enkripsi dan dekripsi pesan dengan panjang bervariasi memakai IV acak 16 byte dan PKCS#7 padding.
- **Validasi ASCII:** plaintext dan key harus berupa ASCII; key AES-128 harus tepat 16 karakter ASCII.
- **Output Hex:** hasil `cipher.encrypt()` berupa hexadecimal huruf kecil, dengan format `IV || ciphertext`.
- **Chat dua arah:** thread penerima pesan, input terminal, enkripsi sebelum pengiriman dan dekripsi setelah penerimaan.
- **Perintah chat:** `/help`, `/hex`, `/quit`, serta dukungan alur `/rekey` melalui callback dari `peer.py`.
- **Unit testing:** pengujian algoritma AES, lapisan cipher, serta simulasi sesi chat.

## 3. Struktur File Modul A

```text
kdc-aes-secure-chat/
├── kdc_chat/
│   ├── aes.py             # Implementasi AES-128 manual
│   ├── cipher.py          # AES-CBC, PKCS#7, ASCII, Hex
│   ├── console.py         # Input terminal menggunakan thread dan queue
│   └── chat.py            # Sesi chat terenkripsi dan kontrol rekey
├── tests/
│   ├── test_aes.py        # Test AES-128 dan test vector standar
│   ├── test_cipher.py     # Test round-trip, IV, validasi input
│   └── test_chat.py       # Test sesi chat menggunakan FakeChannel
└── README_AES.md          # Dokumentasi khusus Modul A
```

File lain di repository (antara lain `kdc.py`, `peer.py`, `net.py`, dan `protocol.py`) merupakan bagian Modul B atau file bersama.

## 4. Cara Kerja

### AES-128 manual

1. Plaintext satu blok (16 byte) dan key 16 byte menjadi input.
2. **Key Expansion** menghasilkan 11 *round key*.
3. **Initial AddRoundKey** melakukan XOR dengan round key pertama.
4. **Round 1–9** menjalankan SubBytes → ShiftRows → MixColumns → AddRoundKey.
5. **Round 10** menjalankan SubBytes → ShiftRows → AddRoundKey, tanpa MixColumns.
6. Proses dekripsi menggunakan transformasi invers dalam urutan yang sesuai.

### AES-CBC untuk pesan

1. Validasi plaintext dan key sebagai ASCII.
2. Tambahkan PKCS#7 padding agar panjang data merupakan kelipatan 16 byte.
3. Bangkitkan IV acak 16 byte.
4. XOR setiap blok plaintext dengan IV atau ciphertext blok sebelumnya, lalu enkripsi menggunakan AES manual.
5. Kembalikan hasil dalam format hexadecimal: `hex(IV || ciphertext)`.
6. Saat dekripsi, pisahkan IV, jalankan proses CBC terbalik, validasi padding, lalu ubah hasil ke ASCII.

### Alur chat

Setelah handshake Modul B berhasil, Alice dan Bob menerima *session key* yang sama. `ChatSession` menggunakan `cipher.encrypt()` untuk pesan keluar dan `cipher.decrypt()` untuk pesan masuk. Pengiriman dan penerimaan memakai `Channel` dari `net.py` (Modul B). Pergantian session key menggunakan pesan kontrol `REKEY` dan `REKEY_ACK` yang dikoordinasikan oleh `peer.py`.

## 5. Persyaratan

- Python **3.10 atau lebih baru**.
- Tidak memerlukan library kriptografi eksternal. Implementasi menggunakan Python standard library.
- Jalankan perintah dari direktori root repository.

## 6. Menjalankan Pengujian

**Tes AES (7 pengujian):**

```powershell
python -m unittest discover -s tests -p "test_aes.py" -v
```

**Tes cipher (12 pengujian):**

```powershell
python -m unittest discover -s tests -p "test_cipher.py" -v
```

**Tes chat (4 pengujian menggunakan FakeChannel):**

```powershell
python -m unittest discover -s tests -p "test_chat.py" -v
```

**Jalankan semua pengujian yang tersedia:**

```powershell
python -m unittest discover -s tests -v
```

Total **23 pengujian Modul A** telah dijalankan pada pengembangan awal. Jumlah keseluruhan repository dapat bertambah setelah test Modul B digabungkan.

### Test vector AES-128

```text
Key       : 000102030405060708090a0b0c0d0e0f
Plaintext : 00112233445566778899aabbccddeeff
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
```

Nilai ciphertext di atas digunakan untuk memverifikasi implementasi AES-128 satu blok, bukan untuk merepresentasikan hasil AES-CBC dengan IV acak.

## 7. Contoh Penggunaan API Cipher

```python
from kdc_chat.cipher import encrypt, decrypt

key = "1234567890ABCDEF"  # 16 karakter ASCII
pesan = "Halo Bob!"

cipher_hex = encrypt(pesan, key)
print("Ciphertext (Hex):", cipher_hex)
print("Hasil dekripsi:", decrypt(cipher_hex, key))
```

Karena IV dibuat acak, ciphertext dari pesan dan key yang sama dapat berbeda pada setiap proses enkripsi.

## 8. Perintah pada Sesi Chat

| Perintah | Fungsi |
|---|---|
| `/help` | Menampilkan bantuan perintah |
| `/hex` | Mengaktifkan/menonaktifkan tampilan ciphertext Hex |
| `/quit` | Menutup sesi chat dan mengirim `BYE` |
| `/rekey` | Meminta session key baru; diproses bersama `peer.py` dan protokol KDC |

Antarmuka `ChatSession` mengikuti kontrak bersama:

```python
ChatSession(channel, session_key, me, peer, on_command=None).run()
```

Nilai kembalian `run()` adalah `"quit"`, `"rekey"`, atau `"closed"`.

## 9. Status Implementasi & Integrasi

**Sudah dikerjakan pada branch `feat/aes-core`:** implementasi AES-128, AES-CBC, console, chat, dan pengujian unit Modul A.

**Masih perlu diuji bersama Modul B:** penggantian `cipher_stub.py` dengan `cipher.py` asli di protokol, handshake KDC lima langkah, chat dua arah pada IP berbeda, perintah rekey end-to-end, serta capture Wireshark. Tes `test_chat.py` masih menggunakan **FakeChannel**, bukan bukti komunikasi jaringan langsung.

## 10. Catatan Keamanan

- Kunci harus diberikan dan dikelola sesuai protokol KDC; jangan menaruh master key asli di source code atau commit Git.
- Mode CBC dengan IV acak memberikan kerahasiaan pesan, tetapi **tidak menyediakan autentikasi atau integritas ciphertext secara kriptografis**. Validasi padding/ASCII tidak menggantikan MAC atau mode AEAD.
- `cipher_stub.py` pada Modul B hanya simulasi untuk pengujian dan **harus dihapus sebelum demo/submission** setelah AES asli terintegrasi.

---

**Pembagian kontribusi:** Modul A mengembangkan AES, Cipher, Console, dan Chat; Modul B mengembangkan jaringan, KDC, protokol handshake, dan program peer. Kesepakatan API dan format pesan merujuk pada `CONTRACT.md`.
