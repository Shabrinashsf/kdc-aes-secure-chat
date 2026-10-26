# KDC AES Secure Chat

Aplikasi chat dua arah antara **Alice** dan **Bob** yang kuncinya dibagikan oleh **KDC (Key Distribution Center)**, lalu pesannya dienkripsi dengan **AES yang diimplementasikan manual**. Dibuat untuk Tugas 2 mata kuliah Keamanan Informasi.

# Gambaran umum

Alice dan Bob tidak pernah bertukar kunci secara langsung. Masing-masing hanya berbagi _master key_ dengan KDC. Saat Alice ingin berbicara dengan Bob, KDC membuat _session key_ (Ks) sementara dan membagikannya ke keduanya dengan skenario key distribution lima langkah:

```
(1) A  → KDC : IDa ‖ IDb ‖ N1
(2) KDC → A  : E(Ka, [Ks ‖ IDa ‖ IDb ‖ N1]) ‖ E(Kb, [Ks ‖ IDa])
(3) A  → B   : E(Kb, [Ks ‖ IDa])
(4) B  → A   : E(Ks, N2)
(5) A  → B   : E(Ks, f(N2))
```

Setelah langkah 5, Alice dan Bob saling berkirim pesan yang dienkripsi AES memakai Ks. Kedua pihak bisa menjadi pengirim maupun penerima.

## Arsitektur

```
                 ┌──────────┐
                 │   KDC    │  server
                 └────▲─────┘
                      │ langkah 1–2 (koneksi singkat)
                      │
 ┌──────────┐  langkah 3–5 + chat (satu koneksi TCP, dua arah)  ┌──────────┐
 │  Alice   │ ────────────────────────────────────────────────► │   Bob    │
 └──────────┘ ◄──────────────────────────────────────────────── └──────────┘
```

- **KDC ↔ Alice**: client-server. KDC hanya menunggu dan melayani request.
- **Alice ↔ Bob**: koneksi langsung (peer-to-peer) lewat satu koneksi TCP full-duplex. Chat tidak melewati KDC.
- Tiga proses dijalankan di tiga perangkat dengan IP berbeda.

## Ketentuan utama

- AES dan KDC ditulis manual, tanpa library kriptografi.
- Key dan plaintext berformat ASCII, ciphertext ditampilkan dalam Hex.
- Key bisa diganti saat program berjalan, tidak di-hardcode.
- Hanya memakai Python standard library.

# Struktur proyek

```
kdc_chat/
├── net.py          transport: framing pesan + Channel
├── protocol.py     langkah 1–5 key distribution
├── aes.py          AES manual
├── cipher.py       padding, mode CBC, konversi ASCII/Hex
├── console.py      pembaca input keyboard
└── chat.py         sesi chat dua arah
kdc.py              program KDC
peer.py             program Alice / Bob
tests/              unit test
```

# Cara menjalankan

Python 3.10 atau lebih baru, tanpa dependensi eksternal. Di Windows, pakai `python` sebagai ganti `python3`. Jalankan semua perintah dari root repo.

Ada tiga program, masing-masing di terminalnya sendiri: **KDC**, **Bob**, dan **Alice**. Jalankan dengan urutan itu.

| Program | Perintah |
| --- | --- |
| KDC | `python3 kdc.py --listen 0.0.0.0:5000 --verbose` |
| Bob | `python3 peer.py --name bob --listen 0.0.0.0:6000` |
| Alice | `python3 peer.py --name alice --kdc <IP_KDC>:5000 --connect <IP_BOB>:6000` |

Untuk satu komputer, ganti `<IP_KDC>` dan `<IP_BOB>` dengan `127.0.0.1`.

Peran initiator ditentukan oleh `--connect`, bukan oleh nama. Peer yang memakai `--connect` dan `--kdc` menjadi **initiator** (yang meminta session key ke KDC dan menghubungi lawan bicara), sedangkan peer tanpa `--connect` menjadi **responder** (menunggu). Jadi Bob juga bisa menjadi initiator, dengan menukar perannya:

| Program | Perintah |
| --- | --- |
| Alice (responder) | `python3 peer.py --name alice --listen 0.0.0.0:6000` |
| Bob (initiator) | `python3 peer.py --name bob --kdc <IP_KDC>:5000 --connect <IP_ALICE>:6000` |

Pada kasus ini, `<IP_BOB>` pada pembahasan di bawah diganti dengan IP Alice.

## Langkah demi langkah

1. **KDC** meminta master key untuk `alice` dan `bob` (masing-masing tepat 16 karakter). Contoh: `kunciAlice123456` dan `kunciBob12345678`.
2. **Bob** dan **Alice** masing-masing meminta master key mereka sendiri. Isi dengan key yang **sama** dengan yang dimasukkan di KDC. Master key bersifat _pre-shared_, jadi kalau berbeda, handshake akan gagal.
3. Di terminal **Bob** ketik `/start`. Bob menunggu koneksi dari Alice.
4. Di terminal **Alice** ketik `/start`. Alice menghubungi Bob, meminta session key ke KDC, lalu kelima langkah handshake berjalan dan tampil di log (`[STEP 1]` sampai `[OK]`).
5. Setelah muncul `Chat dengan ... aktif`, ketik pesan lalu Enter. Alice dan Bob bisa saling mengirim.

## Tiga perangkat dengan IP berbeda

1. Hubungkan ketiga laptop ke **jaringan yang sama**. Hotspot HP paling aman, karena WiFi kampus sering memblokir koneksi antar-client.
2. Cek IP masing-masing laptop: `ipconfig` (Windows) atau `ip a` (Linux dan Mac).
3. Pastikan laptop saling terhubung: `ping <IP>`.
4. Buka firewall untuk koneksi masuk: **TCP 5000** di laptop KDC dan **TCP 6000** di laptop Bob. Alice tidak perlu menerima koneksi masuk.
5. Jalankan program seperti tabel di atas dengan IP yang sebenarnya.

Untuk memastikan port terjangkau sebelum demo, jalankan dari laptop Alice (setelah KDC dan Bob aktif):

```bash
python3 -c "import socket; socket.create_connection(('<IP_KDC>', 5000), 3); print('KDC terjangkau')"
python3 -c "import socket; socket.create_connection(('<IP_BOB>', 6000), 3); print('Bob terjangkau')"
```

> **Jika memakai WSL2**, jaringannya NAT sehingga laptop lain tidak bisa terhubung ke program di dalam WSL. Jalankan Python langsung di Windows, atau aktifkan `networkingMode=mirrored` di `%UserProfile%\.wslconfig`:
>
> ```ini
> [wsl2]
> networkingMode=mirrored
> ```
>
> lalu jalankan `wsl --shutdown` dan buka WSL kembali.

## Command

| Di mana | Command | Fungsi |
| --- | --- | --- |
| Menu Alice dan Bob | `/start` | Alice: hubungi Bob dan mulai handshake. Bob: tunggu koneksi Alice |
| Menu dan sesi chat | `/setkey <key>` | Ganti master key sendiri, berlaku di handshake berikutnya |
| Sesi chat | `/hex` | Tampilkan atau sembunyikan ciphertext hex |
| Sesi chat | `/rekey` | Initiator (yang menghubungi KDC) meminta session key baru, tanpa memutus koneksi |
| Sesi chat | `/quit` | Akhiri sesi, kembali ke menu |
| Menu | `/quit` | Keluar dari program |
| KDC | `/setkey <id> <key>` | Ganti master key `<id>` tanpa restart |
| KDC | `/list` | Tampilkan ID dan master key terdaftar |
| KDC | `/quit` | Hentikan KDC |

## Skenario demo

| # | Aksi | Yang ditunjukkan |
| --- | --- | --- |
| 1 | Jalankan KDC, Bob, Alice, lalu `/start` di Bob dan Alice | Handshake 1–5 berhasil, Ks sama di ketiga log |
| 2 | Alice kirim pesan, Bob membalas | Chat dua arah |
| 3 | Alice `/hex`, kirim pesan yang sama dua kali | Ciphertext berbeda tiap kirim karena IV acak |
| 4 | Alice `/rekey` | Ks baru dari KDC, chat lanjut |
| 5 | `/quit`, lalu Bob `/setkey` ke key lain saja, `/start` di keduanya | Gagal di langkah 3, program tidak crash, kembali ke menu |
| 6 | KDC `/setkey bob <key yang sama>`, `/start` lagi | Berhasil tanpa restart |
| 7 | `/setkey pendek` | Ditolak, key harus 16 karakter |

## Wireshark

1. Capture di **laptop Alice**, karena Alice terlibat di kedua koneksi (ke KDC dan ke Bob) sehingga semua pesan terlihat. Pilih interface WiFi yang dipakai, bukan loopback.
2. Filter tampilan:

   ```
   tcp.port == 5000 || tcp.port == 6000
   ```

3. Klik kanan sebuah paket, lalu **Follow → TCP Stream** untuk melihat isinya.

Yang akan terlihat:

| Pesan | Isi `payload` di jaringan |
| --- | --- |
| Langkah 1 (`KEY_REQUEST`) | Plaintext: `alice\|bob\|<N1>` (sesuai skema, langkah 1 memang tidak dienkripsi) |
| Langkah 2 sampai 5 | Hanya hex |
| Semua pesan `CHAT` | Hanya hex, plaintext chat tidak terlihat |

Field `type`, `from`, dan `to` di envelope tetap terbaca, karena hanya `payload` yang dienkripsi. Ini mirip header yang dibiarkan terbuka agar jaringan bisa meneruskan pesan (slide "Placement of Encryption").

Kalau mengetes di satu komputer (`127.0.0.1`), pilih interface **Loopback** di Wireshark. Di Linux namanya `lo`.

# Kriptografi & Sesi Chat

Bagian ini mencakup AES-128 yang ditulis manual, pembungkus AES-CBC, pembaca input terminal, dan sesi chat terenkripsi antara Alice dan Bob. Modul ini dipakai setelah kedua pihak mendapat _session key_ dari handshake pada bagian [KDC dan jaringan](#kdc-dan-jaringan).

## Fitur

- **AES-128 manual**: S-Box dan inverse S-Box, key expansion, SubBytes, ShiftRows, MixColumns, AddRoundKey, dan semua inversnya.
- **Enkripsi satu blok**: `encrypt_block()` dan `decrypt_block()` untuk blok tepat 16 byte.
- **AES-CBC**: pesan dengan panjang bebas, memakai IV acak 16 byte dan PKCS#7 padding.
- **Validasi ASCII**: plaintext dan key harus ASCII, dan key AES-128 harus tepat 16 karakter.
- **Output hex**: hasil `cipher.encrypt()` berupa hex huruf kecil dengan format `IV || ciphertext`.
- **Chat dua arah**: thread penerima, input terminal, enkripsi sebelum kirim, dan dekripsi setelah terima.
- **Command chat**: `/help`, `/hex`, `/quit`, serta alur `/rekey` lewat callback dari `peer.py`.

## File modul

```
kdc_chat/
├── aes.py        AES-128 manual
├── cipher.py     AES-CBC, PKCS#7, ASCII, hex
├── console.py    input terminal (thread + queue)
└── chat.py       sesi chat terenkripsi dan kontrol rekey
tests/
├── test_aes.py     test AES-128 dan test vector standar
├── test_cipher.py  test round-trip, IV, validasi input
└── test_chat.py    test sesi chat dengan FakeChannel
```

## Cara kerja

### AES-128 manual (`aes.py`)

1. Plaintext satu blok (16 byte) dan key 16 byte menjadi input.
2. **Key expansion** menghasilkan 11 _round key_.
3. **Initial AddRoundKey**: XOR blok dengan round key pertama.
4. **Round 1–9**: SubBytes → ShiftRows → MixColumns → AddRoundKey.
5. **Round 10**: SubBytes → ShiftRows → AddRoundKey, tanpa MixColumns.
6. Dekripsi memakai transformasi invers dalam urutan yang sesuai.

S-Box tidak ditulis sebagai tabel, tetapi dihitung dari invers perkalian di GF(2⁸) yang dilanjutkan transformasi affine. Perkalian di GF(2⁸) (`_gf_mul`) juga dipakai oleh MixColumns.

### AES-CBC untuk pesan (`cipher.py`)

1. Validasi plaintext dan key sebagai ASCII.
2. Tambahkan PKCS#7 padding sampai panjang data kelipatan 16 byte.
3. Bangkitkan IV acak 16 byte dengan `secrets`.
4. XOR tiap blok plaintext dengan IV (blok pertama) atau ciphertext blok sebelumnya, lalu enkripsi dengan AES manual.
5. Kembalikan `hex(IV || ciphertext)`.
6. Saat dekripsi: pisahkan IV, jalankan CBC terbalik, validasi padding, lalu ubah ke ASCII. Key atau ciphertext yang salah menghasilkan `ValueError`, bukan teks acak.

Karena IV acak, pesan dan key yang sama menghasilkan ciphertext berbeda setiap kali. Contoh pemakaian:

```python
from kdc_chat.cipher import encrypt, decrypt

key = "1234567890ABCDEF"  # 16 karakter ASCII
cipher_hex = encrypt("Halo Bob!", key)
print("Ciphertext (Hex):", cipher_hex)
print("Hasil dekripsi:", decrypt(cipher_hex, key))
```

### Sesi chat (`chat.py`)

`ChatSession` memakai dua thread:

```
thread utama                                thread penerima
console.poll() ─► command atau teks         channel.recv()
   teks ─► cipher.encrypt(Ks) ─► CHAT ─►        │
                                       ◄─ CHAT ─┴─► cipher.decrypt(Ks) ─► tampil
```

- Pesan keluar dienkripsi dengan `cipher.encrypt()` memakai Ks, dan pesan masuk didekripsi dengan `cipher.decrypt()`.
- Thread penerima memeriksa bahwa pengirim dan penerima di envelope sesuai. Pesan yang gagal didekripsi hanya menampilkan peringatan, sesi tidak berhenti.
- Output memakai lock supaya tulisan dua thread tidak bercampur.
- Dengan aturan satu pembaca, `recv()` hanya dipanggil oleh thread penerima selama sesi chat berlangsung.

**Alur `/rekey`.** Initiator mengetik `/rekey`, lalu `peer.py` (lewat `on_command`) mengembalikan `"rekey"`. `ChatSession` mengirim `REKEY` dan menunggu `REKEY_ACK`. Di sisi responder, thread penerima membalas `REKEY_ACK`. Setelah itu `run()` di kedua sisi mengembalikan `"rekey"`, thread penerima berhenti, dan `peer.py` menjalankan handshake langkah 1–5 lagi di koneksi yang sama.

Peran ditentukan oleh parameter `initiator` pada `ChatSession`, yang diisi `peer.py` dari argumen `--connect`. Hanya initiator yang boleh meminta `REKEY`, dan hanya responder yang menerimanya. Kalau `initiator` tidak diisi, `ChatSession` memakai aturan lama: `alice` initiator.

### Command sesi chat

| Command | Fungsi |
| --- | --- |
| `/help` | Menampilkan bantuan |
| `/hex` | Menampilkan atau menyembunyikan ciphertext hex |
| `/quit` | Menutup sesi dan mengirim `BYE` |
| `/rekey` | Initiator meminta session key baru (diproses bersama `peer.py` dan KDC) |
| `/setkey <key>` | Ganti master key sendiri. Diteruskan ke `peer.py`, berlaku di handshake berikutnya |

Antarmuka `ChatSession`:

```python
ChatSession(channel, session_key, me, peer, on_command=None).run()
```

Nilai kembalian `run()` adalah `"quit"`, `"rekey"`, atau `"closed"`.

## Pengujian

```bash
python3 -m unittest discover tests -v
```

| Berkas | Jumlah test | Yang diuji |
| --- | --- | --- |
| `test_aes.py` | 7 | AES-128 satu blok, test vector standar, round-trip |
| `test_cipher.py` | 12 | AES-CBC, IV acak, padding, validasi key dan ASCII |
| `test_chat.py` | 4 | kirim, terima, `/quit`, dan alur rekey dengan `FakeChannel` |

Test vector AES-128 (FIPS-197 Appendix C.1):

```
Key       : 000102030405060708090a0b0c0d0e0f
Plaintext : 00112233445566778899aabbccddeeff
Ciphertext: 69c4e0d86a7b0430d8cdb78070b4c55a
```

Nilai ini memverifikasi AES-128 satu blok, bukan hasil AES-CBC dengan IV acak.

`test_chat.py` memakai `FakeChannel`, jadi bukan bukti komunikasi lewat jaringan. Komunikasi sungguhan diuji di Phase 5 pada bagian KDC dan jaringan.

## Catatan keamanan

- Master key harus dikelola lewat protokol KDC. Jangan menaruh master key asli di source code atau commit Git.
- CBC dengan IV acak memberi kerahasiaan pesan, tetapi **tidak memberi autentikasi atau integritas ciphertext**. Validasi padding dan ASCII bukan pengganti MAC atau mode AEAD.

# KDC dan jaringan

Bagian ini mencakup lapisan transport yang dipakai KDC, Alice, dan Bob untuk berkomunikasi, server KDC, handshake Alice–Bob, serta program dan command interaktifnya.

## Phase 1 — Transport (`kdc_chat/net.py`)

TCP adalah stream byte tanpa batas pesan, jadi satu pesan bisa sampai terpotong atau tergabung dengan pesan lain. `net.py` menyelesaikan ini dengan **length-prefix framing**:

```
┌────────────────────┬───────────────────────────────┐
│ 4 byte panjang     │ JSON UTF-8                    │
│ (big-endian)       │ {"type","from","to","payload"}│
└────────────────────┴───────────────────────────────┘
```

Penerima membaca 4 byte header untuk tahu panjang pesan, lalu membaca tepat sebanyak itu.

| Komponen                        | Fungsi                                                                                                                  |
| ------------------------------- | ----------------------------------------------------------------------------------------------------------------------- |
| `recv_exact(sock, n)`           | Membaca tepat _n_ byte, mengulang `recv()` sampai terkumpul                                                             |
| `send_frame` / `recv_frame`     | Mengirim dan menerima satu pesan. Pesan di atas 1 MB atau envelope tidak valid ditolak dengan `ValueError`              |
| `Channel`                       | Pembungkus satu koneksi. `send()` aman dipanggil dari banyak thread, `recv()` mengembalikan `None` bila koneksi ditutup |
| `connect` / `listen` / `accept` | Membuka koneksi TCP                                                                                                     |

Aturan penting: pada satu waktu **hanya satu thread yang memanggil `recv()`** pada sebuah `Channel`, karena dua pembaca pada socket yang sama bisa membuat byte frame tercampur.

### Pengujian

Alice (kanan) mengirim `TICKET` ke Bob (kiri), lalu Bob membalas dengan `CHALLENGE`. Keduanya menerima envelope JSON yang utuh.

![Uji transport: Alice dan Bob saling mengirim pesan](img/transport.png)

Cara mengulang pengujian ini, jalankan di dua terminal dari root repo.

Terminal 1 (Bob):

```bash
python3 -c "from kdc_chat import net; s=net.listen('0.0.0.0',6000); ch,a=net.accept(s,'bob'); print('dari',a,ch.recv()); ch.send('CHALLENGE','alice','halo balik'); ch.close()"
```

Terminal 2 (Alice):

```bash
python3 -c "from kdc_chat import net; ch=net.connect('127.0.0.1',6000,'alice'); ch.send('TICKET','bob','halo'); print(ch.recv()); ch.close()"
```

## Phase 2 — KDC server (`kdc.py`, `kdc_chat/protocol.py`)

KDC menyimpan master key setiap pengguna (`Ka` untuk Alice, `Kb` untuk Bob) dan melayani langkah 1–2 dari skenario key distribution.

```
(1) Alice → KDC : KEY_REQUEST   alice|bob|N1                         (plaintext)
(2) KDC → Alice : KEY_RESPONSE  E(Ka,[Ks|alice|bob|N1]) | E(Kb,[Ks|alice])
```

Alur `kdc_handle` untuk setiap koneksi:

1. Terima `KEY_REQUEST`, lalu pecah payload menjadi `IDa|IDb|N1`.
2. Validasi: formatnya tepat tiga bagian, `IDa` sama dengan pengirim, `IDa` berbeda dari `IDb`, keduanya terdaftar, dan `N1` berupa angka.
3. Bangkitkan session key `Ks`: 16 karakter alfanumerik acak dari `secrets` (CSPRNG), sehingga tidak bisa ditebak dari Ks sebelumnya.
4. Buat dua ciphertext **terpisah**, sesuai slide kelas:
   - `part1 = E(Ka, Ks|IDa|IDb|N1)`, hanya bisa dibuka Alice.
   - `ticket = E(Kb, Ks|IDa)`, hanya bisa dibuka Bob. Alice meneruskannya ke Bob pada langkah 3.
5. Kirim `part1|ticket` sebagai `KEY_RESPONSE`, lalu tutup koneksi.

Kalau validasi gagal, KDC mengirim `ERROR` beserta alasannya, mencatatnya di log, dan menutup koneksi itu tanpa menghentikan server. Setiap koneksi dilayani di thread sendiri, jadi satu client yang lambat tidak menahan client lain.

| Komponen                            | Fungsi                                                                    |
| ----------------------------------- | ------------------------------------------------------------------------- |
| `kdc_handle(ch, keys)`              | Melayani satu request langkah 1 → langkah 2                               |
| `new_session_key()` / `new_nonce()` | Membangkitkan Ks dan nonce dengan `secrets`                               |
| `check_key(key)`                    | Memastikan key tepat 16 karakter ASCII yang bisa dicetak                  |
| `HandshakeError`                    | Error verifikasi protokol, dikirim ke lawan sebagai `ERROR`               |
| `kdc.py`                            | Argumen CLI, input master key, loop accept dengan satu thread per koneksi |

> Phase 1–4 dikerjakan dengan `cipher_stub.py`, pengganti AES sementara yang **bukan enkripsi** (hex-nya memuat key dan plaintext). Stub sudah dihapus di Phase 5 dan diganti `cipher.py` (AES-CBC asli). Screenshot Phase 2 di bawah diambil saat stub masih dipakai, sehingga hex-nya bisa dibaca langsung.

### Menjalankan KDC

```bash
python3 kdc.py --listen 0.0.0.0:5000
```

| Argumen     | Default        | Keterangan                              |
| ----------- | -------------- | --------------------------------------- |
| `--listen`  | `0.0.0.0:5000` | Alamat dan port KDC                     |
| `--users`   | `alice,bob`    | ID yang terdaftar, dipisah koma         |
| `--verbose` | mati           | Tampilkan Ks di log, berguna untuk demo |

Saat start, KDC meminta master key untuk setiap ID. Key yang panjangnya bukan 16 karakter ditolak dan diminta ulang.

### Pengujian

Pengujian memakai dua terminal. Terminal kiri menjalankan KDC, terminal kanan berperan sebagai Alice yang mengirim request.

![Uji KDC: request normal, request ditolak, dan isi hex yang dibuka dengan key masing-masing](img/stub_kdc.png)

**Persiapan.** Terminal 1 menjalankan KDC dan meminta master key setiap ID (tepat 16 karakter):

```bash
python3 kdc.py --listen 127.0.0.1:5000 --verbose
```

Pada pengujian ini master key Alice `kunciAlice123456` dan master key Bob `kunciBob12345678`.

**1. Request normal.** Terminal 2 mengirim langkah 1 sebagai Alice:

```bash
python3 -c "from kdc_chat import net; ch=net.connect('127.0.0.1',5000,'alice'); ch.send('KEY_REQUEST','kdc','alice|bob|481920331'); print(ch.recv())"
```

KDC menjawab `KEY_RESPONSE` yang payload-nya berisi dua hex dipisah `|` (kiri `part1`, kanan `ticket`). Di log KDC muncul `[STEP 1]`, session key baru (karena `--verbose`), lalu `[STEP 2]`.

**2. Request ditolak.** Tiga request yang salah, masing-masing dijawab `ERROR` dan KDC tetap berjalan:

| Request                            | Respons `ERROR`                                |
| ---------------------------------- | ---------------------------------------------- |
| `alice\|carol\|1`                  | `ID 'carol' tidak terdaftar di KDC`            |
| `alice\|bob\|1` dikirim oleh `bob` | `IDa (alice) tidak sama dengan pengirim (bob)` |
| `alice\|bob` (tanpa N1)            | `format langkah 1 harus IDa\|IDb\|N1`          |

Contohnya untuk ID yang tidak terdaftar:

```bash
python3 -c "from kdc_chat import net; ch=net.connect('127.0.0.1',5000,'alice'); ch.send('KEY_REQUEST','kdc','alice|carol|1'); print(ch.recv())"
```

Setelah ketiga request itu, request normal tetap dilayani. Artinya error satu client tidak menghentikan KDC.

**3. Isi hex dibuka dengan key masing-masing.** Hex dari KDC bisa dibuka dengan key yang tepat untuk membuktikan isinya benar:

```bash
python3 -c "
from kdc_chat import net, cipher as c
ch=net.connect('127.0.0.1',5000,'alice'); ch.send('KEY_REQUEST','kdc','alice|bob|481920331')
part1, ticket = ch.recv()['payload'].split('|')
print('part1 (Ka):', c.decrypt(part1,'kunciAlice123456'))
print('ticket(Kb):', c.decrypt(ticket,'kunciBob12345678'))"
```

```
part1 (Ka): haI2BCfgNJbhCUao|alice|bob|481920331
ticket(Kb): haI2BCfgNJbhCUao|alice
```

Hasil ini sesuai dengan slide 13:

- `part1` dibuka dengan Ka dan berisi `Ks|IDa|IDb|N1`. N1 sama dengan yang dikirim Alice (`481920331`), jadi Alice bisa memastikan jawaban ini bukan replay.
- `ticket` dibuka dengan Kb dan berisi `Ks|IDa`.
- Ks di kedua bagian **sama** (`haI2BCfgNJbhCUao`). KDC memberi session key yang sama ke Alice dan Bob lewat dua jalur terpisah.
- Pada screenshot, Ks tiap request berbeda (`AuKYiMHJBisJRfVY`, `dUtUhyzedbH12ILM`, `haI2BCfgNJbhCUao`), jadi session key dibuat baru setiap kali.

## Phase 3 — Handshake langkah 1–5 (`kdc_chat/protocol.py`)

Phase ini melengkapi sisi Alice dan Bob, sehingga kelima langkah berjalan dari awal sampai akhir.

```
(1) Alice → KDC   KEY_REQUEST         alice|bob|N1
(2) KDC   → Alice KEY_RESPONSE        E(Ka,[Ks|alice|bob|N1]) | E(Kb,[Ks|alice])
(3) Alice → Bob   TICKET              E(Kb,[Ks|alice])
(4) Bob   → Alice CHALLENGE           E(Ks, N2)
(5) Alice → Bob   CHALLENGE_RESPONSE  E(Ks, f(N2))        f(N2) = N2 + 1
    Bob   → Alice HANDSHAKE_OK        (konfirmasi, di luar 5 langkah)
```

**`alice_handshake(kdc_addr, bob_ch, me, peer, ka)`** mengembalikan Ks:

1. Membuka koneksi ke KDC, mengirim langkah 1 dengan nonce N1 baru, menerima langkah 2, lalu menutup koneksi KDC.
2. Memecah payload menjadi `part1|ticket` dan membuka `part1` dengan Ka.
3. Memeriksa bahwa IDa dan IDb sesuai permintaan dan **N1 sama dengan yang dikirim**. Ini membuktikan jawaban KDC memang untuk request ini, bukan replay jawaban lama.
4. Meneruskan `ticket` ke Bob apa adanya (langkah 3). Alice tidak bisa membukanya karena dienkripsi Kb.
5. Membuka N2 dari Bob dengan Ks, lalu membalas `E(Ks, N2 + 1)` (langkah 5).

**`bob_handshake(alice_ch, me, kb)`** mengembalikan `(Ks, ID Alice)`:

1. Membuka tiket dengan Kb dan memeriksa bahwa IDa di dalam tiket sama dengan pengirimnya.
2. Membuat nonce N2 baru, mengirim `E(Ks, N2)` (langkah 4).
3. Memeriksa jawaban Alice sama dengan `f(N2)`. Hanya pihak yang memegang Ks yang bisa menjawab dengan benar, jadi tiket lama yang diputar ulang oleh penyerang akan gagal di sini.
4. Mengirim `HANDSHAKE_OK`.

Setelah langkah 5, Alice dan Bob memegang Ks yang sama tanpa Ks pernah dikirim dalam bentuk plaintext.

**Penanganan error.** Setiap kegagalan verifikasi menghasilkan `HandshakeError`. Pihak yang mendeteksi kesalahan mengirim `ERROR` beserta alasannya ke lawan, sehingga kedua sisi tahu kenapa handshake gagal. Pihak yang _menerima_ `ERROR` tidak membalas dengan `ERROR` lagi. Program tidak crash, dan penutupan koneksi Alice–Bob diserahkan ke pemanggil (`peer.py`, Phase 4).

| Kegagalan                            | Terdeteksi di            | Pesan                                                 |
| ------------------------------------ | ------------------------ | ----------------------------------------------------- |
| KDC tidak bisa dihubungi             | Alice, sebelum langkah 1 | `tidak bisa terhubung ke KDC ...`                     |
| ID tidak terdaftar                   | KDC, langkah 1           | `kdc menolak: ID '...' tidak terdaftar di KDC`        |
| Master key initiator salah           | Initiator, langkah 2     | `E(Ka,...) dengan master key <nama> gagal dibuka`     |
| N1 tidak cocok                       | Alice, langkah 2         | `N1 tidak cocok`                                      |
| Format langkah 2 bukan dua bagian    | Alice, langkah 2         | `format langkah 2 harus E(Ka,...)\|E(Kb,...)`         |
| Master key responder beda dengan KDC | Responder, langkah 3     | `tiket E(Kb,...) dengan master key <nama> gagal dibuka` |
| IDa di tiket bukan pengirim          | Bob, langkah 3           | `IDa di tiket (...) tidak sama dengan pengirim (...)` |
| Jawaban challenge salah              | Bob, langkah 5           | `f(N2) salah`                                         |

### Unit test

```bash
python3 -m unittest discover tests -v
```

![Protocol Test](img/test_protocol.png)

`tests/test_protocol.py` menjalankan KDC dan Bob sebagai thread di localhost, lalu menguji Alice terhadap keduanya. Untuk kasus yang tidak bisa dibuat oleh KDC asli (N1 salah, format langkah 2 salah), test memakai KDC palsu. Untuk kasus f(N2) salah dan tiket milik orang lain, test memakai Alice palsu. Ada 9 test: handshake normal, dan 8 kasus gagal dari tabel di atas.

### Pengujian manual (tiga terminal)

Pengujian ini dibuat sebelum `peer.py` ada (Phase 4), jadi Alice dan Bob dijalankan dengan `python3 -c` untuk memanggil fungsi handshake secara langsung. Master key sama dengan pengujian Phase 2.

Terminal 1 (KDC):

```bash
python3 kdc.py --listen 127.0.0.1:5000 --verbose
```

Terminal 2 (Bob):

```bash
python3 -c "from kdc_chat import net, protocol as p; p.VERBOSE=True; s=net.listen('127.0.0.1',6000); ch,_=net.accept(s,'bob'); print(p.bob_handshake(ch,'bob','kunciBob12345678'))"
```

Terminal 3 (Alice):

```bash
python3 -c "from kdc_chat import net, protocol as p; p.VERBOSE=True; ch=net.connect('127.0.0.1',6000,'alice'); print(p.alice_handshake(('127.0.0.1',5000),ch,'alice','bob','kunciAlice123456'))"
```

![Protocol Test Manual](img/handshake.png)

Contoh log di sisi Alice:

```
[STEP 1] alice -> kdc   KEY_REQUEST        alice|bob|816217
[STEP 2] kdc   -> alice KEY_RESPONSE       6b756e6369416c6963653132333435367c334d6a32587a32...(179 char)
[STEP 2] alice: N1 cocok ✓  Ks diterima: 3Mj2Xz2jNSGWDqu9
[STEP 3] alice -> bob   TICKET             6b756e6369426f6231323334353637387c334d6a32587a32...(78 char)
[STEP 4] bob   -> alice CHALLENGE          334d6a32587a326a4e534757447175397c33333336333030...(52 char)
[STEP 4] alice: N2 = 333630015
[STEP 5] alice -> bob   CHALLENGE_RESPONSE 334d6a32587a326a4e534757447175397c33333336333030...(52 char)
[STEP 5] bob   -> alice HANDSHAKE_OK
[OK] handshake alice <-> bob selesai, Ks = 3Mj2Xz2jNSGWDqu9
```

Ks yang dicetak KDC, Alice, dan Bob harus sama. Untuk mencoba kasus gagal, jalankan Bob dengan master key lain, misalnya `kunciBobSALAH123`. Handshake akan berhenti di langkah 3 dengan pesan `tiket E(Kb,...) dengan master key bob gagal dibuka` (atau `PKCS#7 padding tidak valid` pada AES asli).

## Phase 4 — Program Alice/Bob dan command interaktif (`peer.py`, `kdc.py`)

Phase ini membuat program yang bisa dipakai langsung, tanpa `python3 -c`. Master key bisa diganti saat program berjalan, dan session key bisa diperbarui tanpa restart.

### Peran initiator dan responder

`peer.py` dipakai untuk Alice maupun Bob, dan `--name` hanya boleh `alice` atau `bob`. Peran **tidak** ditentukan oleh nama, melainkan oleh `--connect`: peer yang memakai `--connect` menjadi initiator, dan peer tanpa `--connect` menjadi responder. Jadi Alice maupun Bob bisa menjadi initiator.

| Peran             | Argumen                 | Tugas                                                                 |
| ----------------- | ----------------------- | --------------------------------------------------------------------- |
| Initiator         | `--connect` dan `--kdc` | Menghubungi responder, meminta Ks ke KDC, menjalankan langkah 1–5     |
| Responder (Bob)   | tanpa `--connect`       | Menunggu koneksi di `--listen`, menjalankan sisi Bob dari langkah 3–5 |

```bash
python3 peer.py --name bob   --listen 0.0.0.0:6000
python3 peer.py --name alice --kdc <IP_KDC>:5000 --connect <IP_BOB>:6000
```

| Argumen     | Default        | Keterangan                                                     |
| ----------- | -------------- | -------------------------------------------------------------- |
| `--name`    | (wajib)        | `alice` atau `bob`                                             |
| `--connect` | –              | `host:port` Bob, wajib untuk Alice dan dilarang untuk Bob      |
| `--kdc`     | –              | `host:port` KDC, wajib untuk Alice                             |
| `--listen`  | `0.0.0.0:6000` | Alamat responder menunggu koneksi                              |
| `--verbose` | mati           | Tampilkan Ks dan nonce di log                                  |

Saat start, peer meminta master key-nya sendiri (tepat 16 karakter), lalu menampilkan menu.

### Alur program

```
menu ──/start──► handshake 1–5 ──► sesi chat ──/rekey──► handshake 1–5 lagi ──► sesi chat ...
  ▲                   │                 │
  │             gagal │           /quit │ atau lawan menutup koneksi
  └───────────────────┴─────────────────┘
```

- Handshake yang gagal tidak menghentikan program. Pesan error ditampilkan, koneksi Alice–Bob ditutup, dan kedua peer kembali ke menu.
- `/rekey` memakai koneksi yang sama. Initiator mengirim `REKEY`, responder membalas `REKEY_ACK`, lalu keduanya menjalankan langkah 1–5 lagi dan mendapat Ks baru dari KDC. Sesuai slide 14, umur session key sebaiknya dibatasi, dan `/rekey` adalah cara menggantinya tanpa memutus koneksi.

### Command

| Program                   | Command              | Fungsi                                                            |
| ------------------------- | -------------------- | ----------------------------------------------------------------- |
| KDC                       | `/setkey <id> <key>` | Ganti master key `<id>`, atau daftarkan ID baru                   |
| KDC                       | `/list`              | Tampilkan ID dan master key yang terdaftar                        |
| KDC                       | `/quit`              | Hentikan KDC                                                      |
| Alice/Bob (menu)          | `/start`             | Alice: hubungi Bob dan mulai handshake. Bob: tunggu koneksi Alice |
| Alice/Bob (menu dan sesi) | `/setkey <key>`      | Ganti master key sendiri, berlaku di handshake berikutnya         |
| Initiator (sesi)          | `/rekey`             | Minta session key baru ke KDC                                     |
| Alice/Bob                 | `/quit`              | Keluar dari sesi atau program                                     |

Master key bersifat _pre-shared_: KDC dan pemilik key harus mengganti key yang sama. Kalau hanya salah satu yang mengganti, handshake berikutnya gagal. Ini sengaja dipakai sebagai test case.

Agar KDC bisa menerima command sambil tetap melayani request, loop `accept` dijalankan di thread latar belakang, dan thread utama membaca command. `kdc_handle` membaca master key dari dict yang sama, jadi `/setkey` langsung berlaku untuk request berikutnya.

> Pada Phase 4, sesi chat masih berupa `dummy_chat` yang hanya menangani pesan kontrol (`REKEY`, `REKEY_ACK`, `BYE`). Di Phase 5 diganti dengan `ChatSession` dari `chat.py`.

### Pengujian

Jalankan tiga terminal. Master key sama dengan pengujian sebelumnya.

```bash
python3 kdc.py --listen 127.0.0.1:5000
```

```bash
python3 peer.py --name bob --listen 127.0.0.1:6000
```

```bash
python3 peer.py --name alice --kdc 127.0.0.1:5000 --connect 127.0.0.1:6000
```

Skenario yang diuji, berurutan:

| #   | Langkah                                                         | Hasil yang diharapkan                                                                              |
| --- | --------------------------------------------------------------- | -------------------------------------------------------------------------------------------------- |
| 1   | Bob `/start`, lalu Alice `/start`                               | Handshake 1–5 berhasil, keduanya masuk sesi                                                        |
| 2   | Alice `/rekey`                                                  | Handshake diulang di koneksi yang sama, Ks baru dari KDC                                           |
| 3   | Alice `/quit`                                                   | Sesi Alice selesai (`quit`), Bob melihat sesi selesai (`closed`), keduanya kembali ke menu         |
| 4   | Bob `/setkey kunciBobBARU5678`, lalu `/start` di kedua peer     | Gagal di langkah 3: `tiket E(Kb,...) dengan master key Bob gagal dibuka`. Keduanya kembali ke menu |
| 5   | KDC `/setkey bob kunciBobBARU5678`, lalu `/start` di kedua peer | Berhasil lagi **tanpa restart**                                                                    |
| 6   | Alice `/setkey kunciAliceBARU56` di dalam sesi, lalu `/rekey`   | Gagal di langkah 2: `E(Ka,...) dengan master key Alice gagal dibuka`, karena KDC belum diganti     |
| 7   | `/setkey pendek`                                                | Ditolak: `key harus tepat 16 karakter`                                                             |

![Step 1 2 3](img/step1_2_3.png)

![Step 4 5 6](img/step4_5_6.png)

## Phase 5 — Integrasi AES dan chat

Phase ini menyatukan bagian KDC dan jaringan dengan AES dan chat dari anggota A.

| Perubahan | Keterangan |
| --- | --- |
| `protocol.py` dan `tests/test_protocol.py` memakai `cipher` | Enkripsi langkah 2–5 sekarang AES-128 CBC asli |
| `cipher_stub.py` dihapus | `grep -r cipher_stub` kosong |
| `peer.py` memakai `console.ask` dan `ChatSession` | `dummy_chat` dihapus. Alice dan Bob bisa saling mengirim pesan terenkripsi |
| `--name` dibatasi `alice` dan `bob` | Hanya dua ID yang terdaftar di KDC. Peran initiator ditentukan oleh `--connect`, bukan oleh nama |

Setelah langkah 5, setiap pesan chat dikirim sebagai `CHAT` dengan payload `E(Ks, teks)` berformat hex. Command `/hex` di sesi chat menampilkan ciphertext tersebut.

### Pengujian

Tiga terminal seperti Phase 4, sekarang dengan AES asli dan chat sungguhan:

| # | Langkah | Hasil |
| --- | --- | --- |
| 1 | Bob `/start`, Alice `/start`, lalu Alice `/hex` dan mengetik pesan | Handshake berhasil, pesan terkirim sebagai hex dan tampil di sisi Bob |
| 2 | Bob membalas | Pesan Bob tampil di Alice (chat dua arah) |
| 3 | Responder `/rekey` | Ditolak: `hanya initiator (yang menghubungi KDC) yang bisa /rekey` |
| 4 | Alice `/rekey` | Handshake diulang dengan Ks baru, chat lanjut di koneksi yang sama |
| 5 | Alice `/quit` | Bob melihat `alice mengakhiri sesi`, keduanya kembali ke menu |
| 6 | Bob `/setkey` saja, lalu `/start` | Gagal di langkah 3: `PKCS#7 padding tidak valid` (key Bob tidak cocok dengan KDC) |
| 7 | KDC `/setkey bob ...` dengan key yang sama, lalu `/start` | Berhasil lagi tanpa restart |

Pada AES asli, tiket yang dibuka dengan key salah hampir selalu gagal di pemeriksaan padding PKCS#7, bukan pesan `key salah` seperti pada stub.

Contoh keluaran `/hex` di sisi Alice. Ciphertext selalu berbeda karena IV acak, dan panjangnya 48 byte (16 byte IV + 2 blok):

```
[HEX terkirim] b1e7f2eb27da9806d291be49a9691723b4926a2dab61471ccef6fefb2221b9ea75ed4e8c0bb51f2985209089146306f9
[alice] halo bob, ini Alice
[HEX dari bob] b05c72ec5d17a43a2f39bd89b5af8a4035d5099f96b4194c36a35a0c6b090507d9707b8d4984f153fe548e7b43338920
[bob] halo alice, ini Bob
```

# Pembagian kontribusi

- **Modul A**: AES, cipher (CBC), console, dan sesi chat (`aes.py`, `cipher.py`, `console.py`, `chat.py`, beserta test-nya).
- **Modul B**: jaringan, KDC, protokol handshake, dan program peer (`net.py`, `protocol.py`, `kdc.py`, `peer.py`, `tests/test_protocol.py`).

Kesepakatan API dan format pesan antar modul ada di `CONTRACT.md`.
