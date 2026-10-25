
import queue
import threading
from collections.abc import Callable
from typing import TYPE_CHECKING

from kdc_chat import cipher, console

if TYPE_CHECKING:
    from kdc_chat.net import Channel


class ChatSession:
    def __init__(
        self,
        channel: "Channel",
        session_key: str,
        me: str,
        peer: str,
        on_command: Callable[[str], str | None] | None = None,
    ):
        self.channel = channel
        self.session_key = session_key
        self.me = me
        self.peer = peer
        self.on_command = on_command

        self._show_hex = False
        self._events: queue.Queue[str] = queue.Queue()
        self._awaiting_rekey_ack = threading.Event()
        self._print_lock = threading.Lock()


    # 1. OUTPUT TERMINAL

    def _say(self, message: str) -> None:
        """Menampilkan pesan dengan lock agar output tidak bentrok."""
        with self._print_lock:
            print(message, flush=True)


    # 2. RECEIVE THREAD

    def _receive_loop(self) -> None:
        """Menerima pesan dari lawan selama sesi chat."""
        try:
            while True:
                message = self.channel.recv()

                if message is None:
                    self._events.put("closed")
                    return

                if not isinstance(message, dict):
                    self._say("[WARNING] Format pesan tidak valid.")
                    continue

                msg_type = message.get("type")

                if (
                    message.get("from") != self.peer
                    or message.get("to") != self.me
                ):
                    self._say(
                        "[WARNING] Identitas pengirim/penerima "
                        "tidak sesuai."
                    )
                    continue

                payload = message.get("payload")

                if not isinstance(payload, str):
                    self._say(
                        "[WARNING] Payload harus berupa string."
                    )
                    continue

                # Pesan chat terenkripsi AES
                if msg_type == "CHAT":
                    try:
                        plaintext = cipher.decrypt(
                            payload,
                            self.session_key
                        )
                    except ValueError as exc:
                        self._say(
                            f"[WARNING] Gagal decrypt pesan: {exc}"
                        )
                        continue

                    if self._show_hex:
                        self._say(
                            f"[HEX dari {self.peer}] {payload}"
                        )

                    self._say(f"[{self.peer}] {plaintext}")

                # Bob menerima permintaan rekey dari Alice
                elif msg_type == "REKEY" and self.me == "bob":
                    self.channel.send(
                        "REKEY_ACK",
                        self.peer
                    )

                    self._say(
                        "[INFO] Permintaan rekey diterima."
                    )

                    self._events.put("rekey")
                    return

                # Alice menerima persetujuan rekey
                elif (
                    msg_type == "REKEY_ACK"
                    and self._awaiting_rekey_ack.is_set()
                ):
                    self._say(
                        "[INFO] Rekey disetujui oleh Bob."
                    )

                    self._events.put("rekey")
                    return

                # Lawan mengakhiri sesi
                elif msg_type == "BYE":
                    self._say(
                        f"[INFO] {self.peer} mengakhiri sesi."
                    )

                    self._events.put("closed")
                    return

                # Pesan error dari lawan
                elif msg_type == "ERROR":
                    self._say(
                        f"[ERROR dari {self.peer}] {payload}"
                    )

                    self._events.put("closed")
                    return

                else:
                    self._say(
                        f"[WARNING] Tipe pesan tidak dikenal: "
                        f"{msg_type}"
                    )

        except (OSError, ValueError, TypeError) as exc:
            self._say(
                f"[ERROR] Koneksi chat bermasalah: {exc}"
            )
            self._events.put("closed")

    
    # 3. MENGIRIM PESAN TERENKRIPSI

    def _send_chat(self, plaintext: str) -> None:
        """Enkripsi pesan lalu kirim sebagai CHAT."""
        try:
            ciphertext = cipher.encrypt(
                plaintext,
                self.session_key
            )

            self.channel.send(
                "CHAT",
                self.peer,
                ciphertext
            )

        except ValueError as exc:
            self._say(
                f"[WARNING] Pesan tidak dikirim: {exc}"
            )
            return

        if self._show_hex:
            self._say(
                f"[HEX terkirim] {ciphertext}"
            )

        self._say(f"[{self.me}] {plaintext}")


    # 4. MENU BANTUAN

    def _show_help(self) -> None:
        """Menampilkan command yang tersedia."""
        self._say(
            "Perintah chat:\n"
            "  /help  - Menampilkan bantuan\n"
            "  /hex   - Menampilkan/sembunyikan Hex\n"
            "  /quit  - Mengakhiri chat\n"
            "  /rekey - Meminta session key baru (Alice)\n"
            "Perintah lain diteruskan ke menu peer."
        )


    # 5. MAIN CHAT SESSION

    def run(self) -> str:
        """Menjalankan chat sampai quit, rekey, atau closed."""

        console.start()

        # Thread khusus menerima pesan
        receiver = threading.Thread(
            target=self._receive_loop,
            daemon=True,
            name=f"chat-recv-{self.me}",
        )
        receiver.start()

        self._say(
            f"[INFO] Chat dengan {self.peer} aktif. "
            "Ketik /help untuk bantuan."
        )

        reason = "closed"

        try:
            while True:

                # Periksa apakah receiver meminta sesi berhenti
                try:
                    reason = self._events.get_nowait()
                    break
                except queue.Empty:
                    pass

                # Setelah REKEY, tunggu ACK sebelum handshake baru
                if self._awaiting_rekey_ack.is_set():
                    try:
                        reason = self._events.get(timeout=0.1)
                        break
                    except queue.Empty:
                        continue

                # Baca input keyboard tanpa blocking permanen
                line = console.poll(0.1)

                if line is None:
                    continue

                # Command help
                if line == "/help":
                    self._show_help()
                    continue

                # Command hex
                if line == "/hex":
                    self._show_hex = not self._show_hex

                    status = (
                        "ON" if self._show_hex else "OFF"
                    )
                    self._say(
                        f"[INFO] Tampilkan Hex: {status}"
                    )
                    continue

                # Command keluar
                if line == "/quit":
                    self.channel.send(
                        "BYE",
                        self.peer
                    )

                    reason = "quit"
                    break

                # Command tambahan dari peer.py
                if line.startswith("/"):
                    if self.on_command is None:
                        self._say(
                            f"[WARNING] Perintah tidak dikenal: "
                            f"{line}"
                        )
                        continue

                    result = self.on_command(line)

                    # Rekey hanya boleh dimulai Alice
                    if result == "rekey":
                        if self.me != "alice":
                            self._say(
                                "[WARNING] Hanya Alice yang "
                                "dapat meminta rekey."
                            )
                            continue

                        self._awaiting_rekey_ack.set()

                        self.channel.send(
                            "REKEY",
                            self.peer
                        )

                        self._say(
                            "[INFO] Menunggu REKEY_ACK "
                            "dari Bob..."
                        )

                    elif result == "quit":
                        self.channel.send(
                            "BYE",
                            self.peer
                        )

                        reason = "quit"
                        break

                    continue

                # Input biasa -> encrypt -> send
                self._send_chat(line)

        except (OSError, ValueError, TypeError) as exc:
            self._say(
                f"[ERROR] Sesi chat dihentikan: {exc}"
            )
            reason = "closed"

        finally:
            if reason == "rekey":
                # Pastikan receiver selesai sebelum handshake baru
                receiver.join()
            else:
                try:
                    self.channel.close()
                except OSError:
                    pass

        return reason
