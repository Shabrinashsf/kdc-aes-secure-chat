
import queue
import sys
import threading

# Tempat menyimpan input dari keyboard
_input_queue: queue.Queue[str | None] = queue.Queue()

_started = False
_start_lock = threading.Lock()


def _read_input():
    """Membaca keyboard terus-menerus di thread terpisah."""
    while True:
        line = sys.stdin.readline()

        if line == "":
            _input_queue.put(None)
            break

        _input_queue.put(line.rstrip("\r\n"))


def start() -> None:
    """Memulai thread pembaca keyboard hanya satu kali."""
    global _started

    with _start_lock:
        if _started:
            return

        reader = threading.Thread(
            target=_read_input,
            daemon=True,
            name="console-reader"
        )

        reader.start()
        _started = True


def ask(prompt: str = "") -> str:
    """Menunggu input pengguna dan mengembalikannya."""
    start()

    if prompt:
        print(prompt, end="", flush=True)

    line = _input_queue.get()

    if line is None:
        _input_queue.put(None)
        raise EOFError("Input keyboard ditutup.")

    return line


def poll(timeout: float) -> str | None:
    """Mengambil input jika tersedia dalam batas waktu."""
    if timeout < 0:
        raise ValueError("Timeout tidak boleh negatif.")

    start()

    try:
        line = _input_queue.get(timeout=timeout)
    except queue.Empty:
        return None

    if line is None:
        _input_queue.put(None)
        return None

    return line
