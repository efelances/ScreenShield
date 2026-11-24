"""Win32 global hotkey registration using RegisterHotKey (no keyboard hooks)."""

from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes
from typing import Callable


MOD_ALT = 0x0001
MOD_CONTROL = 0x0002
MOD_SHIFT = 0x0004
MOD_WIN = 0x0008
MOD_NOREPEAT = 0x4000

WM_HOTKEY = 0x0312
WM_QUIT = 0x0012
WM_APP_REBIND = 0x8001

_MODIFIER_MAP = {
    "ALT": MOD_ALT,
    "CTRL": MOD_CONTROL,
    "CONTROL": MOD_CONTROL,
    "SHIFT": MOD_SHIFT,
    "WIN": MOD_WIN,
    "SUPER": MOD_WIN,
}

_SPECIAL_KEYS = {
    "SPACE": 0x20,
    "ESC": 0x1B,
    "ESCAPE": 0x1B,
    "TAB": 0x09,
    "ENTER": 0x0D,
    "RETURN": 0x0D,
    "BACKSPACE": 0x08,
    "DELETE": 0x2E,
    "DEL": 0x2E,
    "HOME": 0x24,
    "END": 0x23,
    "PAGEUP": 0x21,
    "PAGEDOWN": 0x22,
    "UP": 0x26,
    "DOWN": 0x28,
    "LEFT": 0x25,
    "RIGHT": 0x27,
    "PAUSE": 0x13,
}


def parse_hotkey(combo: str) -> tuple[int, int]:
    """Parse a human-readable hotkey string like 'Ctrl+Alt+H' into (modifiers, vk)."""
    if not combo or not combo.strip():
        raise ValueError("Hotkey string cannot be empty")
    parts = [p.strip().upper() for p in combo.split("+") if p.strip()]
    if not parts:
        raise ValueError(f"Invalid hotkey: {combo!r}")

    modifiers = 0
    key_token: str | None = None
    for part in parts:
        if part in _MODIFIER_MAP:
            modifiers |= _MODIFIER_MAP[part]
        else:
            if key_token is not None:
                raise ValueError(f"Multiple non-modifier keys in hotkey: {combo!r}")
            key_token = part

    if key_token is None:
        raise ValueError(f"Missing trigger key in hotkey: {combo!r}")

    if len(key_token) == 1 and ("A" <= key_token <= "Z" or "0" <= key_token <= "9"):
        vk = ord(key_token)
    elif key_token.startswith("F") and key_token[1:].isdigit():
        fnum = int(key_token[1:])
        if not (1 <= fnum <= 24):
            raise ValueError(f"Unsupported function key: {key_token}")
        vk = 0x6F + fnum
    elif key_token in _SPECIAL_KEYS:
        vk = _SPECIAL_KEYS[key_token]
    else:
        raise ValueError(f"Unsupported key token: {key_token!r}")

    return modifiers, vk


class GlobalHotkeyManager:
    """Manages Win32 RegisterHotKey bindings on a dedicated message-loop thread."""

    def __init__(self) -> None:
        self._lock = threading.RLock()
        self._bindings: dict[str, str] = {}
        self._callbacks: dict[str, Callable[[], None]] = {}
        self._status: dict[str, bool] = {}
        self._id_to_name: dict[int, str] = {}
        self._thread: threading.Thread | None = None
        self._thread_id: int | None = None
        self._ready = threading.Event()
        self._rebind_done = threading.Event()
        self._stopping = False

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stopping = False
            self._ready.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="ScreenShieldHotkeys", daemon=True
            )
            self._thread.start()
        self._ready.wait(timeout=2.0)

    def stop(self) -> None:
        with self._lock:
            self._stopping = True
            tid = self._thread_id
        if tid:
            ctypes.windll.user32.PostThreadMessageW(tid, WM_QUIT, 0, 0)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def update_bindings(
        self,
        bindings: dict[str, str],
        callbacks: dict[str, Callable[[], None]],
    ) -> dict[str, bool]:
        """Update registered global hotkeys and return registration status per action."""
        self.start()
        with self._lock:
            self._bindings = dict(bindings)
            self._callbacks = dict(callbacks)
            self._rebind_done.clear()
            tid = self._thread_id

        if tid:
            ctypes.windll.user32.PostThreadMessageW(tid, WM_APP_REBIND, 0, 0)
            self._rebind_done.wait(timeout=2.0)

        with self._lock:
            return dict(self._status)

    def get_status(self) -> dict[str, bool]:
        with self._lock:
            return dict(self._status)

    def _apply_registrations(self) -> None:
        user32 = ctypes.windll.user32
        with self._lock:
            for hotkey_id in list(self._id_to_name):
                user32.UnregisterHotKey(None, hotkey_id)
            self._id_to_name.clear()

            new_status: dict[str, bool] = {}
            next_id = 100
            for action_name, combo in self._bindings.items():
                try:
                    mods, vk = parse_hotkey(combo)
                except ValueError:
                    new_status[action_name] = False
                    continue

                ok = bool(user32.RegisterHotKey(None, next_id, mods | MOD_NOREPEAT, vk))
                if not ok:
                    ok = bool(user32.RegisterHotKey(None, next_id, mods, vk))
                if ok:
                    self._id_to_name[next_id] = action_name
                new_status[action_name] = ok
                next_id += 1
            self._status = new_status
        self._rebind_done.set()

    def _run_loop(self) -> None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        msg = wintypes.MSG()
        # Ensure message queue exists before signalling ready.
        user32.PeekMessageW(ctypes.byref(msg), None, 0, 0, 0)
        self._thread_id = int(kernel32.GetCurrentThreadId())
        self._ready.set()

        while not self._stopping:
            ret = user32.GetMessageW(ctypes.byref(msg), None, 0, 0)
            if ret <= 0:
                break
            if msg.message == WM_APP_REBIND:
                self._apply_registrations()
            elif msg.message == WM_HOTKEY:
                hotkey_id = int(msg.wParam)
                with self._lock:
                    action_name = self._id_to_name.get(hotkey_id)
                    cb = self._callbacks.get(action_name) if action_name else None
                if cb is not None:
                    try:
                        cb()
                    except Exception:
                        pass

        with self._lock:
            for hotkey_id in list(self._id_to_name):
                user32.UnregisterHotKey(None, hotkey_id)
            self._id_to_name.clear()
