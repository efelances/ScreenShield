"""Offline secret pattern detection and clipboard privacy guard."""

from __future__ import annotations

import ctypes
import hashlib
import re
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Callable


_COMPILED_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private_key_pem", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----")),
    ("openai_key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("aws_access_key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("google_api_key", re.compile(r"\bAIza[0-9A-Za-z_-]{30,}\b")),
    ("stripe_key", re.compile(r"\b(?:sk|rk)_(?:live|test)_[0-9A-Za-z]{16,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b")),
    ("jwt_token", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")),
    (
        "env_assignment",
        re.compile(
            r"(?im)^\s*(?:export\s+)?[A-Z0-9_]*(?:KEY|SECRET|TOKEN|PASSWORD|PASSWD|DATABASE_URL|DSN|AUTH|CREDENTIAL)[A-Z0-9_]*\s*=\s*['\"]?[^\s'\"]{6,}"
        ),
    ),
]

_CARD_CANDIDATE_RE = re.compile(r"(?<!\d)(?:\d[ -]?){13,19}(?!\d)")


def _luhn_valid(digits: str) -> bool:
    if not (13 <= len(digits) <= 19) or not digits.isdigit():
        return False
    if len(set(digits)) == 1:
        return False
    total = 0
    reverse_digits = digits[::-1]
    for idx, ch in enumerate(reverse_digits):
        n = ord(ch) - 48
        if idx % 2 == 1:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    return total % 10 == 0


def detect_secrets(text: str) -> list[str]:
    """Detect sensitive secret categories in text without retaining secret values."""
    if not text:
        return []
    found: set[str] = set()
    for category, pattern in _COMPILED_PATTERNS:
        if pattern.search(text):
            found.add(category)
    for match in _CARD_CANDIDATE_RE.finditer(text):
        digits = re.sub(r"[ -]", "", match.group(0))
        if _luhn_valid(digits):
            found.add("credit_card")
            break
    return sorted(found)


@dataclass(frozen=True)
class ClipboardAlert:
    """Redacted clipboard alert entry (never contains raw clipboard text)."""

    id: str
    timestamp: str
    categories: list[str]
    auto_cleared: bool

    def to_dict(self) -> dict[str, object]:
        return {
            "id": self.id,
            "timestamp": self.timestamp,
            "categories": list(self.categories),
            "auto_cleared": self.auto_cleared,
        }


def _read_clipboard_text_win32() -> str | None:
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    cf_unicodetext = 13

    user32.OpenClipboard.argtypes = [ctypes.c_void_p]
    user32.OpenClipboard.restype = ctypes.c_int
    user32.IsClipboardFormatAvailable.argtypes = [ctypes.c_uint]
    user32.IsClipboardFormatAvailable.restype = ctypes.c_int
    user32.GetClipboardData.argtypes = [ctypes.c_uint]
    user32.GetClipboardData.restype = ctypes.c_void_p
    user32.CloseClipboard.argtypes = []
    user32.CloseClipboard.restype = ctypes.c_int
    kernel32.GlobalLock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalLock.restype = ctypes.c_void_p
    kernel32.GlobalUnlock.argtypes = [ctypes.c_void_p]
    kernel32.GlobalUnlock.restype = ctypes.c_int

    if not user32.IsClipboardFormatAvailable(cf_unicodetext):
        return None
    if not user32.OpenClipboard(None):
        return None
    try:
        handle = user32.GetClipboardData(cf_unicodetext)
        if not handle:
            return None
        ptr = kernel32.GlobalLock(handle)
        if not ptr:
            return None
        try:
            return ctypes.wstring_at(ptr)
        finally:
            kernel32.GlobalUnlock(handle)
    finally:
        user32.CloseClipboard()


def _clear_clipboard_win32() -> bool:
    user32 = ctypes.windll.user32
    if not user32.OpenClipboard(None):
        return False
    try:
        return bool(user32.EmptyClipboard())
    finally:
        user32.CloseClipboard()


class ClipboardGuard:
    """Monitors clipboard text offline for leaked secrets during active sharing."""

    def __init__(
        self,
        read_clipboard: Callable[[], str | None] | None = None,
        clear_clipboard: Callable[[], bool] | None = None,
        poll_interval_s: float = 0.6,
    ) -> None:
        self._read_clipboard = read_clipboard or _read_clipboard_text_win32
        self._clear_clipboard = clear_clipboard or _clear_clipboard_win32
        self._poll_interval_s = poll_interval_s
        self._lock = threading.RLock()
        self._enabled = True
        self._active_sharing = False
        self._auto_clear = False
        self._last_hash: str | None = None
        self._alerts: list[ClipboardAlert] = []
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    def configure(self, *, enabled: bool, active_sharing: bool, auto_clear: bool) -> None:
        with self._lock:
            self._enabled = enabled
            self._active_sharing = active_sharing
            self._auto_clear = auto_clear

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="ScreenShieldClipboardGuard", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=1.5)

    def _run_loop(self) -> None:
        while not self._stop_event.wait(self._poll_interval_s):
            self.scan_once()

    def scan_once(self) -> ClipboardAlert | None:
        """Read current clipboard text once and record a redacted alert if secrets match."""
        with self._lock:
            if not (self._enabled and self._active_sharing):
                return None
            auto_clear = self._auto_clear

        try:
            text = self._read_clipboard()
        except Exception:
            return None

        if not text:
            return None

        digest = hashlib.sha256(text.encode("utf-8", errors="ignore")).hexdigest()
        with self._lock:
            if digest == self._last_hash:
                return None
            self._last_hash = digest

        categories = detect_secrets(text)
        if not categories:
            return None

        cleared = False
        if auto_clear:
            try:
                cleared = bool(self._clear_clipboard())
            except Exception:
                cleared = False

        alert = ClipboardAlert(
            id=f"clip_{uuid.uuid4().hex[:8]}",
            timestamp=datetime.now(timezone.utc).isoformat(),
            categories=categories,
            auto_cleared=cleared,
        )
        with self._lock:
            self._alerts.insert(0, alert)
            if len(self._alerts) > 50:
                self._alerts = self._alerts[:50]
            if cleared:
                self._last_hash = None
        return alert

    def get_alerts(self) -> list[dict[str, object]]:
        with self._lock:
            return [a.to_dict() for a in self._alerts]

    def clear_alerts(self) -> None:
        with self._lock:
            self._alerts.clear()
            self._last_hash = None
