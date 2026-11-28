"""Tracks active/visible desktop windows for privacy-rule matching and allowlisting."""

from __future__ import annotations

import ctypes
import os
import re
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from screenshield.core.config import PrivacyRule
from screenshield.core.secret_patterns import detect_secrets


DWMWA_EXTENDED_FRAME_BOUNDS = 9
DWMWA_CLOAKED = 14
WDA_NONE = 0x00000000
WDA_EXCLUDEFROMCAPTURE = 0x00000011
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000

_IGNORED_CLASS_NAMES = {"Progman", "WorkerW", "Shell_TrayWnd", "Windows.UI.Core.CoreWindow"}


def _setup_watcher_win32_signatures() -> None:
    user32 = ctypes.windll.user32
    kernel32 = ctypes.windll.kernel32
    dwmapi = ctypes.windll.dwmapi

    kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
    kernel32.OpenProcess.restype = wintypes.HANDLE

    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    kernel32.QueryFullProcessImageNameW.argtypes = [
        wintypes.HANDLE,
        wintypes.DWORD,
        wintypes.LPWSTR,
        ctypes.POINTER(wintypes.DWORD),
    ]
    kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL

    user32.GetForegroundWindow.argtypes = []
    user32.GetForegroundWindow.restype = wintypes.HWND

    user32.IsWindowVisible.argtypes = [wintypes.HWND]
    user32.IsWindowVisible.restype = wintypes.BOOL

    user32.IsIconic.argtypes = [wintypes.HWND]
    user32.IsIconic.restype = wintypes.BOOL

    user32.GetWindowTextLengthW.argtypes = [wintypes.HWND]
    user32.GetWindowTextLengthW.restype = ctypes.c_int

    user32.GetWindowTextW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetWindowTextW.restype = ctypes.c_int

    user32.GetClassNameW.argtypes = [wintypes.HWND, wintypes.LPWSTR, ctypes.c_int]
    user32.GetClassNameW.restype = ctypes.c_int

    user32.GetWindowThreadProcessId.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.DWORD)]
    user32.GetWindowThreadProcessId.restype = wintypes.DWORD

    user32.GetWindowRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetWindowRect.restype = wintypes.BOOL

    dwmapi.DwmGetWindowAttribute.argtypes = [
        wintypes.HWND,
        wintypes.DWORD,
        ctypes.c_void_p,
        wintypes.DWORD,
    ]
    dwmapi.DwmGetWindowAttribute.restype = ctypes.c_long


_setup_watcher_win32_signatures()


def enable_dpi_awareness() -> None:
    """Enable Per-Monitor V2 DPI awareness so window coordinates match physical pixels."""
    try:
        user32 = ctypes.windll.user32
        # DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 = -4
        user32.SetProcessDpiAwarenessContext.argtypes = [ctypes.c_ssize_t]
        user32.SetProcessDpiAwarenessContext.restype = wintypes.BOOL
        if user32.SetProcessDpiAwarenessContext(-4):
            return
    except Exception:
        pass
    try:
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


@dataclass(frozen=True)
class WindowInfo:
    """Snapshot of a visible top-level desktop window."""

    hwnd: int
    title: str
    process_name: str
    pid: int
    rect: tuple[int, int, int, int]
    is_minimized: bool
    is_foreground: bool
    z_order: int

    def to_dict(self) -> dict[str, object]:
        left, top, right, bottom = self.rect
        return {
            "hwnd": self.hwnd,
            "title": self.title,
            "process_name": self.process_name,
            "pid": self.pid,
            "rect": {"left": left, "top": top, "right": right, "bottom": bottom},
            "width": max(0, right - left),
            "height": max(0, bottom - top),
            "is_minimized": self.is_minimized,
            "is_foreground": self.is_foreground,
            "z_order": self.z_order,
        }


def _query_process_name(pid: int) -> str:
    kernel32 = ctypes.windll.kernel32
    handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
    if not handle:
        return ""
    try:
        buf = ctypes.create_unicode_buffer(512)
        size = wintypes.DWORD(len(buf))
        if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
            return Path(buf.value).name
        return ""
    finally:
        kernel32.CloseHandle(handle)


def _get_window_rect(hwnd: int) -> tuple[int, int, int, int]:
    rect = wintypes.RECT()
    try:
        dwmapi = ctypes.windll.dwmapi
        hr = dwmapi.DwmGetWindowAttribute(
            wintypes.HWND(hwnd),
            DWMWA_EXTENDED_FRAME_BOUNDS,
            ctypes.byref(rect),
            ctypes.sizeof(rect),
        )
        if hr == 0 and rect.right > rect.left and rect.bottom > rect.top:
            return int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)
    except Exception:
        pass
    ctypes.windll.user32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(rect))
    return int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)


def _is_cloaked(hwnd: int) -> bool:
    try:
        cloaked = wintypes.DWORD(0)
        hr = ctypes.windll.dwmapi.DwmGetWindowAttribute(
            wintypes.HWND(hwnd),
            DWMWA_CLOAKED,
            ctypes.byref(cloaked),
            ctypes.sizeof(cloaked),
        )
        return hr == 0 and cloaked.value != 0
    except Exception:
        return False


def get_window_title(hwnd: int) -> str:
    """Read current title of a specific HWND."""
    user32 = ctypes.windll.user32
    length = user32.GetWindowTextLengthW(wintypes.HWND(hwnd))
    if length <= 0:
        return ""
    buf = ctypes.create_unicode_buffer(length + 1)
    user32.GetWindowTextW(wintypes.HWND(hwnd), buf, length + 1)
    return buf.value


def enumerate_windows(*, exclude_own_pid: bool = True) -> list[WindowInfo]:
    """Enumerate visible top-level windows in Z-order (front-to-back)."""
    user32 = ctypes.windll.user32
    own_pid = os.getpid()
    foreground_hwnd = int(user32.GetForegroundWindow() or 0)
    results: list[WindowInfo] = []
    class_buf = ctypes.create_unicode_buffer(256)

    enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

    def _callback(hwnd: int, _lparam: int) -> bool:
        h = int(hwnd)
        if not user32.IsWindowVisible(wintypes.HWND(h)):
            return True
        if _is_cloaked(h):
            return True

        user32.GetClassNameW(wintypes.HWND(h), class_buf, len(class_buf))
        if class_buf.value in _IGNORED_CLASS_NAMES:
            return True

        title = get_window_title(h).strip()
        if not title:
            return True

        pid_val = wintypes.DWORD(0)
        user32.GetWindowThreadProcessId(wintypes.HWND(h), ctypes.byref(pid_val))
        pid = int(pid_val.value)
        if exclude_own_pid and pid == own_pid:
            return True

        is_min = bool(user32.IsIconic(wintypes.HWND(h)))
        rect = _get_window_rect(h)
        if not is_min and (rect[2] - rect[0] <= 1 or rect[3] - rect[1] <= 1):
            return True

        results.append(
            WindowInfo(
                hwnd=h,
                title=title,
                process_name=_query_process_name(pid),
                pid=pid,
                rect=rect,
                is_minimized=is_min,
                is_foreground=(h == foreground_hwnd),
                z_order=len(results),
            )
        )
        return True

    cb = enum_proc_type(_callback)
    user32.EnumWindows(cb, 0)
    return results


def match_rules(window: WindowInfo, rules: list[PrivacyRule]) -> list[PrivacyRule]:
    """Return enabled privacy rules matching a window's title or process name."""
    haystack = f"{window.title} {window.process_name}".strip()
    haystack_lower = haystack.lower()
    matched: list[PrivacyRule] = []
    for rule in rules:
        if not rule.enabled:
            continue
        if rule.match_type == "contains":
            if rule.pattern.lower() in haystack_lower:
                matched.append(rule)
        else:
            try:
                if re.search(rule.pattern, haystack, flags=re.IGNORECASE):
                    matched.append(rule)
            except re.error:
                continue
    return matched


def is_window_sensitive(window: WindowInfo, rules: list[PrivacyRule]) -> tuple[bool, list[str]]:
    """Evaluate whether a window matches any enabled privacy rule or title secret pattern."""
    reasons = [rule.label for rule in match_rules(window, rules)]
    secret_cats = detect_secrets(window.title)
    for cat in secret_cats:
        reasons.append(f"secret:{cat}")
    return bool(reasons), reasons


def set_window_exclude_from_capture(hwnd: int, exclude: bool) -> bool:
    """Apply or clear WDA_EXCLUDEFROMCAPTURE on a window owned by the current process."""
    if not hwnd:
        return False
    try:
        user32 = ctypes.windll.user32
        user32.SetWindowDisplayAffinity.argtypes = [wintypes.HWND, wintypes.DWORD]
        user32.SetWindowDisplayAffinity.restype = wintypes.BOOL
        affinity = WDA_EXCLUDEFROMCAPTURE if exclude else WDA_NONE
        return bool(user32.SetWindowDisplayAffinity(wintypes.HWND(hwnd), affinity))
    except Exception:
        return False


def find_hwnd_by_title_and_pid(title_substring: str, pid: int | None = None) -> int | None:
    """Locate a top-level HWND owned by the specified PID matching a title substring."""
    user32 = ctypes.windll.user32
    found: list[int] = []
    enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)
    needle = title_substring.lower()

    def _cb(hwnd: int, _lparam: int) -> bool:
        h = int(hwnd)
        if not user32.IsWindowVisible(wintypes.HWND(h)):
            return True
        if pid is not None:
            pid_val = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(wintypes.HWND(h), ctypes.byref(pid_val))
            if int(pid_val.value) != pid:
                return True
        title = get_window_title(h)
        if needle in title.lower():
            found.append(h)
            return False
        return True

    user32.EnumWindows(enum_proc_type(_cb), 0)
    return found[0] if found else None
