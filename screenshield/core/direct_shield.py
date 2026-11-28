"""Ultra-low-latency Direct On-Screen Auto Shield using Win32 SetWinEventHook & pooled overlays."""

from __future__ import annotations

import ctypes
import os
import re
import threading
import time
from collections import deque
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path

from screenshield.core.config import AppConfig, PrivacyRule
from screenshield.core.mirror_engine import capture_window_image
from screenshield.core.mirror_window import (
    BITMAPINFO,
    BITMAPINFOHEADER,
    DIB_RGB_COLORS,
    HALFTONE,
    PAINTSTRUCT,
    SRCCOPY,
    WNDCLASSEXW,
    WNDPROC,
)
from screenshield.core.privacy_mask import CURTAIN_STRINGS, make_heavy_frost_image
from screenshield.core.secret_patterns import detect_secrets
from screenshield.core.window_watcher import (
    DWMWA_CLOAKED,
    DWMWA_EXTENDED_FRAME_BOUNDS,
    PROCESS_QUERY_LIMITED_INFORMATION,
    WindowInfo,
    get_window_title,
)


POOL_SIZE = 12
HEARTBEAT_TIMER_ID = 1
HEARTBEAT_INTERVAL_MS = 16

CS_VREDRAW = 0x0001
CS_HREDRAW = 0x0002
MONITOR_DEFAULTTONEAREST = 2

WS_POPUP = 0x80000000
WS_EX_TOPMOST = 0x00000008
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000

SW_HIDE = 0
SW_SHOWNOACTIVATE = 4
SWP_NOSIZE = 0x0001
SWP_NOMOVE = 0x0002
SWP_NOZORDER = 0x0004
SWP_NOACTIVATE = 0x0010
SWP_SHOWWINDOW = 0x0040
SWP_HIDEWINDOW = 0x0080

HWND_TOP = 0
HWND_TOPMOST = -1
HWND_NOTOPMOST = -2
GW_HWNDPREV = 3
GWL_EXSTYLE = -20
LWA_ALPHA = 0x00000002

SM_XVIRTUALSCREEN = 76
SM_YVIRTUALSCREEN = 77
SM_CXVIRTUALSCREEN = 78
SM_CYVIRTUALSCREEN = 79

WM_DESTROY = 0x0002
WM_PAINT = 0x000F
WM_ERASEBKGND = 0x0014
WM_QUIT = 0x0012
WM_TIMER = 0x0113

WM_APP_START = 0x8101
WM_APP_STOP = 0x8102
WM_APP_SYNC = 0x8103
WM_APP_PANIC = 0x8104
WM_APP_REFRESH_STYLE = 0x8105

# WinEvent constants
WINEVENT_OUTOFCONTEXT = 0x0000
WINEVENT_SKIPOWNPROCESS = 0x0002
EVENT_SYSTEM_FOREGROUND = 0x0003
EVENT_SYSTEM_MOVESIZESTART = 0x000A
EVENT_SYSTEM_MOVESIZEEND = 0x000B
EVENT_SYSTEM_MINIMIZESTART = 0x0016
EVENT_SYSTEM_MINIMIZEEND = 0x0017
EVENT_OBJECT_SHOW = 0x8002
EVENT_OBJECT_HIDE = 0x8003
EVENT_OBJECT_LOCATIONCHANGE = 0x800B
EVENT_OBJECT_NAMECHANGE = 0x800C

TRANSPARENT_BK = 1
DT_CENTER = 0x00000001
DT_VCENTER = 0x00000004
DT_SINGLELINE = 0x00000020
DT_END_ELLIPSIS = 0x00008000

_IGNORED_CLASSES = {"Progman", "WorkerW", "Shell_TrayWnd", "Windows.UI.Core.CoreWindow"}

WINEVENTPROC = ctypes.WINFUNCTYPE(
    None,
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.HWND,
    wintypes.LONG,
    wintypes.LONG,
    wintypes.DWORD,
    wintypes.DWORD,
)


class _MONITORINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.DWORD),
        ("rcMonitor", wintypes.RECT),
        ("rcWork", wintypes.RECT),
        ("dwFlags", wintypes.DWORD),
    ]


def _setup_direct_win32_signatures() -> None:
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    user32.SetWinEventHook.argtypes = [
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.HMODULE,
        WINEVENTPROC,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.UINT,
    ]
    user32.SetWinEventHook.restype = wintypes.HANDLE

    user32.UnhookWinEvent.argtypes = [wintypes.HANDLE]
    user32.UnhookWinEvent.restype = wintypes.BOOL

    user32.GetWindow.argtypes = [wintypes.HWND, wintypes.UINT]
    user32.GetWindow.restype = wintypes.HWND

    user32.GetWindowLongW.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.GetWindowLongW.restype = wintypes.LONG

    user32.BeginDeferWindowPos.argtypes = [ctypes.c_int]
    user32.BeginDeferWindowPos.restype = wintypes.HANDLE

    user32.DeferWindowPos.argtypes = [
        wintypes.HANDLE,
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    user32.DeferWindowPos.restype = wintypes.HANDLE

    user32.EndDeferWindowPos.argtypes = [wintypes.HANDLE]
    user32.EndDeferWindowPos.restype = wintypes.BOOL

    user32.SetTimer.argtypes = [wintypes.HWND, ctypes.c_size_t, wintypes.UINT, ctypes.c_void_p]
    user32.SetTimer.restype = ctypes.c_size_t

    user32.KillTimer.argtypes = [wintypes.HWND, ctypes.c_size_t]
    user32.KillTimer.restype = wintypes.BOOL

    user32.DrawTextW.argtypes = [
        wintypes.HDC,
        wintypes.LPCWSTR,
        ctypes.c_int,
        ctypes.POINTER(wintypes.RECT),
        wintypes.UINT,
    ]
    user32.DrawTextW.restype = ctypes.c_int

    user32.FrameRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HBRUSH]
    user32.FrameRect.restype = ctypes.c_int

    gdi32.SetBkMode.argtypes = [wintypes.HDC, ctypes.c_int]
    gdi32.SetBkMode.restype = ctypes.c_int

    gdi32.SetTextColor.argtypes = [wintypes.HDC, wintypes.COLORREF]
    gdi32.SetTextColor.restype = wintypes.COLORREF

    gdi32.CreateFontW.argtypes = [
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.DWORD,
        wintypes.LPCWSTR,
    ]
    gdi32.CreateFontW.restype = wintypes.HFONT

    gdi32.Polygon.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.POINT), ctypes.c_int]
    gdi32.Polygon.restype = wintypes.BOOL

    user32.UpdateWindow.argtypes = [wintypes.HWND]
    user32.UpdateWindow.restype = wintypes.BOOL

    user32.MonitorFromWindow.argtypes = [wintypes.HWND, wintypes.DWORD]
    user32.MonitorFromWindow.restype = wintypes.HMONITOR

    user32.GetMonitorInfoW.argtypes = [wintypes.HMONITOR, ctypes.POINTER(_MONITORINFO)]
    user32.GetMonitorInfoW.restype = wintypes.BOOL


_setup_direct_win32_signatures()


class CompiledRuleSet:
    """Pre-compiled privacy rules for sub-millisecond window matching."""

    def __init__(self, rules: list[PrivacyRule]) -> None:
        self._contains: list[tuple[str, str]] = []
        self._regexes: list[tuple[str, re.Pattern[str]]] = []
        for rule in rules:
            if not rule.enabled:
                continue
            if rule.match_type == "contains":
                self._contains.append((rule.label, rule.pattern.lower()))
            else:
                try:
                    self._regexes.append((rule.label, re.compile(rule.pattern, re.IGNORECASE)))
                except re.error:
                    continue

    def match(self, title: str, process_name: str = "") -> tuple[bool, list[str]]:
        haystack = f"{title} {process_name}".strip()
        haystack_lower = haystack.lower()
        reasons: list[str] = []

        for label, needle in self._contains:
            if needle in haystack_lower:
                reasons.append(label)

        for label, pattern in self._regexes:
            if pattern.search(haystack):
                reasons.append(label)

        for cat in detect_secrets(title):
            reasons.append(f"secret:{cat}")

        return bool(reasons), reasons


@dataclass(frozen=True)
class ShieldTarget:
    """Target desktop window and expanded bounding box for an on-screen overlay."""

    hwnd: int
    rect: tuple[int, int, int, int]
    label: str
    z_order: int


def compute_shield_targets(
    windows: list[WindowInfo],
    compiled_rules: CompiledRuleSet,
    manual_hwnds: set[int],
    padding_px: int = 4,
) -> list[ShieldTarget]:
    """Compute ordered overlay targets from visible windows, rules, and manual blocks."""
    pad = max(0, int(padding_px))
    targets: list[ShieldTarget] = []
    for win in windows:
        if win.is_minimized:
            continue
        left, top, right, bottom = win.rect
        if right - left <= 1 or bottom - top <= 1:
            continue

        matched, reasons = compiled_rules.match(win.title, win.process_name)
        manual = win.hwnd in manual_hwnds
        if not matched and not manual:
            continue

        label = reasons[0] if reasons else (win.process_name or win.title[:32])
        expanded = (left - pad, top - pad, right + pad, bottom + pad)
        targets.append(
            ShieldTarget(
                hwnd=win.hwnd,
                rect=expanded,
                label=label,
                z_order=win.z_order,
            )
        )
    return targets


def expand_for_resizing(
    targets: list[ShieldTarget],
    resizing_hwnds: set[int],
    monitor_rects: dict[int, tuple[int, int, int, int]],
) -> list[ShieldTarget]:
    """Expand overlays to full monitor work area while a shielded window is dragged or resized."""
    if not resizing_hwnds:
        return targets
    expanded: list[ShieldTarget] = []
    for target in targets:
        if target.hwnd in resizing_hwnds and target.hwnd in monitor_rects:
            expanded.append(
                ShieldTarget(
                    hwnd=target.hwnd,
                    rect=monitor_rects[target.hwnd],
                    label=target.label,
                    z_order=target.z_order,
                )
            )
        else:
            expanded.append(target)
    return expanded


def needs_clear_topmost(overlay_is_topmost: bool, target_wants_topmost: bool) -> bool:
    """Return True when an overlay must be demoted via HWND_NOTOPMOST before normal Z-order."""
    return overlay_is_topmost and not target_wants_topmost


class DirectOverlayEngine:
    """Zero-polling WinEvent-driven on-screen shield overlay pool."""

    OVERLAY_CLASS = "ScreenShieldDirectOverlayClass"
    PANIC_CLASS = "ScreenShieldPanicCurtainClass"

    def __init__(self, initial_config: AppConfig) -> None:
        self._lock = threading.RLock()
        self._config = initial_config
        self._compiled_rules = CompiledRuleSet(initial_config.rules)
        self._manual_hwnds: set[int] = set(initial_config.blocked_hwnds)

        self._active = False
        self._panic = False
        self._active_shields = 0
        self._events_processed = 0
        self._last_latency_ms = 0.0
        self._latency_samples: deque[float] = deque(maxlen=40)

        self._pid_cache: dict[int, str] = {}
        self._pool_hwnds: list[int] = []
        self._own_hwnds: set[int] = set()
        self._overlay_labels: dict[int, str] = {}
        self._overlay_frost: dict[int, tuple[bytes, int, int]] = {}
        self._overlay_rects: dict[int, tuple[int, int, int, int]] = {}
        self._resizing_hwnds: set[int] = set()
        self._minimize_hold_until: dict[int, tuple[float, tuple[int, int, int, int], str]] = {}
        self._active_map: dict[int, int] = {}  # target_hwnd -> pool_index
        self._panic_hwnd: int = 0
        self._msg_hwnd: int = 0
        self._hooks: list[int] = []

        self._thread: threading.Thread | None = None
        self._thread_id: int = 0
        self._frost_thread: threading.Thread | None = None
        self._frost_stop = threading.Event()
        self._ready = threading.Event()
        self._wndproc_ref: WNDPROC | None = None
        self._panic_wndproc_ref: WNDPROC | None = None
        self._winevent_proc_ref: WINEVENTPROC | None = None

    def start_thread(self) -> None:
        with self._lock:
            if self._thread is None or not self._thread.is_alive():
                self._ready.clear()
                self._thread = threading.Thread(
                    target=self._run_loop, name="ScreenShieldDirectOverlay", daemon=True
                )
                self._thread.start()
                wait_needed = True
            else:
                wait_needed = False
            if self._frost_thread is None or not self._frost_thread.is_alive():
                self._frost_stop.clear()
                self._frost_thread = threading.Thread(
                    target=self._frost_loop, name="ScreenShieldFrostWorker", daemon=True
                )
                self._frost_thread.start()
        if wait_needed:
            self._ready.wait(timeout=3.0)

    def start_shield(self) -> None:
        self.start_thread()
        with self._lock:
            self._active = True
        if self._msg_hwnd:
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._msg_hwnd), WM_APP_START, 0, 0)

    def stop_shield(self) -> None:
        with self._lock:
            self._active = False
            self._active_shields = 0
            self._overlay_frost.clear()
        if self._msg_hwnd:
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._msg_hwnd), WM_APP_STOP, 0, 0)

    def set_panic(self, active: bool) -> None:
        if active:
            self.start_thread()
        with self._lock:
            self._panic = bool(active)
        if self._msg_hwnd:
            ctypes.windll.user32.PostMessageW(
                wintypes.HWND(self._msg_hwnd), WM_APP_PANIC, 1 if active else 0, 0
            )

    def update_config(self, config: AppConfig) -> None:
        with self._lock:
            style_changed = config.mask_style != self._config.mask_style
            lang_or_hc_changed = (
                config.language != self._config.language
                or config.high_contrast != self._config.high_contrast
            )
            self._config = config
            self._compiled_rules = CompiledRuleSet(config.rules)
            self._manual_hwnds = set(config.blocked_hwnds)
            if config.mask_style != "blur":
                self._overlay_frost.clear()

        if self._msg_hwnd:
            if style_changed or lang_or_hc_changed:
                ctypes.windll.user32.PostMessageW(
                    wintypes.HWND(self._msg_hwnd), WM_APP_REFRESH_STYLE, 0, 0
                )
            if self._active:
                ctypes.windll.user32.PostMessageW(
                    wintypes.HWND(self._msg_hwnd), WM_APP_SYNC, 0, 0
                )

    def refresh(self) -> None:
        if self._msg_hwnd and self._active:
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._msg_hwnd), WM_APP_SYNC, 0, 0)

    def get_metrics(self) -> dict[str, object]:
        with self._lock:
            avg = (
                sum(self._latency_samples) / len(self._latency_samples)
                if self._latency_samples
                else 0.0
            )
            return {
                "active": self._active,
                "panic": self._panic,
                "active_shields": self._active_shields,
                "events_processed": self._events_processed,
                "last_latency_ms": round(self._last_latency_ms, 2),
                "avg_latency_ms": round(avg, 2),
            }

    def stop(self) -> None:
        with self._lock:
            self._active = False
            self._panic = False
            self._overlay_frost.clear()
        self._frost_stop.set()
        frost_thread = self._frost_thread
        if frost_thread is not None and frost_thread.is_alive():
            frost_thread.join(timeout=1.5)
        tid = self._thread_id
        if tid:
            ctypes.windll.user32.PostThreadMessageW(tid, WM_QUIT, 0, 0)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def _frost_loop(self) -> None:
        """Periodically build opaque 100%-unreadable heavy frost textures for active overlays."""
        user32 = ctypes.windll.user32
        while not self._frost_stop.wait(0.4):
            with self._lock:
                if not self._active or self._config.mask_style != "blur":
                    continue
                pairs = [
                    (target_hwnd, self._pool_hwnds[idx])
                    for target_hwnd, idx in self._active_map.items()
                    if 0 <= idx < len(self._pool_hwnds)
                ]
            if not pairs:
                continue

            active_overlays = {ov for _, ov in pairs}
            with self._lock:
                for stale_ov in list(self._overlay_frost):
                    if stale_ov not in active_overlays:
                        self._overlay_frost.pop(stale_ov, None)

            for target_hwnd, overlay_hwnd in pairs:
                if self._frost_stop.is_set():
                    break
                try:
                    snap = capture_window_image(target_hwnd)
                    if snap is None:
                        continue
                    frosted = make_heavy_frost_image(snap, (240, 140)).convert("RGBA")
                    raw = frosted.tobytes("raw", "BGRA")
                    with self._lock:
                        if not self._active or self._config.mask_style != "blur":
                            continue
                        self._overlay_frost[overlay_hwnd] = (raw, 240, 140)
                    user32.InvalidateRect(wintypes.HWND(overlay_hwnd), None, False)
                except Exception:
                    continue

    def _query_process_name_cached(self, pid: int) -> str:
        cached = self._pid_cache.get(pid)
        if cached is not None:
            return cached
        kernel32 = ctypes.windll.kernel32
        handle = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
        name = ""
        if handle:
            try:
                buf = ctypes.create_unicode_buffer(512)
                size = wintypes.DWORD(len(buf))
                if kernel32.QueryFullProcessImageNameW(handle, 0, buf, ctypes.byref(size)):
                    name = Path(buf.value).name
            finally:
                kernel32.CloseHandle(handle)
        if len(self._pid_cache) > 512:
            self._pid_cache.clear()
        self._pid_cache[pid] = name
        return name

    def _fast_enum_windows(self) -> list[WindowInfo]:
        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi
        own_pid = os.getpid()
        fg = int(user32.GetForegroundWindow() or 0)
        class_buf = ctypes.create_unicode_buffer(128)
        results: list[WindowInfo] = []

        enum_proc_type = ctypes.WINFUNCTYPE(wintypes.BOOL, wintypes.HWND, wintypes.LPARAM)

        def _cb(hwnd: int, _lp: int) -> bool:
            h = int(hwnd)
            if h in self._own_hwnds:
                return True
            if not user32.IsWindowVisible(wintypes.HWND(h)):
                return True
            if user32.IsIconic(wintypes.HWND(h)):
                return True

            cloaked = wintypes.DWORD(0)
            if (
                dwmapi.DwmGetWindowAttribute(
                    wintypes.HWND(h), DWMWA_CLOAKED, ctypes.byref(cloaked), ctypes.sizeof(cloaked)
                )
                == 0
                and cloaked.value != 0
            ):
                return True

            user32.GetClassNameW(wintypes.HWND(h), class_buf, len(class_buf))
            if class_buf.value in _IGNORED_CLASSES:
                return True

            title = get_window_title(h).strip()
            if not title:
                return True

            pid_val = wintypes.DWORD(0)
            user32.GetWindowThreadProcessId(wintypes.HWND(h), ctypes.byref(pid_val))
            pid = int(pid_val.value)
            if pid == own_pid:
                return True

            rect = wintypes.RECT()
            hr = dwmapi.DwmGetWindowAttribute(
                wintypes.HWND(h),
                DWMWA_EXTENDED_FRAME_BOUNDS,
                ctypes.byref(rect),
                ctypes.sizeof(rect),
            )
            if hr != 0 or rect.right <= rect.left or rect.bottom <= rect.top:
                user32.GetWindowRect(wintypes.HWND(h), ctypes.byref(rect))
            if rect.right - rect.left <= 1 or rect.bottom - rect.top <= 1:
                return True

            results.append(
                WindowInfo(
                    hwnd=h,
                    title=title,
                    process_name=self._query_process_name_cached(pid),
                    pid=pid,
                    rect=(int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)),
                    is_minimized=False,
                    is_foreground=(h == fg),
                    z_order=len(results),
                )
            )
            return True

        user32.EnumWindows(enum_proc_type(_cb), 0)
        return results

    def _get_window_rect_fast(self, hwnd: int) -> tuple[int, int, int, int] | None:
        user32 = ctypes.windll.user32
        dwmapi = ctypes.windll.dwmapi
        if not user32.IsWindowVisible(wintypes.HWND(hwnd)) or user32.IsIconic(wintypes.HWND(hwnd)):
            return None
        rect = wintypes.RECT()
        hr = dwmapi.DwmGetWindowAttribute(
            wintypes.HWND(hwnd),
            DWMWA_EXTENDED_FRAME_BOUNDS,
            ctypes.byref(rect),
            ctypes.sizeof(rect),
        )
        if hr != 0 or rect.right <= rect.left or rect.bottom <= rect.top:
            user32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(rect))
        if rect.right - rect.left <= 1 or rect.bottom - rect.top <= 1:
            return None
        return int(rect.left), int(rect.top), int(rect.right), int(rect.bottom)

    def _compute_insert_after(self, target_hwnd: int) -> wintypes.HWND:
        """Return the HWND directly above target_hwnd so our shield tracks target's exact Z-order."""
        user32 = ctypes.windll.user32
        ex_style = int(user32.GetWindowLongW(wintypes.HWND(target_hwnd), GWL_EXSTYLE))
        if ex_style & WS_EX_TOPMOST:
            return wintypes.HWND(HWND_TOPMOST)

        cur = user32.GetWindow(wintypes.HWND(target_hwnd), GW_HWNDPREV)
        while cur:
            cur_int = int(cur)
            if cur_int not in self._own_hwnds:
                cur_ex = int(user32.GetWindowLongW(wintypes.HWND(cur_int), GWL_EXSTYLE))
                if not (cur_ex & WS_EX_TOPMOST):
                    return wintypes.HWND(cur_int)
                return wintypes.HWND(HWND_TOP)
            cur = user32.GetWindow(wintypes.HWND(cur_int), GW_HWNDPREV)
        return wintypes.HWND(HWND_TOP)

    def _record_latency(self, t0: float) -> None:
        dt_ms = (time.perf_counter() - t0) * 1000.0
        with self._lock:
            self._events_processed += 1
            self._last_latency_ms = dt_ms
            self._latency_samples.append(dt_ms)

    def _get_monitor_work_rect(self, hwnd: int) -> tuple[int, int, int, int] | None:
        user32 = ctypes.windll.user32
        hmon = user32.MonitorFromWindow(wintypes.HWND(hwnd), MONITOR_DEFAULTTONEAREST)
        if not hmon:
            return None
        mi = _MONITORINFO()
        mi.cbSize = ctypes.sizeof(_MONITORINFO)
        if not user32.GetMonitorInfoW(hmon, ctypes.byref(mi)):
            return None
        return (
            int(mi.rcWork.left),
            int(mi.rcWork.top),
            int(mi.rcWork.right),
            int(mi.rcWork.bottom),
        )

    def _hide_all_pool(self) -> None:
        user32 = ctypes.windll.user32
        hdwp = user32.BeginDeferWindowPos(len(self._pool_hwnds))
        for overlay_hwnd in self._pool_hwnds:
            if hdwp:
                hdwp = user32.DeferWindowPos(
                    hdwp,
                    wintypes.HWND(overlay_hwnd),
                    None,
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW,
                )
        if hdwp:
            user32.EndDeferWindowPos(hdwp)
        self._overlay_rects.clear()
        self._resizing_hwnds.clear()
        self._minimize_hold_until.clear()
        with self._lock:
            self._active_map.clear()
            self._active_shields = 0

    def _sync_all(self) -> None:
        t0 = time.perf_counter()
        with self._lock:
            active = self._active
            rules = self._compiled_rules
            manual = set(self._manual_hwnds)
            pad = self._config.direct_padding_px

        if not active:
            self._hide_all_pool()
            return

        windows = self._fast_enum_windows()
        targets = compute_shield_targets(windows, rules, manual, padding_px=pad)[:POOL_SIZE]

        if self._resizing_hwnds:
            monitor_rects: dict[int, tuple[int, int, int, int]] = {}
            for t in targets:
                if t.hwnd in self._resizing_hwnds:
                    mrect = self._get_monitor_work_rect(t.hwnd)
                    if mrect is not None:
                        monitor_rects[t.hwnd] = mrect
            targets = expand_for_resizing(targets, self._resizing_hwnds, monitor_rects)

        now_mono = time.monotonic()
        target_hwnds = {t.hwnd for t in targets}
        for mh in list(self._minimize_hold_until):
            exp, mrect, mlabel = self._minimize_hold_until[mh]
            if now_mono >= exp or mh in target_hwnds:
                self._minimize_hold_until.pop(mh, None)
            elif len(targets) < POOL_SIZE:
                targets.append(ShieldTarget(hwnd=mh, rect=mrect, label=mlabel, z_order=0))

        user32 = ctypes.windll.user32
        new_map: dict[int, int] = {}
        used_indices: set[int] = set()

        # Keep existing pool slot assignments stable to avoid flicker
        for t in targets:
            if t.hwnd in self._active_map:
                idx = self._active_map[t.hwnd]
                new_map[t.hwnd] = idx
                used_indices.add(idx)

        free_indices = [i for i in range(POOL_SIZE) if i not in used_indices]
        for t in targets:
            if t.hwnd not in new_map and free_indices:
                idx = free_indices.pop(0)
                new_map[t.hwnd] = idx
                used_indices.add(idx)

        resized_overlays: list[int] = []
        hdwp = user32.BeginDeferWindowPos(POOL_SIZE)
        for t in targets:
            idx = new_map.get(t.hwnd)
            if idx is None:
                continue
            overlay_hwnd = self._pool_hwnds[idx]
            prev_label = self._overlay_labels.get(overlay_hwnd)
            new_label = f"ScreenShield · {t.label}"
            if prev_label != new_label:
                self._overlay_labels[overlay_hwnd] = new_label
                user32.InvalidateRect(wintypes.HWND(overlay_hwnd), None, False)

            left, top, right, bottom = t.rect
            w = max(2, right - left)
            h = max(2, bottom - top)
            rect_tuple = (left, top, w, h)
            if self._overlay_rects.get(overlay_hwnd) != rect_tuple:
                self._overlay_rects[overlay_hwnd] = rect_tuple
                resized_overlays.append(overlay_hwnd)

            is_resizing = t.hwnd in self._resizing_hwnds
            target_ex = int(user32.GetWindowLongW(wintypes.HWND(t.hwnd), GWL_EXSTYLE))
            target_wants_topmost = is_resizing or bool(target_ex & WS_EX_TOPMOST)
            ov_ex = int(user32.GetWindowLongW(wintypes.HWND(overlay_hwnd), GWL_EXSTYLE))
            if needs_clear_topmost(bool(ov_ex & WS_EX_TOPMOST), target_wants_topmost):
                user32.SetWindowPos(
                    wintypes.HWND(overlay_hwnd),
                    wintypes.HWND(HWND_NOTOPMOST),
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                )

            insert_after = (
                wintypes.HWND(HWND_TOPMOST)
                if target_wants_topmost
                else self._compute_insert_after(t.hwnd)
            )

            if hdwp:
                hdwp = user32.DeferWindowPos(
                    hdwp,
                    wintypes.HWND(overlay_hwnd),
                    insert_after,
                    left,
                    top,
                    w,
                    h,
                    SWP_NOACTIVATE | SWP_SHOWWINDOW,
                )

        for idx in range(POOL_SIZE):
            if idx not in used_indices:
                overlay_hwnd = self._pool_hwnds[idx]
                self._overlay_rects.pop(overlay_hwnd, None)
                if hdwp:
                    hdwp = user32.DeferWindowPos(
                        hdwp,
                        wintypes.HWND(overlay_hwnd),
                        None,
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOZORDER | SWP_NOACTIVATE | SWP_HIDEWINDOW,
                    )

        if hdwp:
            user32.EndDeferWindowPos(hdwp)

        for ohwnd in resized_overlays:
            user32.InvalidateRect(wintypes.HWND(ohwnd), None, False)
            user32.UpdateWindow(wintypes.HWND(ohwnd))

        with self._lock:
            self._active_map = new_map
            self._active_shields = len(new_map)
            active_overlays = {self._pool_hwnds[i] for i in used_indices}
            for stale_ov in list(self._overlay_frost):
                if stale_ov not in active_overlays:
                    self._overlay_frost.pop(stale_ov, None)
        self._record_latency(t0)

    def _fast_move_single(self, target_hwnd: int) -> None:
        if target_hwnd in self._resizing_hwnds:
            return
        with self._lock:
            pool_idx = self._active_map.get(target_hwnd)
        if pool_idx is None:
            return
        t0 = time.perf_counter()
        rect = self._get_window_rect_fast(target_hwnd)
        if rect is None:
            self._sync_all()
            return
        with self._lock:
            pad = self._config.direct_padding_px
        overlay_hwnd = self._pool_hwnds[pool_idx]
        left = rect[0] - pad
        top = rect[1] - pad
        w = max(2, (rect[2] + pad) - left)
        h = max(2, (rect[3] + pad) - top)
        rect_tuple = (left, top, w, h)
        changed = self._overlay_rects.get(overlay_hwnd) != rect_tuple
        self._overlay_rects[overlay_hwnd] = rect_tuple
        user32 = ctypes.windll.user32
        target_ex = int(user32.GetWindowLongW(wintypes.HWND(target_hwnd), GWL_EXSTYLE))
        target_wants_topmost = bool(target_ex & WS_EX_TOPMOST)
        ov_ex = int(user32.GetWindowLongW(wintypes.HWND(overlay_hwnd), GWL_EXSTYLE))
        if needs_clear_topmost(bool(ov_ex & WS_EX_TOPMOST), target_wants_topmost):
            user32.SetWindowPos(
                wintypes.HWND(overlay_hwnd),
                wintypes.HWND(HWND_NOTOPMOST),
                0,
                0,
                0,
                0,
                SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
            )
        insert_after = (
            wintypes.HWND(HWND_TOPMOST)
            if target_wants_topmost
            else self._compute_insert_after(target_hwnd)
        )
        user32.SetWindowPos(
            wintypes.HWND(overlay_hwnd),
            insert_after,
            left,
            top,
            w,
            h,
            SWP_NOACTIVATE | SWP_SHOWWINDOW,
        )
        if changed:
            user32.InvalidateRect(wintypes.HWND(overlay_hwnd), None, False)
            user32.UpdateWindow(wintypes.HWND(overlay_hwnd))
        self._record_latency(t0)

    def _install_hooks(self) -> None:
        if self._hooks:
            return
        user32 = ctypes.windll.user32

        def _on_win_event(
            _hook: int,
            event: int,
            hwnd: int,
            id_object: int,
            id_child: int,
            _thread: int,
            _time_ms: int,
        ) -> None:
            if not self._active:
                return
            h = int(hwnd or 0)
            if h in self._own_hwnds:
                return
            if event == EVENT_SYSTEM_MOVESIZESTART:
                if h in self._active_map:
                    self._resizing_hwnds.add(h)
                    self._sync_all()
                return
            if event == EVENT_SYSTEM_MOVESIZEEND:
                if h in self._resizing_hwnds:
                    self._resizing_hwnds.discard(h)
                self._sync_all()
                return
            if event == EVENT_SYSTEM_MINIMIZESTART:
                if h in self._active_map:
                    idx = self._active_map[h]
                    ov = self._pool_hwnds[idx]
                    cur_rect = self._overlay_rects.get(ov)
                    if cur_rect is not None:
                        lbl = self._overlay_labels.get(ov, "ScreenShield").removeprefix(
                            "ScreenShield · "
                        )
                        self._minimize_hold_until[h] = (
                            time.monotonic() + 0.16,
                            (
                                cur_rect[0],
                                cur_rect[1],
                                cur_rect[0] + cur_rect[2],
                                cur_rect[1] + cur_rect[3],
                            ),
                            lbl,
                        )
                self._sync_all()
                return
            if event == EVENT_OBJECT_LOCATIONCHANGE:
                if id_object == 0 and id_child == 0 and h in self._active_map:
                    self._fast_move_single(h)
                return
            if event == EVENT_OBJECT_NAMECHANGE:
                if id_object == 0 and id_child == 0 and h:
                    self._sync_all()
                return
            if id_object == 0 or event in (
                EVENT_SYSTEM_FOREGROUND,
                EVENT_SYSTEM_MINIMIZEEND,
            ):
                self._sync_all()

        self._winevent_proc_ref = WINEVENTPROC(_on_win_event)
        flags = WINEVENT_OUTOFCONTEXT | WINEVENT_SKIPOWNPROCESS
        ranges = [
            (EVENT_SYSTEM_FOREGROUND, EVENT_SYSTEM_FOREGROUND),
            (EVENT_SYSTEM_MOVESIZESTART, EVENT_SYSTEM_MOVESIZEEND),
            (EVENT_SYSTEM_MINIMIZESTART, EVENT_SYSTEM_MINIMIZEEND),
            (EVENT_OBJECT_SHOW, EVENT_OBJECT_HIDE),
            (EVENT_OBJECT_LOCATIONCHANGE, EVENT_OBJECT_NAMECHANGE),
        ]
        for ev_min, ev_max in ranges:
            hook = user32.SetWinEventHook(ev_min, ev_max, None, self._winevent_proc_ref, 0, 0, flags)
            if hook:
                self._hooks.append(int(hook))

        user32.SetTimer(wintypes.HWND(self._msg_hwnd), HEARTBEAT_TIMER_ID, HEARTBEAT_INTERVAL_MS, None)

    def _remove_hooks(self) -> None:
        user32 = ctypes.windll.user32
        if self._msg_hwnd:
            user32.KillTimer(wintypes.HWND(self._msg_hwnd), HEARTBEAT_TIMER_ID)
        for hook in self._hooks:
            user32.UnhookWinEvent(wintypes.HANDLE(hook))
        self._hooks.clear()

    def _apply_panic_curtain(self, show: bool) -> None:
        if not self._panic_hwnd:
            return
        user32 = ctypes.windll.user32
        if show:
            vx = int(user32.GetSystemMetrics(SM_XVIRTUALSCREEN))
            vy = int(user32.GetSystemMetrics(SM_YVIRTUALSCREEN))
            vw = int(user32.GetSystemMetrics(SM_CXVIRTUALSCREEN) or 1920)
            vh = int(user32.GetSystemMetrics(SM_CYVIRTUALSCREEN) or 1080)
            user32.SetWindowPos(
                wintypes.HWND(self._panic_hwnd),
                wintypes.HWND(HWND_TOPMOST),
                vx,
                vy,
                vw,
                vh,
                SWP_NOACTIVATE | SWP_SHOWWINDOW,
            )
            user32.InvalidateRect(wintypes.HWND(self._panic_hwnd), None, False)
        else:
            user32.ShowWindow(wintypes.HWND(self._panic_hwnd), SW_HIDE)

    def _run_loop(self) -> None:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        kernel32 = ctypes.windll.kernel32
        hinstance = kernel32.GetModuleHandleW(None)
        self._thread_id = int(kernel32.GetCurrentThreadId())

        bg_brush = gdi32.CreateSolidBrush(0x00191B1C)      # #1C1B19
        border_brush = gdi32.CreateSolidBrush(0x00465C24)  # #245C46 (COLORREF 0x00BBGGRR)
        overlay_font = gdi32.CreateFontW(20, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, "Segoe UI")
        panic_title_font = gdi32.CreateFontW(34, 0, 0, 0, 700, 0, 0, 0, 1, 0, 0, 4, 0, "Segoe UI")
        panic_sub_font = gdi32.CreateFontW(20, 0, 0, 0, 400, 0, 0, 0, 1, 0, 0, 4, 0, "Segoe UI")

        def _overlay_wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_ERASEBKGND:
                return 1
            if msg == WM_PAINT:
                ps = PAINTSTRUCT()
                hdc = user32.BeginPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                try:
                    rc = wintypes.RECT()
                    user32.GetClientRect(wintypes.HWND(hwnd), ctypes.byref(rc))
                    cw = max(1, rc.right - rc.left)
                    ch = max(1, rc.bottom - rc.top)
                    with self._lock:
                        use_frost = self._config.mask_style == "blur"
                        frost_entry = self._overlay_frost.get(int(hwnd)) if use_frost else None

                    if frost_entry is not None:
                        raw, fw, fh = frost_entry
                        bmi = BITMAPINFO()
                        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
                        bmi.bmiHeader.biWidth = fw
                        bmi.bmiHeader.biHeight = -fh
                        bmi.bmiHeader.biPlanes = 1
                        bmi.bmiHeader.biBitCount = 32
                        bmi.bmiHeader.biCompression = 0
                        buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
                        gdi32.SetStretchBltMode(hdc, HALFTONE)
                        gdi32.StretchDIBits(
                            hdc,
                            0,
                            0,
                            cw,
                            ch,
                            0,
                            0,
                            fw,
                            fh,
                            ctypes.cast(buf, ctypes.c_void_p),
                            ctypes.byref(bmi),
                            DIB_RGB_COLORS,
                            SRCCOPY,
                        )
                    else:
                        user32.FillRect(hdc, ctypes.byref(rc), bg_brush)

                    # Draw 3px #245C46 border
                    for inset in range(3):
                        frame_rc = wintypes.RECT(
                            rc.left + inset,
                            rc.top + inset,
                            rc.right - inset,
                            rc.bottom - inset,
                        )
                        user32.FrameRect(hdc, ctypes.byref(frame_rc), border_brush)
                    label = self._overlay_labels.get(int(hwnd), "ScreenShield")
                    if (rc.right - rc.left) >= 120 and (rc.bottom - rc.top) >= 44:
                        old_font = gdi32.SelectObject(hdc, overlay_font)
                        gdi32.SetBkMode(hdc, TRANSPARENT_BK)
                        gdi32.SetTextColor(hdc, 0x00F0F5F7)  # #F7F5F0
                        text_rc = wintypes.RECT(rc.left + 12, rc.top + 8, rc.right - 12, rc.bottom - 8)
                        user32.DrawTextW(
                            hdc,
                            label,
                            -1,
                            ctypes.byref(text_rc),
                            DT_CENTER | DT_VCENTER | DT_SINGLELINE | DT_END_ELLIPSIS,
                        )
                        gdi32.SelectObject(hdc, old_font)
                finally:
                    user32.EndPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                return 0
            if msg == WM_APP_START:
                self._install_hooks()
                self._sync_all()
                return 0
            if msg == WM_APP_STOP:
                self._remove_hooks()
                self._hide_all_pool()
                return 0
            if msg == WM_APP_SYNC:
                self._sync_all()
                return 0
            if msg == WM_APP_PANIC:
                self._apply_panic_curtain(bool(wparam))
                return 0
            if msg == WM_APP_REFRESH_STYLE:
                for ohwnd in self._pool_hwnds:
                    user32.InvalidateRect(wintypes.HWND(ohwnd), None, False)
                if self._panic_hwnd:
                    user32.InvalidateRect(wintypes.HWND(self._panic_hwnd), None, False)
                return 0
            if msg == WM_TIMER and int(wparam) == HEARTBEAT_TIMER_ID:
                if self._active:
                    self._sync_all()
                return 0
            return user32.DefWindowProcW(wintypes.HWND(hwnd), msg, wparam, lparam)

        def _panic_wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_ERASEBKGND:
                return 1
            if msg == WM_PAINT:
                ps = PAINTSTRUCT()
                hdc = user32.BeginPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                try:
                    rc = wintypes.RECT()
                    user32.GetClientRect(wintypes.HWND(hwnd), ctypes.byref(rc))
                    user32.FillRect(hdc, ctypes.byref(rc), bg_brush)
                    for inset in range(12, 16):
                        frame_rc = wintypes.RECT(
                            rc.left + inset,
                            rc.top + inset,
                            rc.right - inset,
                            rc.bottom - inset,
                        )
                        user32.FrameRect(hdc, ctypes.byref(frame_rc), border_brush)

                    with self._lock:
                        lang = self._config.language
                    title, subtitle = CURTAIN_STRINGS.get(lang, CURTAIN_STRINGS["en"])["panic"]
                    cx = (rc.left + rc.right) // 2
                    cy = (rc.top + rc.bottom) // 2 - 40

                    # Shield polygon
                    pts = (wintypes.POINT * 6)(
                        wintypes.POINT(cx, cy - 56),
                        wintypes.POINT(cx + 46, cy - 32),
                        wintypes.POINT(cx + 38, cy + 16),
                        wintypes.POINT(cx, cy + 52),
                        wintypes.POINT(cx - 38, cy + 16),
                        wintypes.POINT(cx - 46, cy - 32),
                    )
                    old_brush = gdi32.SelectObject(hdc, border_brush)
                    gdi32.Polygon(hdc, pts, 6)
                    gdi32.SelectObject(hdc, old_brush)

                    gdi32.SetBkMode(hdc, TRANSPARENT_BK)
                    gdi32.SetTextColor(hdc, 0x00F0F5F7)

                    old_f = gdi32.SelectObject(hdc, panic_title_font)
                    t_rc = wintypes.RECT(rc.left + 40, cy + 70, rc.right - 40, cy + 120)
                    user32.DrawTextW(
                        hdc, title, -1, ctypes.byref(t_rc), DT_CENTER | DT_SINGLELINE
                    )
                    gdi32.SelectObject(hdc, old_f)

                    old_sf = gdi32.SelectObject(hdc, panic_sub_font)
                    s_rc = wintypes.RECT(rc.left + 40, cy + 124, rc.right - 40, cy + 164)
                    user32.DrawTextW(
                        hdc, subtitle, -1, ctypes.byref(s_rc), DT_CENTER | DT_SINGLELINE
                    )
                    gdi32.SelectObject(hdc, old_sf)
                finally:
                    user32.EndPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                return 0
            return user32.DefWindowProcW(wintypes.HWND(hwnd), msg, wparam, lparam)

        self._wndproc_ref = WNDPROC(_overlay_wnd_proc)
        self._panic_wndproc_ref = WNDPROC(_panic_wnd_proc)

        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.style = CS_HREDRAW | CS_VREDRAW
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinstance
        wc.hbrBackground = bg_brush
        wc.lpszClassName = self.OVERLAY_CLASS
        user32.RegisterClassExW(ctypes.byref(wc))

        pwc = WNDCLASSEXW()
        pwc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        pwc.style = CS_HREDRAW | CS_VREDRAW
        pwc.lpfnWndProc = self._panic_wndproc_ref
        pwc.hInstance = hinstance
        pwc.hbrBackground = bg_brush
        pwc.lpszClassName = self.PANIC_CLASS
        user32.RegisterClassExW(ctypes.byref(pwc))

        msg_hwnd = user32.CreateWindowExW(
            WS_EX_TOOLWINDOW,
            self.OVERLAY_CLASS,
            "ScreenShieldDirectHost",
            0,
            0,
            0,
            1,
            1,
            None,
            None,
            hinstance,
            None,
        )
        self._msg_hwnd = int(msg_hwnd or 0)
        if self._msg_hwnd:
            self._own_hwnds.add(self._msg_hwnd)

        for idx in range(POOL_SIZE):
            ohwnd = user32.CreateWindowExW(
                WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE | WS_EX_LAYERED,
                self.OVERLAY_CLASS,
                f"ScreenShield Overlay {idx}",
                WS_POPUP,
                0,
                0,
                100,
                100,
                None,
                None,
                hinstance,
                None,
            )
            if ohwnd:
                h_int = int(ohwnd)
                user32.SetLayeredWindowAttributes(wintypes.HWND(h_int), 0, 255, LWA_ALPHA)
                self._pool_hwnds.append(h_int)
                self._own_hwnds.add(h_int)

        panic_hwnd = user32.CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            self.PANIC_CLASS,
            "ScreenShield Panic Curtain",
            WS_POPUP,
            0,
            0,
            800,
            600,
            None,
            None,
            hinstance,
            None,
        )
        self._panic_hwnd = int(panic_hwnd or 0)
        if self._panic_hwnd:
            self._own_hwnds.add(self._panic_hwnd)

        self._ready.set()

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        self._remove_hooks()
        for h_int in [*self._pool_hwnds, self._panic_hwnd, self._msg_hwnd]:
            if h_int:
                user32.DestroyWindow(wintypes.HWND(h_int))
        self._pool_hwnds.clear()
        self._own_hwnds.clear()
        for gdi_obj in (bg_brush, border_brush, overlay_font, panic_title_font, panic_sub_font):
            if gdi_obj:
                gdi32.DeleteObject(gdi_obj)
