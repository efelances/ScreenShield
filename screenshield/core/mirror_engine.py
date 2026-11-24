"""Zero-leak Safe Share Mirror capture engine with Allowlist and Fail-Closed buffer."""

from __future__ import annotations

import ctypes
import io
import os
import threading
import time
from ctypes import wintypes

import mss
from PIL import Image

from screenshield.core.config import AppConfig
from screenshield.core.mirror_window import BITMAPINFO, BITMAPINFOHEADER, MirrorWindow
from screenshield.core.privacy_mask import (
    SafetyRingBuffer,
    apply_normalized_zones,
    apply_region_mask,
    render_curtain,
)
from screenshield.core.window_watcher import (
    WindowInfo,
    enumerate_windows,
    get_window_title,
    is_window_sensitive,
)


PW_RENDERFULLCONTENT = 0x00000002
DIB_RGB_COLORS = 0


def _setup_capture_signatures() -> None:
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    user32.GetDC.argtypes = [wintypes.HWND]
    user32.GetDC.restype = wintypes.HDC

    user32.ReleaseDC.argtypes = [wintypes.HWND, wintypes.HDC]
    user32.ReleaseDC.restype = ctypes.c_int

    user32.PrintWindow.argtypes = [wintypes.HWND, wintypes.HDC, wintypes.UINT]
    user32.PrintWindow.restype = wintypes.BOOL

    gdi32.CreateCompatibleDC.argtypes = [wintypes.HDC]
    gdi32.CreateCompatibleDC.restype = wintypes.HDC

    gdi32.DeleteDC.argtypes = [wintypes.HDC]
    gdi32.DeleteDC.restype = wintypes.BOOL

    gdi32.CreateDIBSection.argtypes = [
        wintypes.HDC,
        ctypes.POINTER(BITMAPINFO),
        wintypes.UINT,
        ctypes.POINTER(ctypes.c_void_p),
        wintypes.HANDLE,
        wintypes.DWORD,
    ]
    gdi32.CreateDIBSection.restype = wintypes.HBITMAP

    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ

    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteObject.restype = wintypes.BOOL


_setup_capture_signatures()


def capture_window_image(hwnd: int) -> Image.Image | None:
    """Capture a single window off-screen using Win32 PrintWindow + top-down DIB."""
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32

    if not user32.IsWindow(wintypes.HWND(hwnd)) or user32.IsIconic(wintypes.HWND(hwnd)):
        return None

    rect = wintypes.RECT()
    if not user32.GetWindowRect(wintypes.HWND(hwnd), ctypes.byref(rect)):
        return None

    width = int(rect.right - rect.left)
    height = int(rect.bottom - rect.top)
    if width < 2 or height < 2:
        return None

    hwnd_dc = user32.GetDC(wintypes.HWND(hwnd))
    if not hwnd_dc:
        return None
    mem_dc = gdi32.CreateCompatibleDC(hwnd_dc)
    if not mem_dc:
        user32.ReleaseDC(wintypes.HWND(hwnd), hwnd_dc)
        return None

    bmi = BITMAPINFO()
    bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
    bmi.bmiHeader.biWidth = width
    bmi.bmiHeader.biHeight = -height
    bmi.bmiHeader.biPlanes = 1
    bmi.bmiHeader.biBitCount = 32
    bmi.bmiHeader.biCompression = 0

    bits_ptr = ctypes.c_void_p()
    hbitmap = gdi32.CreateDIBSection(
        mem_dc, ctypes.byref(bmi), DIB_RGB_COLORS, ctypes.byref(bits_ptr), None, 0
    )
    if not hbitmap or not bits_ptr.value:
        if hbitmap:
            gdi32.DeleteObject(hbitmap)
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(wintypes.HWND(hwnd), hwnd_dc)
        return None

    old_obj = gdi32.SelectObject(mem_dc, hbitmap)
    try:
        ok = bool(user32.PrintWindow(wintypes.HWND(hwnd), mem_dc, PW_RENDERFULLCONTENT))
        if not ok:
            ok = bool(user32.PrintWindow(wintypes.HWND(hwnd), mem_dc, 0))
        if not ok:
            return None
        byte_count = width * height * 4
        raw = ctypes.string_at(bits_ptr.value, byte_count)
        return Image.frombytes("RGBA", (width, height), raw, "raw", "BGRA").convert("RGB")
    finally:
        gdi32.SelectObject(mem_dc, old_obj)
        gdi32.DeleteObject(hbitmap)
        gdi32.DeleteDC(mem_dc)
        user32.ReleaseDC(wintypes.HWND(hwnd), hwnd_dc)


class MirrorEngine:
    """Runs the capture, redaction, safety buffer, and fail-closed mirror pipeline."""

    def __init__(self, mirror_window: MirrorWindow, initial_config: AppConfig) -> None:
        self.mirror_window = mirror_window
        self._lock = threading.RLock()
        self._config = initial_config
        self._ring = SafetyRingBuffer(delay_ms=initial_config.buffer_delay_ms)
        self._sharing = False
        self._panic = False
        self._status_reason = "idle"
        self._sensitive_blocks = 0
        self._fail_closed_count = 0
        self._actual_fps = 0.0
        self._preview_jpeg: bytes = self._encode_jpeg(
            render_curtain(
                960,
                540,
                "idle",
                language=initial_config.language,
                high_contrast=initial_config.high_contrast,
            )
        )
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None

    @staticmethod
    def _encode_jpeg(image: Image.Image) -> bytes:
        preview = image.copy()
        preview.thumbnail((960, 540), Image.Resampling.BILINEAR)
        buf = io.BytesIO()
        preview.save(buf, format="JPEG", quality=80)
        return buf.getvalue()

    def update_config(self, config: AppConfig) -> None:
        with self._lock:
            self._config = config
            self._ring.set_delay_ms(config.buffer_delay_ms)
            if not self._sharing and not self._panic:
                curtain = render_curtain(
                    960,
                    540,
                    "idle",
                    language=config.language,
                    high_contrast=config.high_contrast,
                )
                self._preview_jpeg = self._encode_jpeg(curtain)

    def start_sharing(self) -> None:
        with self._lock:
            self._sharing = True
            self._ring.flush()
        self.mirror_window.show()
        self._ensure_thread()

    def stop_sharing(self) -> None:
        with self._lock:
            self._sharing = False
            self._ring.flush()
            self._status_reason = "panic" if self._panic else "idle"
            curtain = render_curtain(
                960,
                540,
                "panic" if self._panic else "idle",
                language=self._config.language,
                high_contrast=self._config.high_contrast,
            )
            self._preview_jpeg = self._encode_jpeg(curtain)
        self.mirror_window.hide()

    def set_panic(self, active: bool) -> None:
        with self._lock:
            self._panic = active
            self._ring.flush()
            if active:
                self._status_reason = "panic"
                curtain = render_curtain(
                    960,
                    540,
                    "panic",
                    language=self._config.language,
                    high_contrast=self._config.high_contrast,
                )
                self._emit_frame(curtain)

    def _emit_frame(self, frame: Image.Image) -> None:
        self.mirror_window.update_frame(frame)
        self._preview_jpeg = self._encode_jpeg(frame)

    def _ensure_thread(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._stop_event.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="ScreenShieldMirrorEngine", daemon=True
            )
            self._thread.start()

    def stop(self) -> None:
        self._stop_event.set()
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def get_preview_jpeg(self) -> bytes:
        with self._lock:
            return self._preview_jpeg

    def get_metrics(self) -> dict[str, object]:
        with self._lock:
            return {
                "sharing": self._sharing,
                "panic": self._panic,
                "status_reason": self._status_reason,
                "actual_fps": round(self._actual_fps, 1),
                "buffer_delay_ms": self._ring.delay_ms,
                "buffered_frames": self._ring.size,
                "sensitive_blocks": self._sensitive_blocks,
                "fail_closed_count": self._fail_closed_count,
            }

    def _select_allowlist_window(
        self, allowlist_hwnds: list[int], visible_windows: list[WindowInfo]
    ) -> WindowInfo | None:
        allowed_set = set(allowlist_hwnds)
        candidates = [w for w in visible_windows if w.hwnd in allowed_set and not w.is_minimized]
        if not candidates:
            return None
        # Prefer foreground window if allowlisted, otherwise highest Z-order.
        for cand in candidates:
            if cand.is_foreground:
                return cand
        return candidates[0]

    def _capture_allowlist_step(self, cfg: AppConfig, visible: list[WindowInfo]) -> tuple[Image.Image | None, str | None]:
        target = self._select_allowlist_window(cfg.allowlist_hwnds, visible)
        if target is None:
            return None, "waiting_window"

        sensitive, _reasons = is_window_sensitive(target, cfg.rules)
        if sensitive:
            return None, "sensitive_blocked"

        frame = capture_window_image(target.hwnd)
        if frame is None:
            return None, "fail_closed"

        # Re-check title right after PrintWindow to close any title-update race window.
        post_title = get_window_title(target.hwnd)
        post_win = WindowInfo(
            hwnd=target.hwnd,
            title=post_title or target.title,
            process_name=target.process_name,
            pid=target.pid,
            rect=target.rect,
            is_minimized=target.is_minimized,
            is_foreground=target.is_foreground,
            z_order=target.z_order,
        )
        post_sensitive, _ = is_window_sensitive(post_win, cfg.rules)
        if post_sensitive:
            return None, "sensitive_blocked"

        apply_normalized_zones(frame, cfg.zones)
        return frame, None

    def _capture_monitor_redact_step(
        self, sct: mss.mss, cfg: AppConfig, visible: list[WindowInfo]
    ) -> tuple[Image.Image | None, str | None]:
        monitors = sct.monitors
        idx = cfg.monitor_index if 1 <= cfg.monitor_index < len(monitors) else 1
        mon = monitors[idx]
        raw = sct.grab(mon)
        frame = Image.frombytes("RGB", raw.size, raw.bgra, "raw", "BGRX")

        mon_left = int(mon["left"])
        mon_top = int(mon["top"])
        own_pid = os.getpid()

        # Enumerate including own windows so ScreenShield's own windows are masked on the monitor feed.
        all_visible = enumerate_windows(exclude_own_pid=False)
        for win in all_visible:
            if win.is_minimized:
                continue
            redact = win.pid == own_pid
            label = "ScreenShield" if win.pid == own_pid else None
            if not redact:
                sensitive, reasons = is_window_sensitive(win, cfg.rules)
                if sensitive:
                    redact = True
                    label = reasons[0] if reasons else "Shielded"
            if redact:
                box = (
                    win.rect[0] - mon_left,
                    win.rect[1] - mon_top,
                    win.rect[2] - mon_left,
                    win.rect[3] - mon_top,
                )
                apply_region_mask(frame, box, style=cfg.mask_style, label=label)

        apply_normalized_zones(frame, cfg.zones)
        return frame, None

    def _run_loop(self) -> None:
        fps_counter = 0
        fps_window_start = time.monotonic()

        with mss.mss() as sct:
            while not self._stop_event.is_set():
                loop_start = time.monotonic()
                with self._lock:
                    cfg = self._config
                    sharing = self._sharing
                    panic = self._panic

                if not sharing:
                    time.sleep(0.08)
                    continue

                if panic:
                    self._ring.flush()
                    curtain = render_curtain(
                        960,
                        540,
                        "panic",
                        language=cfg.language,
                        high_contrast=cfg.high_contrast,
                    )
                    with self._lock:
                        self._status_reason = "panic"
                        self._emit_frame(curtain)
                    time.sleep(0.1)
                    continue

                try:
                    visible = enumerate_windows(exclude_own_pid=True)
                    if cfg.mirror_mode == "allowlist":
                        frame, block_kind = self._capture_allowlist_step(cfg, visible)
                    else:
                        frame, block_kind = self._capture_monitor_redact_step(sct, cfg, visible)

                    if block_kind is not None or frame is None:
                        self._ring.flush()
                        kind = block_kind or "fail_closed"
                        curtain = render_curtain(
                            960,
                            540,
                            kind,  # type: ignore[arg-type]
                            language=cfg.language,
                            high_contrast=cfg.high_contrast,
                        )
                        with self._lock:
                            self._status_reason = kind
                            if kind == "sensitive_blocked":
                                self._sensitive_blocks += 1
                            elif kind == "fail_closed":
                                self._fail_closed_count += 1
                            self._emit_frame(curtain)
                    else:
                        now = time.monotonic()
                        self._ring.push(frame, now=now)
                        ready = self._ring.pop_ready(now=now)
                        with self._lock:
                            self._status_reason = "streaming"
                            if ready is not None:
                                self._emit_frame(ready)
                except Exception:
                    # Fail-closed guarantee: flush safety buffer and show shielded standby.
                    self._ring.flush()
                    curtain = render_curtain(
                        960,
                        540,
                        "fail_closed",
                        language=cfg.language,
                        high_contrast=cfg.high_contrast,
                    )
                    with self._lock:
                        self._status_reason = "fail_closed"
                        self._fail_closed_count += 1
                        self._emit_frame(curtain)

                fps_counter += 1
                elapsed_fps = time.monotonic() - fps_window_start
                if elapsed_fps >= 1.0:
                    with self._lock:
                        self._actual_fps = fps_counter / elapsed_fps
                    fps_counter = 0
                    fps_window_start = time.monotonic()

                target_interval = 1.0 / max(5, cfg.fps)
                sleep_for = target_interval - (time.monotonic() - loop_start)
                if sleep_for > 0:
                    time.sleep(sleep_for)
