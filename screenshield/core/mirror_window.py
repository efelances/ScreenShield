"""Native Win32 Safe Share Mirror window and Static Zone desktop overlays."""

from __future__ import annotations

import ctypes
import threading
from ctypes import wintypes
from typing import Callable

from PIL import Image

from screenshield.core.config import StaticZone


WS_OVERLAPPEDWINDOW = 0x00CF0000
WS_VISIBLE = 0x10000000
WS_POPUP = 0x80000000
WS_EX_TOPMOST = 0x00000008
WS_EX_TRANSPARENT = 0x00000020
WS_EX_TOOLWINDOW = 0x00000080
WS_EX_LAYERED = 0x00080000
WS_EX_NOACTIVATE = 0x08000000

SW_SHOWNOACTIVATE = 4
SW_HIDE = 0
SW_RESTORE = 9
SWP_NOACTIVATE = 0x0010
SWP_NOMOVE = 0x0002
SWP_NOSIZE = 0x0001
HWND_TOPMOST = -1
HWND_BOTTOM = 1

WM_DESTROY = 0x0002
WM_CLOSE = 0x0010
WM_PAINT = 0x000F
WM_ERASEBKGND = 0x0014
WM_SYSCOMMAND = 0x0112
SC_MINIMIZE = 0xF020
WM_QUIT = 0x0012
WM_APP_FRAME = 0x8002
WM_APP_SHOW = 0x8003
WM_APP_HIDE = 0x8004
WM_APP_SYNC_ZONES = 0x8005
WM_APP_SEND_BACK = 0x8006

SRCCOPY = 0x00CC0020
DIB_RGB_COLORS = 0
HALFTONE = 4
LWA_ALPHA = 0x00000002

SM_CXSCREEN = 0
SM_CYSCREEN = 1

WNDPROC = ctypes.WINFUNCTYPE(
    ctypes.c_ssize_t, wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM
)


class WNDCLASSEXW(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("style", wintypes.UINT),
        ("lpfnWndProc", WNDPROC),
        ("cbClsExtra", ctypes.c_int),
        ("cbWndExtra", ctypes.c_int),
        ("hInstance", wintypes.HINSTANCE),
        ("hIcon", wintypes.HICON),
        ("hCursor", wintypes.HANDLE),
        ("hbrBackground", wintypes.HBRUSH),
        ("lpszMenuName", wintypes.LPCWSTR),
        ("lpszClassName", wintypes.LPCWSTR),
        ("hIconSm", wintypes.HICON),
    ]


class PAINTSTRUCT(ctypes.Structure):
    _fields_ = [
        ("hdc", wintypes.HDC),
        ("fErase", wintypes.BOOL),
        ("rcPaint", wintypes.RECT),
        ("fRestore", wintypes.BOOL),
        ("fIncUpdate", wintypes.BOOL),
        ("rgbReserved", ctypes.c_byte * 32),
    ]


class BITMAPINFOHEADER(ctypes.Structure):
    _fields_ = [
        ("biSize", wintypes.DWORD),
        ("biWidth", wintypes.LONG),
        ("biHeight", wintypes.LONG),
        ("biPlanes", wintypes.WORD),
        ("biBitCount", wintypes.WORD),
        ("biCompression", wintypes.DWORD),
        ("biSizeImage", wintypes.DWORD),
        ("biXPelsPerMeter", wintypes.LONG),
        ("biYPelsPerMeter", wintypes.LONG),
        ("biClrUsed", wintypes.DWORD),
        ("biClrImportant", wintypes.DWORD),
    ]


class BITMAPINFO(ctypes.Structure):
    _fields_ = [
        ("bmiHeader", BITMAPINFOHEADER),
        ("bmiColors", wintypes.DWORD * 3),
    ]


def _setup_win32_signatures() -> None:
    user32 = ctypes.windll.user32
    gdi32 = ctypes.windll.gdi32
    kernel32 = ctypes.windll.kernel32

    kernel32.GetModuleHandleW.argtypes = [wintypes.LPCWSTR]
    kernel32.GetModuleHandleW.restype = wintypes.HMODULE

    kernel32.GetCurrentThreadId.argtypes = []
    kernel32.GetCurrentThreadId.restype = wintypes.DWORD

    gdi32.CreateSolidBrush.argtypes = [wintypes.COLORREF]
    gdi32.CreateSolidBrush.restype = wintypes.HBRUSH

    gdi32.SelectObject.argtypes = [wintypes.HDC, wintypes.HGDIOBJ]
    gdi32.SelectObject.restype = wintypes.HGDIOBJ

    gdi32.DeleteObject.argtypes = [wintypes.HGDIOBJ]
    gdi32.DeleteObject.restype = wintypes.BOOL

    user32.RegisterClassExW.argtypes = [ctypes.POINTER(WNDCLASSEXW)]
    user32.RegisterClassExW.restype = wintypes.ATOM

    user32.CreateWindowExW.argtypes = [
        wintypes.DWORD,
        wintypes.LPCWSTR,
        wintypes.LPCWSTR,
        wintypes.DWORD,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.HWND,
        wintypes.HMENU,
        wintypes.HINSTANCE,
        wintypes.LPVOID,
    ]
    user32.CreateWindowExW.restype = wintypes.HWND

    user32.DestroyWindow.argtypes = [wintypes.HWND]
    user32.DestroyWindow.restype = wintypes.BOOL

    user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
    user32.ShowWindow.restype = wintypes.BOOL

    user32.InvalidateRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT), wintypes.BOOL]
    user32.InvalidateRect.restype = wintypes.BOOL

    user32.SetLayeredWindowAttributes.argtypes = [
        wintypes.HWND,
        wintypes.COLORREF,
        ctypes.c_ubyte,
        wintypes.DWORD,
    ]
    user32.SetLayeredWindowAttributes.restype = wintypes.BOOL

    user32.GetMessageW.argtypes = [
        ctypes.POINTER(wintypes.MSG),
        wintypes.HWND,
        wintypes.UINT,
        wintypes.UINT,
    ]
    user32.GetMessageW.restype = ctypes.c_int

    user32.TranslateMessage.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.TranslateMessage.restype = wintypes.BOOL

    user32.DispatchMessageW.argtypes = [ctypes.POINTER(wintypes.MSG)]
    user32.DispatchMessageW.restype = ctypes.c_ssize_t

    user32.PostThreadMessageW.argtypes = [
        wintypes.DWORD,
        wintypes.UINT,
        wintypes.WPARAM,
        wintypes.LPARAM,
    ]
    user32.PostThreadMessageW.restype = wintypes.BOOL

    user32.DefWindowProcW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.DefWindowProcW.restype = ctypes.c_ssize_t

    user32.BeginPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
    user32.BeginPaint.restype = wintypes.HDC

    user32.EndPaint.argtypes = [wintypes.HWND, ctypes.POINTER(PAINTSTRUCT)]
    user32.EndPaint.restype = wintypes.BOOL

    user32.FillRect.argtypes = [wintypes.HDC, ctypes.POINTER(wintypes.RECT), wintypes.HBRUSH]
    user32.FillRect.restype = ctypes.c_int

    user32.GetClientRect.argtypes = [wintypes.HWND, ctypes.POINTER(wintypes.RECT)]
    user32.GetClientRect.restype = wintypes.BOOL

    user32.PostMessageW.argtypes = [wintypes.HWND, wintypes.UINT, wintypes.WPARAM, wintypes.LPARAM]
    user32.PostMessageW.restype = wintypes.BOOL

    user32.SetWindowPos.argtypes = [
        wintypes.HWND,
        wintypes.HWND,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        wintypes.UINT,
    ]
    user32.SetWindowPos.restype = wintypes.BOOL

    user32.IsIconic.argtypes = [wintypes.HWND]
    user32.IsIconic.restype = wintypes.BOOL

    gdi32.SetStretchBltMode.argtypes = [wintypes.HDC, ctypes.c_int]
    gdi32.SetStretchBltMode.restype = ctypes.c_int

    gdi32.StretchDIBits.argtypes = [
        wintypes.HDC,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_int,
        ctypes.c_void_p,
        ctypes.POINTER(BITMAPINFO),
        wintypes.UINT,
        wintypes.DWORD,
    ]
    gdi32.StretchDIBits.restype = ctypes.c_int


_setup_win32_signatures()


class MirrorWindow:
    """Dedicated Win32 window displaying the Safe Share Mirror output."""

    CLASS_NAME = "ScreenShieldMirrorWindow"
    WINDOW_TITLE = "ScreenShield — Safe Mirror (Share This)"

    def __init__(self, on_user_close: Callable[[], None] | None = None) -> None:
        self._on_user_close = on_user_close
        self._lock = threading.Lock()
        self._frame_bgra: bytes | None = None
        self._frame_w = 0
        self._frame_h = 0
        self._hwnd: int = 0
        self._thread: threading.Thread | None = None
        self._thread_id: int = 0
        self._ready = threading.Event()
        self._visible = False
        self._wndproc_ref: WNDPROC | None = None

    @property
    def hwnd(self) -> int:
        return self._hwnd

    @property
    def is_visible(self) -> bool:
        return self._visible

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._ready.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="ScreenShieldMirrorWindow", daemon=True
            )
            self._thread.start()
        self._ready.wait(timeout=3.0)

    def show(self) -> None:
        self.start()
        if self._hwnd:
            self._visible = True
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._hwnd), WM_APP_SHOW, 0, 0)

    def hide(self) -> None:
        self._visible = False
        if self._hwnd:
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._hwnd), WM_APP_HIDE, 0, 0)

    def send_to_back(self) -> None:
        """Push mirror window behind other windows without minimizing it."""
        if self._hwnd and self._visible:
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._hwnd), WM_APP_SEND_BACK, 0, 0)

    def update_frame(self, image: Image.Image) -> None:
        rgba = image if image.mode == "RGBA" else image.convert("RGBA")
        raw = rgba.tobytes("raw", "BGRA")
        with self._lock:
            self._frame_bgra = raw
            self._frame_w, self._frame_h = rgba.size
        if self._hwnd and self._visible:
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._hwnd), WM_APP_FRAME, 0, 0)

    def stop(self) -> None:
        tid = self._thread_id
        if tid:
            ctypes.windll.user32.PostThreadMessageW(tid, WM_QUIT, 0, 0)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def _run_loop(self) -> None:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        kernel32 = ctypes.windll.kernel32
        hinstance = kernel32.GetModuleHandleW(None)
        self._thread_id = int(kernel32.GetCurrentThreadId())

        # #1C1B19 in COLORREF (0x00BBGGRR)
        bg_brush = gdi32.CreateSolidBrush(0x00191B1C)

        def _wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_ERASEBKGND:
                return 1
            if msg == WM_SYSCOMMAND:
                if (int(wparam) & 0xFFF0) == SC_MINIMIZE and self._visible:
                    # Never let Windows minimize the active mirror; push it behind instead
                    # so Discord/Zoom/OBS keep receiving live frames without "Stream Paused".
                    user32.SetWindowPos(
                        wintypes.HWND(hwnd),
                        wintypes.HWND(HWND_BOTTOM),
                        0,
                        0,
                        0,
                        0,
                        SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                    )
                    return 0
            if msg == WM_APP_SHOW:
                if user32.IsIconic(wintypes.HWND(hwnd)):
                    user32.ShowWindow(wintypes.HWND(hwnd), SW_RESTORE)
                user32.ShowWindow(wintypes.HWND(hwnd), SW_SHOWNOACTIVATE)
                user32.InvalidateRect(wintypes.HWND(hwnd), None, False)
                return 0
            if msg == WM_APP_SEND_BACK:
                user32.SetWindowPos(
                    wintypes.HWND(hwnd),
                    wintypes.HWND(HWND_BOTTOM),
                    0,
                    0,
                    0,
                    0,
                    SWP_NOMOVE | SWP_NOSIZE | SWP_NOACTIVATE,
                )
                return 0
            if msg == WM_APP_HIDE:
                user32.ShowWindow(wintypes.HWND(hwnd), SW_HIDE)
                return 0
            if msg == WM_APP_FRAME:
                user32.InvalidateRect(wintypes.HWND(hwnd), None, False)
                return 0
            if msg == WM_PAINT:
                ps = PAINTSTRUCT()
                hdc = user32.BeginPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                try:
                    client = wintypes.RECT()
                    user32.GetClientRect(wintypes.HWND(hwnd), ctypes.byref(client))
                    cw = max(1, client.right - client.left)
                    ch = max(1, client.bottom - client.top)

                    with self._lock:
                        raw = self._frame_bgra
                        fw = self._frame_w
                        fh = self._frame_h

                    if not raw or fw <= 0 or fh <= 0:
                        user32.FillRect(hdc, ctypes.byref(client), bg_brush)
                    else:
                        scale = min(cw / fw, ch / fh)
                        dw = max(1, int(round(fw * scale)))
                        dh = max(1, int(round(fh * scale)))
                        dx = (cw - dw) // 2
                        dy = (ch - dh) // 2

                        if dx > 0 or dy > 0:
                            user32.FillRect(hdc, ctypes.byref(client), bg_brush)

                        bmi = BITMAPINFO()
                        bmi.bmiHeader.biSize = ctypes.sizeof(BITMAPINFOHEADER)
                        bmi.bmiHeader.biWidth = fw
                        bmi.bmiHeader.biHeight = -fh  # top-down DIB
                        bmi.bmiHeader.biPlanes = 1
                        bmi.bmiHeader.biBitCount = 32
                        bmi.bmiHeader.biCompression = 0

                        buf = (ctypes.c_ubyte * len(raw)).from_buffer_copy(raw)
                        gdi32.SetStretchBltMode(hdc, HALFTONE)
                        gdi32.StretchDIBits(
                            hdc,
                            dx,
                            dy,
                            dw,
                            dh,
                            0,
                            0,
                            fw,
                            fh,
                            ctypes.cast(buf, ctypes.c_void_p),
                            ctypes.byref(bmi),
                            DIB_RGB_COLORS,
                            SRCCOPY,
                        )
                finally:
                    user32.EndPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                return 0
            if msg == WM_CLOSE:
                self._visible = False
                user32.ShowWindow(wintypes.HWND(hwnd), SW_HIDE)
                if self._on_user_close is not None:
                    try:
                        self._on_user_close()
                    except Exception:
                        pass
                return 0
            if msg == WM_DESTROY:
                user32.PostQuitMessage(0)
                return 0
            return user32.DefWindowProcW(wintypes.HWND(hwnd), msg, wparam, lparam)

        self._wndproc_ref = WNDPROC(_wnd_proc)
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinstance
        wc.hbrBackground = bg_brush
        wc.lpszClassName = self.CLASS_NAME
        user32.RegisterClassExW(ctypes.byref(wc))

        hwnd = user32.CreateWindowExW(
            0,
            self.CLASS_NAME,
            self.WINDOW_TITLE,
            WS_OVERLAPPEDWINDOW,
            100,
            100,
            960,
            560,
            None,
            None,
            hinstance,
            None,
        )
        self._hwnd = int(hwnd or 0)
        self._ready.set()

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        if bg_brush:
            gdi32.DeleteObject(bg_brush)
        if border_brush:
            gdi32.DeleteObject(border_brush)


class StaticZoneOverlayManager:
    """Manages topmost click-through privacy rectangles on the primary monitor."""

    CLASS_NAME = "ScreenShieldZoneOverlay"

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._zones: list[StaticZone] = []
        self._enabled = False
        self._hwnds: list[int] = []
        self._thread: threading.Thread | None = None
        self._thread_id: int = 0
        self._msg_hwnd: int = 0
        self._ready = threading.Event()
        self._wndproc_ref: WNDPROC | None = None

    @property
    def is_active(self) -> bool:
        return self._enabled

    def start(self) -> None:
        with self._lock:
            if self._thread is not None and self._thread.is_alive():
                return
            self._ready.clear()
            self._thread = threading.Thread(
                target=self._run_loop, name="ScreenShieldZoneOverlays", daemon=True
            )
            self._thread.start()
        self._ready.wait(timeout=2.0)

    def sync(self, zones: list[StaticZone], active: bool) -> None:
        self.start()
        with self._lock:
            self._zones = list(zones)
            self._enabled = bool(active)
        if self._msg_hwnd:
            ctypes.windll.user32.PostMessageW(wintypes.HWND(self._msg_hwnd), WM_APP_SYNC_ZONES, 0, 0)

    def stop(self) -> None:
        tid = self._thread_id
        if tid:
            ctypes.windll.user32.PostThreadMessageW(tid, WM_QUIT, 0, 0)
        thread = self._thread
        if thread is not None and thread.is_alive():
            thread.join(timeout=2.0)

    def _rebuild_overlays(self) -> None:
        user32 = ctypes.windll.user32
        kernel32 = ctypes.windll.kernel32
        hinstance = kernel32.GetModuleHandleW(None)

        for hwnd in self._hwnds:
            user32.DestroyWindow(wintypes.HWND(hwnd))
        self._hwnds.clear()

        with self._lock:
            if not self._enabled:
                return
            zones = [z for z in self._zones if z.enabled]

        screen_w = int(user32.GetSystemMetrics(SM_CXSCREEN) or 1920)
        screen_h = int(user32.GetSystemMetrics(SM_CYSCREEN) or 1080)

        for zone in zones:
            x = max(0, int(round(zone.x * screen_w)))
            y = max(0, int(round(zone.y * screen_h)))
            w = max(20, int(round(zone.width * screen_w)))
            h = max(20, int(round(zone.height * screen_h)))
            hwnd = user32.CreateWindowExW(
                WS_EX_TOPMOST | WS_EX_TOOLWINDOW | WS_EX_TRANSPARENT | WS_EX_LAYERED | WS_EX_NOACTIVATE,
                self.CLASS_NAME,
                f"ScreenShield Zone - {zone.label}",
                WS_POPUP | WS_VISIBLE,
                x,
                y,
                w,
                h,
                None,
                None,
                hinstance,
                None,
            )
            if hwnd:
                user32.SetLayeredWindowAttributes(wintypes.HWND(hwnd), 0, 255, LWA_ALPHA)
                user32.SetWindowPos(
                    wintypes.HWND(hwnd),
                    wintypes.HWND(HWND_TOPMOST),
                    x,
                    y,
                    w,
                    h,
                    SWP_NOACTIVATE,
                )
                self._hwnds.append(int(hwnd))

    def _run_loop(self) -> None:
        user32 = ctypes.windll.user32
        gdi32 = ctypes.windll.gdi32
        kernel32 = ctypes.windll.kernel32
        hinstance = kernel32.GetModuleHandleW(None)
        self._thread_id = int(kernel32.GetCurrentThreadId())
        bg_brush = gdi32.CreateSolidBrush(0x00191B1C)
        border_brush = gdi32.CreateSolidBrush(0x00465C24)

        def _wnd_proc(hwnd: int, msg: int, wparam: int, lparam: int) -> int:
            if msg == WM_APP_SYNC_ZONES:
                self._rebuild_overlays()
                return 0
            if msg == WM_PAINT:
                ps = PAINTSTRUCT()
                hdc = user32.BeginPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                try:
                    rc = wintypes.RECT()
                    user32.GetClientRect(wintypes.HWND(hwnd), ctypes.byref(rc))
                    user32.FillRect(hdc, ctypes.byref(rc), bg_brush)
                    for inset in range(2):
                        frame_rc = wintypes.RECT(
                            rc.left + inset,
                            rc.top + inset,
                            rc.right - inset,
                            rc.bottom - inset,
                        )
                        user32.FrameRect(hdc, ctypes.byref(frame_rc), border_brush)
                finally:
                    user32.EndPaint(wintypes.HWND(hwnd), ctypes.byref(ps))
                return 0
            return user32.DefWindowProcW(wintypes.HWND(hwnd), msg, wparam, lparam)

        self._wndproc_ref = WNDPROC(_wnd_proc)
        wc = WNDCLASSEXW()
        wc.cbSize = ctypes.sizeof(WNDCLASSEXW)
        wc.lpfnWndProc = self._wndproc_ref
        wc.hInstance = hinstance
        wc.hbrBackground = bg_brush
        wc.lpszClassName = self.CLASS_NAME
        user32.RegisterClassExW(ctypes.byref(wc))

        msg_hwnd = user32.CreateWindowExW(
            WS_EX_TOOLWINDOW,
            self.CLASS_NAME,
            "ScreenShieldZoneHost",
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
        self._ready.set()

        msg = wintypes.MSG()
        while user32.GetMessageW(ctypes.byref(msg), None, 0, 0) > 0:
            user32.TranslateMessage(ctypes.byref(msg))
            user32.DispatchMessageW(ctypes.byref(msg))

        for hwnd in self._hwnds:
            user32.DestroyWindow(wintypes.HWND(hwnd))
        self._hwnds.clear()
        if bg_brush:
            gdi32.DeleteObject(bg_brush)
        if border_brush:
            gdi32.DeleteObject(border_brush)
