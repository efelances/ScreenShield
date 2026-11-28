"""Desktop pywebview launcher and localhost Uvicorn server lifecycle."""

from __future__ import annotations

import ctypes
import os
import socket
import threading
import time
from ctypes import wintypes

import uvicorn
import webview

from screenshield.assets import ensure_icon_file
from screenshield.core.config import ConfigStore
from screenshield.core.controller import ShieldController
from screenshield.core.window_watcher import find_hwnd_by_title_and_pid
from screenshield.server import AuthState, create_app


def _find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return int(sock.getsockname()[1])


def _wait_for_port(port: int, timeout_s: float = 5.0) -> None:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            if sock.connect_ex(("127.0.0.1", port)) == 0:
                return
        time.sleep(0.05)


def run_headless(port: int = 8765) -> int:
    """Run only the localhost FastAPI server (for testing or browser inspection)."""
    target_port = port if port > 0 else _find_free_port()
    store = ConfigStore()
    controller = ShieldController(store=store)
    auth = AuthState()
    app = create_app(controller, auth=auth)
    bootstrap_url = f"http://127.0.0.1:{target_port}/auth/bootstrap?token={auth.bootstrap_token}"
    print(f"ScreenShield headless listening on {bootstrap_url}")
    try:
        uvicorn.run(
            app,
            host="127.0.0.1",
            port=target_port,
            log_config=None,
            access_log=False,
        )
    finally:
        controller.shutdown()
    return 0


_MUTEX_NAME = "Local\\ScreenShieldSingleInstance"
_ERROR_ALREADY_EXISTS = 183
_SW_RESTORE = 9


def _acquire_single_instance_mutex() -> int | None:
    """Acquire a per-session named mutex; returns handle or None if already running."""
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateMutexW.argtypes = [ctypes.c_void_p, wintypes.BOOL, wintypes.LPCWSTR]
    kernel32.CreateMutexW.restype = wintypes.HANDLE
    kernel32.GetLastError.argtypes = []
    kernel32.GetLastError.restype = wintypes.DWORD
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    kernel32.CloseHandle.restype = wintypes.BOOL

    handle = kernel32.CreateMutexW(None, False, _MUTEX_NAME)
    if handle and kernel32.GetLastError() == _ERROR_ALREADY_EXISTS:
        kernel32.CloseHandle(handle)
        return None
    return int(handle or 0)


def _focus_existing_instance() -> None:
    hwnd = find_hwnd_by_title_and_pid("ScreenShield — Control Panel", pid=None)
    if hwnd:
        user32 = ctypes.windll.user32
        user32.ShowWindow.argtypes = [wintypes.HWND, ctypes.c_int]
        user32.ShowWindow.restype = wintypes.BOOL
        user32.SetForegroundWindow.argtypes = [wintypes.HWND]
        user32.SetForegroundWindow.restype = wintypes.BOOL
        user32.ShowWindow(wintypes.HWND(hwnd), _SW_RESTORE)
        user32.SetForegroundWindow(wintypes.HWND(hwnd))


def run_desktop(port: int = 0) -> int:
    """Launch ScreenShield as a standalone pywebview desktop application."""
    mutex_handle = _acquire_single_instance_mutex()
    if mutex_handle is None:
        _focus_existing_instance()
        return 0

    target_port = port if port > 0 else _find_free_port()
    store = ConfigStore()
    icon_path = ensure_icon_file(store.data_dir / "screenshield.ico")
    controller = ShieldController(store=store)
    auth = AuthState()
    app = create_app(controller, auth=auth)

    uvi_config = uvicorn.Config(
        app,
        host="127.0.0.1",
        port=target_port,
        log_config=None,
        access_log=False,
    )
    server = uvicorn.Server(uvi_config)
    server_thread = threading.Thread(target=server.run, name="ScreenShieldServer", daemon=True)
    server_thread.start()
    _wait_for_port(target_port)

    bootstrap_url = f"http://127.0.0.1:{target_port}/auth/bootstrap?token={auth.bootstrap_token}"
    bg_color = "#1C1B19" if controller.config.theme == "dark" else "#F7F5F0"
    window = webview.create_window(
        "ScreenShield — Control Panel",
        url=bootstrap_url,
        width=1160,
        height=780,
        min_size=(860, 620),
        background_color=bg_color,
    )

    def _on_shown() -> None:
        hwnd = find_hwnd_by_title_and_pid("ScreenShield — Control Panel", os.getpid())
        if hwnd:
            controller.set_control_window_hwnd(hwnd)

    if window is not None:
        window.events.shown += _on_shown

    try:
        webview.start(icon=str(icon_path))
    finally:
        server.should_exit = True
        controller.shutdown()
        if mutex_handle:
            ctypes.windll.kernel32.CloseHandle(wintypes.HANDLE(mutex_handle))
    return 0
