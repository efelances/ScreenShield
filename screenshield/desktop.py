"""Desktop pywebview launcher and localhost Uvicorn server lifecycle."""

from __future__ import annotations

import os
import socket
import threading
import time

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


def run_desktop(port: int = 0) -> int:
    """Launch ScreenShield as a standalone pywebview desktop application."""
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
    return 0
