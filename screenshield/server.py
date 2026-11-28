"""Localhost-only FastAPI server with session cookie auth and CSP security headers."""

from __future__ import annotations

import secrets
import sys
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field

from screenshield.core.controller import ShieldController


SESSION_COOKIE_NAME = "screenshield_session"
CSRF_HEADER_NAME = "x-screenshield-csrf"
_MUTATING_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_ALLOWED_LOCAL_HOSTS = {"127.0.0.1", "localhost"}


class AuthState:
    """Holds per-process session secret and single-use bootstrap token."""

    def __init__(self) -> None:
        self.session_token: str = secrets.token_urlsafe(32)
        self.bootstrap_token: str | None = secrets.token_urlsafe(32)

    def consume_bootstrap(self, candidate: str) -> bool:
        if not candidate or self.bootstrap_token is None:
            return False
        ok = secrets.compare_digest(candidate, self.bootstrap_token)
        if ok:
            self.bootstrap_token = None
        return ok

    def validate_session(self, candidate: str | None) -> bool:
        if not candidate:
            return False
        return secrets.compare_digest(candidate, self.session_token)


def get_web_dir() -> Path:
    """Resolve web asset directory for source and PyInstaller frozen builds."""
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        candidate = Path(meipass) / "screenshield" / "web"
        if candidate.exists():
            return candidate
    return Path(__file__).resolve().parent / "web"


class AllowlistPayload(BaseModel):
    hwnds: list[int] = Field(default_factory=list)


class PanicPayload(BaseModel):
    active: bool


def _is_valid_local_origin(origin: str, request_port: int | None) -> bool:
    try:
        parsed = urlparse(origin)
    except Exception:
        return False
    if parsed.scheme != "http" or parsed.hostname not in _ALLOWED_LOCAL_HOSTS:
        return False
    if request_port is not None and parsed.port is not None and parsed.port != request_port:
        return False
    return True


def _is_valid_local_host_header(host_header: str, *, allow_test_host: bool = False) -> bool:
    if not host_header:
        return True
    host_only = host_header.split(":")[0].strip().lower()
    if host_only in _ALLOWED_LOCAL_HOSTS:
        return True
    return allow_test_host and host_only == "testserver"


def create_app(
    controller: ShieldController,
    auth: AuthState | None = None,
    *,
    allow_test_host: bool = False,
) -> FastAPI:
    """Build the configured FastAPI application bound to a ShieldController."""
    auth_state = auth or AuthState()
    app = FastAPI(title="ScreenShield Local API", docs_url=None, redoc_url=None, openapi_url=None)
    app.state.controller = controller
    app.state.auth = auth_state

    @app.middleware("http")
    async def security_middleware(request: Request, call_next):  # type: ignore[no-untyped-def]
        host_header = request.headers.get("host", "")
        if not _is_valid_local_host_header(host_header, allow_test_host=allow_test_host):
            return JSONResponse({"detail": "Invalid local host"}, status_code=403)

        path = request.url.path
        if path.startswith("/api/"):
            cookie_val = request.cookies.get(SESSION_COOKIE_NAME)
            if not auth_state.validate_session(cookie_val):
                return JSONResponse({"detail": "Unauthorized"}, status_code=401)

            if request.method in _MUTATING_METHODS:
                if request.headers.get(CSRF_HEADER_NAME) != "1":
                    return JSONResponse({"detail": "Missing CSRF header"}, status_code=403)
                origin = request.headers.get("origin")
                if origin is not None and not _is_valid_local_origin(origin, request.url.port):
                    return JSONResponse({"detail": "Cross-origin request blocked"}, status_code=403)

        response: Response = await call_next(request)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'none'"
        )
        response.headers["X-Content-Type-Options"] = "nosniff"
        if path.startswith("/api/") or path == "/auth/bootstrap":
            response.headers["Cache-Control"] = "no-store"
        return response

    @app.get("/auth/bootstrap")
    async def bootstrap_auth(token: str = "") -> RedirectResponse:
        if not auth_state.consume_bootstrap(token):
            raise HTTPException(status_code=403, detail="Invalid or expired bootstrap token")
        response = RedirectResponse(url="/", status_code=303)
        response.set_cookie(
            key=SESSION_COOKIE_NAME,
            value=auth_state.session_token,
            httponly=True,
            samesite="strict",
            path="/",
        )
        return response

    @app.get("/api/state")
    async def get_state() -> dict[str, Any]:
        return controller.get_state()

    @app.post("/api/share/start")
    async def start_share() -> dict[str, Any]:
        return controller.start_sharing()

    @app.post("/api/share/stop")
    async def stop_share() -> dict[str, Any]:
        return controller.stop_sharing()

    @app.post("/api/share/toggle")
    async def toggle_share() -> dict[str, Any]:
        return controller.toggle_sharing()

    @app.post("/api/panic")
    async def set_panic(payload: PanicPayload) -> dict[str, Any]:
        return controller.set_panic(payload.active)

    @app.post("/api/panic/toggle")
    async def toggle_panic() -> dict[str, Any]:
        return controller.toggle_panic()

    @app.post("/api/zones/overlays/toggle")
    async def toggle_zone_overlays() -> dict[str, Any]:
        return controller.toggle_zone_overlays()

    @app.post("/api/mirror/send-back")
    async def send_mirror_to_back() -> dict[str, Any]:
        return controller.send_mirror_to_back()

    @app.get("/api/windows")
    async def list_windows() -> dict[str, Any]:
        return {"windows": controller.list_windows()}

    @app.post("/api/allowlist")
    async def set_allowlist(payload: AllowlistPayload) -> dict[str, Any]:
        return controller.set_allowlist(payload.hwnds)

    @app.post("/api/blocked-windows")
    async def set_blocked_windows(payload: AllowlistPayload) -> dict[str, Any]:
        return controller.set_blocked_hwnds(payload.hwnds)

    @app.get("/api/monitors")
    async def list_monitors() -> dict[str, Any]:
        return {"monitors": controller.list_monitors()}

    @app.put("/api/config")
    async def update_config(patch: dict[str, Any]) -> dict[str, Any]:
        try:
            return controller.update_config(patch)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.post("/api/rules")
    async def add_rule(rule: dict[str, Any]) -> dict[str, Any]:
        try:
            return controller.add_rule(rule)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.put("/api/rules/{rule_id}")
    async def update_rule(rule_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        try:
            state = controller.update_rule(rule_id, patch)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if state is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        return state

    @app.delete("/api/rules/{rule_id}")
    async def delete_rule(rule_id: str) -> dict[str, Any]:
        state = controller.delete_rule(rule_id)
        if state is None:
            raise HTTPException(status_code=404, detail="Rule not found")
        return state

    @app.post("/api/zones")
    async def add_zone(zone: dict[str, Any]) -> dict[str, Any]:
        try:
            return controller.add_zone(zone)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc

    @app.put("/api/zones/{zone_id}")
    async def update_zone(zone_id: str, patch: dict[str, Any]) -> dict[str, Any]:
        try:
            state = controller.update_zone(zone_id, patch)
        except Exception as exc:
            raise HTTPException(status_code=422, detail=str(exc)) from exc
        if state is None:
            raise HTTPException(status_code=404, detail="Zone not found")
        return state

    @app.delete("/api/zones/{zone_id}")
    async def delete_zone(zone_id: str) -> dict[str, Any]:
        state = controller.delete_zone(zone_id)
        if state is None:
            raise HTTPException(status_code=404, detail="Zone not found")
        return state

    @app.get("/api/mirror/preview.jpg")
    async def mirror_preview() -> Response:
        jpeg_bytes = controller.mirror_engine.get_preview_jpeg()
        return Response(content=jpeg_bytes, media_type="image/jpeg")

    @app.post("/api/clipboard/alerts/clear")
    async def clear_clipboard_alerts() -> dict[str, Any]:
        return controller.clear_clipboard_alerts()

    web_dir = get_web_dir()
    if web_dir.exists():
        app.mount("/", StaticFiles(directory=str(web_dir), html=True), name="web")

    return app
