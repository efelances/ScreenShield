"""Security and API integration tests for ScreenShield's localhost server."""

from __future__ import annotations

from fastapi.testclient import TestClient

from screenshield.core.config import ConfigStore
from screenshield.core.controller import ShieldController
from screenshield.core.focus_assist import FocusAssistController, WindowAnimationController
from screenshield.server import AuthState, create_app
from tests.test_focus_assist import FakeAnimationBackend, FakeRegistryBackend


def _make_test_client(tmp_path):
    store = ConfigStore(data_dir=tmp_path)
    focus = FocusAssistController(store.focus_backup_path, backend=FakeRegistryBackend())
    anim = WindowAnimationController(store.animation_backup_path, backend=FakeAnimationBackend())
    controller = ShieldController(
        store=store,
        enable_hotkeys=False,
        enable_clipboard_guard=False,
        focus_assist=focus,
        window_animations=anim,
    )
    auth = AuthState()
    app = create_app(controller, auth=auth, allow_test_host=False)
    client = TestClient(app, base_url="http://127.0.0.1:8000")
    return client, controller, auth


_CSRF = {"X-ScreenShield-CSRF": "1"}


def test_auth_bootstrap_and_csrf_protection(tmp_path):
    client, controller, auth = _make_test_client(tmp_path)
    try:
        # Unauthenticated API access must fail with 401
        r_unauth = client.get("/api/state")
        assert r_unauth.status_code == 401

        # Spoofed / non-localhost Host header (including testserver in prod) is blocked
        r_bad_host = client.get("/api/state", headers={"Host": "evil.local"})
        assert r_bad_host.status_code == 403
        r_test_host = client.get("/api/state", headers={"Host": "testserver"})
        assert r_test_host.status_code == 403

        # Wrong bootstrap token fails
        r_bad_boot = client.get("/auth/bootstrap?token=wrong", follow_redirects=False)
        assert r_bad_boot.status_code == 403

        # Valid bootstrap token sets HttpOnly cookie and is single-use
        valid_token = auth.bootstrap_token
        r_boot = client.get(f"/auth/bootstrap?token={valid_token}", follow_redirects=False)
        assert r_boot.status_code == 303
        assert "screenshield_session" in r_boot.cookies

        # Replay of bootstrap token is rejected
        r_replay = client.get(f"/auth/bootstrap?token={valid_token}", follow_redirects=False)
        assert r_replay.status_code == 403

        # Authenticated GET succeeds and returns security headers
        r_state = client.get("/api/state")
        assert r_state.status_code == 200
        assert "Content-Security-Policy" in r_state.headers
        assert r_state.headers.get("X-Content-Type-Options") == "nosniff"

        # Mutating request without CSRF header is blocked even with valid cookie
        r_no_csrf = client.post(
            "/api/panic",
            json={"active": True},
            headers={"Origin": "http://127.0.0.1:8000"},
        )
        assert r_no_csrf.status_code == 403

        # Cross-origin mutating request is blocked
        r_evil = client.post(
            "/api/panic",
            json={"active": True},
            headers={"Origin": "https://evil.example", **_CSRF},
        )
        assert r_evil.status_code == 403

        # Same-origin mutating request with CSRF header succeeds
        r_panic = client.post(
            "/api/panic",
            json={"active": True},
            headers={"Origin": "http://127.0.0.1:8000", **_CSRF},
        )
        assert r_panic.status_code == 200
        assert r_panic.json()["metrics"]["panic"] is True
    finally:
        controller.shutdown()


def test_rules_zones_config_and_preview_endpoints(tmp_path):
    client, controller, auth = _make_test_client(tmp_path)
    try:
        client.get(f"/auth/bootstrap?token={auth.bootstrap_token}", follow_redirects=False)

        # Update config language, theme, shield_mode & padding
        r_cfg = client.put(
            "/api/config",
            headers=_CSRF,
            json={
                "language": "de",
                "theme": "light",
                "shield_mode": "safe_mirror",
                "direct_padding_px": 10,
                "buffer_delay_ms": 225,
            },
        )
        assert r_cfg.status_code == 200
        cfg = r_cfg.json()["config"]
        assert cfg["language"] == "de"
        assert cfg["theme"] == "light"
        assert cfg["shield_mode"] == "safe_mirror"
        assert cfg["direct_padding_px"] == 10
        assert cfg["buffer_delay_ms"] == 225

        # Manual blocked-windows endpoint tracks session blocked HWNDs
        r_blk = client.post("/api/blocked-windows", headers=_CSRF, json={"hwnds": [12345, 67890]})
        assert r_blk.status_code == 200
        assert r_blk.json()["config"]["blocked_hwnds"] == [12345, 67890]

        # Send mirror to back endpoint works cleanly
        r_back = client.post("/api/mirror/send-back", headers=_CSRF)
        assert r_back.status_code == 200

        # Add, toggle, and delete privacy rule
        r_add_rule = client.post(
            "/api/rules",
            headers=_CSRF,
            json={"label": "Custom Vault", "pattern": "myvault", "match_type": "contains"},
        )
        assert r_add_rule.status_code == 200
        rules = r_add_rule.json()["config"]["rules"]
        custom_rule = next(r for r in rules if r["label"] == "Custom Vault")
        r_del_rule = client.delete(f"/api/rules/{custom_rule['id']}", headers=_CSRF)
        assert r_del_rule.status_code == 200

        # Add and delete static zone
        r_add_zone = client.post(
            "/api/zones",
            headers=_CSRF,
            json={"label": "Corner", "x": 0.7, "y": 0.7, "width": 0.3, "height": 0.3},
        )
        assert r_add_zone.status_code == 200
        zones = r_add_zone.json()["config"]["zones"]
        assert len(zones) == 1
        r_del_zone = client.delete(f"/api/zones/{zones[0]['id']}", headers=_CSRF)
        assert r_del_zone.status_code == 200

        # Mirror JPEG preview endpoint returns valid JPEG bytes
        r_jpg = client.get("/api/mirror/preview.jpg")
        assert r_jpg.status_code == 200
        assert r_jpg.headers["content-type"] == "image/jpeg"
        assert r_jpg.content[:2] == b"\xff\xd8"
    finally:
        controller.shutdown()
