"""Tests for offline secret pattern matching and ClipboardGuard."""

from __future__ import annotations

from screenshield.core.secret_patterns import ClipboardGuard, detect_secrets


def _build_fake_luhn_card() -> str:
    # Build a synthetic 16-digit Luhn-valid number programmatically so no literal PAN is needed.
    prefix = "400000123456789"
    total = 0
    for idx, ch in enumerate(prefix[::-1]):
        n = int(ch)
        if idx % 2 == 0:
            n *= 2
            if n > 9:
                n -= 9
        total += n
    check = (10 - (total % 10)) % 10
    return f"{prefix}{check}"


def test_detect_secrets_categories():
    card = _build_fake_luhn_card()
    sample = "\n".join(
        [
            "OPENAI_API_KEY=super_secret_demo_value_123",
            "ghp" + "_" + "AbCdEfGhIjKlMnOpQrStUvWxYz1234567890",
            "AKIA" + "IOSFODNN7EXAMPLE",
            "-----BEGIN " + "RSA PRIVATE KEY-----",
            f"card: {card}",
        ]
    )
    cats = detect_secrets(sample)
    assert "env_assignment" in cats
    assert "openai_key" not in cats
    assert "github_token" in cats
    assert "aws_access_key" in cats
    assert "private_key_pem" in cats
    assert "credit_card" in cats

    assert detect_secrets("sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456") == ["openai_key"]
    assert detect_secrets("normal harmless meeting notes") == []


def test_clipboard_guard_redacts_and_autoclears():
    clipboard = {"text": "DATABASE_URL=postgres://user:pass@localhost/db"}
    cleared = {"count": 0}

    guard = ClipboardGuard(
        read_clipboard=lambda: clipboard["text"],
        clear_clipboard=lambda: (cleared.__setitem__("count", cleared["count"] + 1) or True),
    )
    guard.configure(enabled=True, active_sharing=True, auto_clear=True)
    alert = guard.scan_once()
    assert alert is not None
    assert "env_assignment" in alert.categories
    assert alert.auto_cleared is True
    assert cleared["count"] == 1

    alerts = guard.get_alerts()
    assert len(alerts) == 1
    serialized = str(alerts)
    assert "postgres://user:pass" not in serialized
