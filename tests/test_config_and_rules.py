"""Tests for ConfigStore persistence and privacy rule matching."""

from __future__ import annotations

from screenshield.core.config import ConfigStore, PrivacyRule
from screenshield.core.window_watcher import WindowInfo, is_window_sensitive, match_rules


def test_config_store_defaults_and_roundtrip(tmp_path):
    store = ConfigStore(data_dir=tmp_path)
    cfg = store.load()
    assert cfg.language == "tr"
    assert cfg.theme == "dark"
    assert cfg.shield_mode == "direct_overlay"
    assert cfg.direct_padding_px == 4
    assert cfg.buffer_delay_ms == 150
    assert len(cfg.rules) >= 10

    updated = cfg.model_copy(
        update={
            "language": "en",
            "theme": "light",
            "shield_mode": "safe_mirror",
            "direct_padding_px": 8,
            "buffer_delay_ms": 200,
            "high_contrast": True,
        }
    )
    store.save(updated)

    reloaded = store.load()
    assert reloaded.language == "en"
    assert reloaded.theme == "light"
    assert reloaded.shield_mode == "safe_mirror"
    assert reloaded.direct_padding_px == 8
    assert reloaded.buffer_delay_ms == 200
    assert reloaded.high_contrast is True


def test_window_rule_matching():
    win_wa = WindowInfo(
        hwnd=101,
        title="WhatsApp - Chat",
        process_name="WhatsApp.exe",
        pid=2222,
        rect=(0, 0, 800, 600),
        is_minimized=False,
        is_foreground=True,
        z_order=0,
    )
    win_env = WindowInfo(
        hwnd=102,
        title=".env — ScreenShield — Visual Studio Code",
        process_name="Code.exe",
        pid=3333,
        rect=(0, 0, 1280, 720),
        is_minimized=False,
        is_foreground=False,
        z_order=1,
    )
    win_safe = WindowInfo(
        hwnd=103,
        title="controller.py — ScreenShield — Visual Studio Code",
        process_name="Code.exe",
        pid=3333,
        rect=(0, 0, 1280, 720),
        is_minimized=False,
        is_foreground=False,
        z_order=2,
    )

    store_rules = ConfigStore.__new__(ConfigStore)
    _ = store_rules
    from screenshield.core.config import default_privacy_rules

    rules = default_privacy_rules()
    assert len(match_rules(win_wa, rules)) >= 1
    sensitive_env, reasons_env = is_window_sensitive(win_env, rules)
    assert sensitive_env is True
    assert ".env Files" in reasons_env

    sensitive_safe, reasons_safe = is_window_sensitive(win_safe, rules)
    assert sensitive_safe is False
    assert reasons_safe == []

    custom = PrivacyRule(label="Notion", pattern="notion", match_type="contains", enabled=False)
    assert match_rules(win_safe, [custom]) == []
