"""Unit tests for Direct On-Screen Auto Shield rule compilation and target selection."""

from __future__ import annotations

from screenshield.core.config import PrivacyRule, default_privacy_rules
from screenshield.core.direct_shield import (
    CompiledRuleSet,
    ShieldTarget,
    compute_shield_targets,
    expand_for_resizing,
    needs_clear_topmost,
)
from screenshield.core.window_watcher import WindowInfo


def test_compiled_rule_set_matching_and_invalid_regex_safety():
    rules = [
        *default_privacy_rules(),
        PrivacyRule(label="Broken Regex", pattern="[unclosed", match_type="regex", enabled=True),
        PrivacyRule(label="Disabled Rule", pattern="discord", match_type="contains", enabled=False),
    ]
    compiled = CompiledRuleSet(rules)

    matched_wa, reasons_wa = compiled.match("WhatsApp Web", "chrome.exe")
    assert matched_wa is True
    assert "WhatsApp" in reasons_wa

    matched_secret, reasons_secret = compiled.match(
        "Notes " + "sk-" + "proj-" + "abcdefghijklmnopqrstuvwxyz123456", "notepad.exe"
    )
    assert matched_secret is True
    assert "secret:openai_key" in reasons_secret

    matched_dc, reasons_dc = compiled.match("Discord", "Discord.exe")
    assert matched_dc is False
    assert reasons_dc == []


def test_compute_shield_targets_padding_manual_and_minimized():
    compiled = CompiledRuleSet(default_privacy_rules())
    windows = [
        WindowInfo(
            hwnd=10,
            title="WhatsApp",
            process_name="WhatsApp.exe",
            pid=100,
            rect=(100, 100, 500, 400),
            is_minimized=False,
            is_foreground=True,
            z_order=0,
        ),
        WindowInfo(
            hwnd=20,
            title="Custom Private App",
            process_name="custom.exe",
            pid=200,
            rect=(600, 200, 900, 500),
            is_minimized=False,
            is_foreground=False,
            z_order=1,
        ),
        WindowInfo(
            hwnd=30,
            title="Minimized 1Password",
            process_name="1Password.exe",
            pid=300,
            rect=(0, 0, 400, 300),
            is_minimized=True,
            is_foreground=False,
            z_order=2,
        ),
        WindowInfo(
            hwnd=40,
            title="Safe Editor - app.py",
            process_name="Code.exe",
            pid=400,
            rect=(50, 50, 1200, 800),
            is_minimized=False,
            is_foreground=False,
            z_order=3,
        ),
    ]

    targets = compute_shield_targets(windows, compiled, manual_hwnds={20}, padding_px=6)
    assert [t.hwnd for t in targets] == [10, 20]
    assert targets[0].rect == (94, 94, 506, 406)
    assert targets[0].label == "WhatsApp"
    assert targets[0].z_order == 0
    assert targets[1].rect == (594, 194, 906, 506)
    assert targets[1].label == "custom.exe"


def test_expand_for_resizing_expands_only_active_resizing_target():
    t1 = ShieldTarget(hwnd=10, rect=(100, 100, 500, 400), label="WhatsApp", z_order=0)
    t2 = ShieldTarget(hwnd=20, rect=(600, 200, 900, 500), label="1Password", z_order=1)

    expanded = expand_for_resizing([t1, t2], {10}, {10: (0, 0, 1920, 1032)})
    assert expanded[0].rect == (0, 0, 1920, 1032)
    assert expanded[1].rect == (600, 200, 900, 500)


def test_needs_clear_topmost():
    assert needs_clear_topmost(True, False) is True
    assert needs_clear_topmost(True, True) is False
    assert needs_clear_topmost(False, False) is False
    assert needs_clear_topmost(False, True) is False
