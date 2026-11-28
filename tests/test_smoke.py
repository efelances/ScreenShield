"""Smoke tests for ScreenShield."""

from __future__ import annotations

import screenshield
from screenshield.__main__ import main
from screenshield.assets import build_shield_icon_image, ensure_icon_file
from screenshield.core.hotkeys import parse_hotkey


def test_package_version_and_cli(capsys):
    assert screenshield.__version__ == "0.1.1"
    assert main(["--version"]) == 0
    captured = capsys.readouterr()
    assert "0.1.1" in captured.out


def test_icon_generation(tmp_path):
    img = build_shield_icon_image(64)
    assert img.size == (64, 64)
    ico = ensure_icon_file(tmp_path / "app.ico")
    assert ico.exists()
    assert ico.stat().st_size > 100


def test_hotkey_parser():
    mods, vk = parse_hotkey("Ctrl+Alt+H")
    assert mods == 0x0003
    assert vk == ord("H")

    mods2, vk2 = parse_hotkey("Ctrl+Shift+F12")
    assert mods2 == 0x0006
    assert vk2 == 0x7B
