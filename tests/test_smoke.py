"""Smoke tests for ScreenShield."""

from __future__ import annotations

import screenshield
from screenshield.__main__ import main


def test_package_version_and_cli():
    assert screenshield.__version__ == "0.1.0"
    assert main(["--version"]) == 0
