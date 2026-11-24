"""Tests for FocusAssistController backup, restore, and crash recovery."""

from __future__ import annotations

import winreg

from screenshield.core.focus_assist import (
    NOTIF_SETTINGS_SUBKEY,
    PUSH_NOTIF_SUBKEY,
    FocusAssistController,
    WindowAnimationController,
)


class FakeRegistryBackend:
    """In-memory HKCU double for deterministic unit testing."""

    def __init__(self, initial: dict[tuple[str, str], tuple[int, int]] | None = None) -> None:
        self.data: dict[tuple[str, str], tuple[int, int]] = dict(initial or {})

    def read_value(self, subkey: str, name: str) -> tuple[bool, int | None, int | None]:
        entry = self.data.get((subkey, name))
        if entry is None:
            return False, None, None
        return True, entry[0], entry[1]

    def write_dword(self, subkey: str, name: str, value: int, reg_type: int | None = None) -> None:
        self.data[(subkey, name)] = (int(value), winreg.REG_DWORD if reg_type is None else reg_type)

    def delete_value(self, subkey: str, name: str) -> None:
        self.data.pop((subkey, name), None)


def test_focus_assist_silence_restore_and_crash_recovery(tmp_path):
    backup = tmp_path / "focus_assist_backup.json"
    backend = FakeRegistryBackend(
        {
            (NOTIF_SETTINGS_SUBKEY, "NOC_GLOBAL_SETTING_TOASTS_ENABLED"): (1, winreg.REG_DWORD),
        }
    )

    ctrl = FocusAssistController(backup_path=backup, backend=backend)
    assert ctrl.is_silenced is False

    ctrl.enable_silence()
    assert ctrl.is_silenced is True
    assert backup.exists()
    assert backend.read_value(NOTIF_SETTINGS_SUBKEY, "NOC_GLOBAL_SETTING_TOASTS_ENABLED") == (
        True,
        0,
        winreg.REG_DWORD,
    )
    assert backend.read_value(PUSH_NOTIF_SUBKEY, "ToastEnabled") == (True, 0, winreg.REG_DWORD)

    # Simulate crash recovery with a brand-new controller instance
    recovered_ctrl = FocusAssistController(backup_path=backup, backend=backend)
    assert recovered_ctrl.recover_if_dirty() is True
    assert not backup.exists()
    assert backend.read_value(NOTIF_SETTINGS_SUBKEY, "NOC_GLOBAL_SETTING_TOASTS_ENABLED") == (
        True,
        1,
        winreg.REG_DWORD,
    )
    # Key that did not exist before must be deleted on restore
    assert backend.read_value(PUSH_NOTIF_SUBKEY, "ToastEnabled") == (False, None, None)


class FakeAnimationBackend:
    """In-memory SPI_GETANIMATION/SPI_SETANIMATION double."""

    def __init__(self, initial: int = 1) -> None:
        self.value = initial

    def get_min_animate(self) -> int:
        return self.value

    def set_min_animate(self, value: int) -> bool:
        self.value = 1 if value else 0
        return True


def test_window_animation_disable_restore_and_crash_recovery(tmp_path):
    backup = tmp_path / "animation_backup.json"
    backend = FakeAnimationBackend(initial=1)

    ctrl = WindowAnimationController(backup_path=backup, backend=backend)
    assert ctrl.is_disabled is False

    ctrl.disable_animations()
    assert ctrl.is_disabled is True
    assert backend.value == 0
    assert backup.exists()

    recovered = WindowAnimationController(backup_path=backup, backend=backend)
    assert recovered.recover_if_dirty() is True
    assert backend.value == 1
    assert not backup.exists()
