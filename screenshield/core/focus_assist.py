"""Windows Focus Assist / Toast notification silencer with crash-safe backup."""

from __future__ import annotations

import ctypes
import json
import os
import threading
import winreg
from ctypes import wintypes
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol


NOTIF_SETTINGS_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\Notifications\Settings"
PUSH_NOTIF_SUBKEY = r"Software\Microsoft\Windows\CurrentVersion\PushNotifications"

MANAGED_VALUES: tuple[tuple[str, str], ...] = (
    (NOTIF_SETTINGS_SUBKEY, "NOC_GLOBAL_SETTING_TOASTS_ENABLED"),
    (PUSH_NOTIF_SUBKEY, "ToastEnabled"),
)


@dataclass
class RegistrySnapshotEntry:
    subkey: str
    value_name: str
    existed: bool
    value: int | None
    reg_type: int | None


class RegistryBackend(Protocol):
    """Abstraction over HKCU registry access for deterministic testing."""

    def read_value(self, subkey: str, name: str) -> tuple[bool, int | None, int | None]: ...

    def write_dword(self, subkey: str, name: str, value: int, reg_type: int | None = None) -> None: ...

    def delete_value(self, subkey: str, name: str) -> None: ...


class Win32RegistryBackend:
    """HKCU implementation using stdlib winreg."""

    def read_value(self, subkey: str, name: str) -> tuple[bool, int | None, int | None]:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_READ) as key:
                val, reg_type = winreg.QueryValueEx(key, name)
                return True, int(val), int(reg_type)
        except FileNotFoundError:
            return False, None, None
        except OSError:
            return False, None, None

    def write_dword(self, subkey: str, name: str, value: int, reg_type: int | None = None) -> None:
        target_type = winreg.REG_DWORD if reg_type is None else reg_type
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, name, 0, target_type, int(value))

    def delete_value(self, subkey: str, name: str) -> None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, subkey, 0, winreg.KEY_SET_VALUE) as key:
                winreg.DeleteValue(key, name)
        except FileNotFoundError:
            return


class FocusAssistController:
    """Mutes Windows toast popups while sharing and restores exact original state."""

    def __init__(self, backup_path: Path, backend: RegistryBackend | None = None) -> None:
        self.backup_path = Path(backup_path)
        self.backend: RegistryBackend = backend or Win32RegistryBackend()
        self._lock = threading.RLock()
        self._silenced = False

    @property
    def is_silenced(self) -> bool:
        with self._lock:
            return self._silenced or self.backup_path.exists()

    def recover_if_dirty(self) -> bool:
        """Restore previous notification state if a crash left a backup file behind."""
        with self._lock:
            if not self.backup_path.exists():
                return False
            return self.restore()

    def enable_silence(self) -> bool:
        """Snapshot original HKCU notification settings and disable toast popups."""
        with self._lock:
            if not self.backup_path.exists():
                entries: list[dict[str, object]] = []
                for subkey, name in MANAGED_VALUES:
                    existed, val, reg_type = self.backend.read_value(subkey, name)
                    entries.append(
                        {
                            "subkey": subkey,
                            "value_name": name,
                            "existed": existed,
                            "value": val,
                            "reg_type": reg_type,
                        }
                    )
                self.backup_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.backup_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps({"entries": entries}, indent=2), encoding="utf-8")
                os.replace(tmp, self.backup_path)

            for subkey, name in MANAGED_VALUES:
                self.backend.write_dword(subkey, name, 0, winreg.REG_DWORD)
            self._silenced = True
            return True

    def restore(self) -> bool:
        """Restore notification settings from backup and remove backup file."""
        with self._lock:
            if not self.backup_path.exists():
                self._silenced = False
                return False
            try:
                data = json.loads(self.backup_path.read_text(encoding="utf-8"))
                entries = data.get("entries", [])
                for entry in entries:
                    subkey = str(entry["subkey"])
                    name = str(entry["value_name"])
                    if entry.get("existed"):
                        self.backend.write_dword(
                            subkey,
                            name,
                            int(entry["value"]),
                            entry.get("reg_type"),
                        )
                    else:
                        self.backend.delete_value(subkey, name)
            finally:
                try:
                    self.backup_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self._silenced = False
            return True


SPI_GETANIMATION = 0x0048
SPI_SETANIMATION = 0x0049
SPIF_SENDCHANGE = 0x0002


class _ANIMATIONINFO(ctypes.Structure):
    _fields_ = [
        ("cbSize", wintypes.UINT),
        ("iMinAnimate", ctypes.c_int),
    ]


class AnimationBackend(Protocol):
    """Abstraction over Windows minimize/maximize animation setting."""

    def get_min_animate(self) -> int: ...

    def set_min_animate(self, value: int) -> bool: ...


class Win32AnimationBackend:
    """Win32 SystemParametersInfoW implementation for SPI_GETANIMATION / SPI_SETANIMATION."""

    def get_min_animate(self) -> int:
        info = _ANIMATIONINFO()
        info.cbSize = ctypes.sizeof(_ANIMATIONINFO)
        ok = ctypes.windll.user32.SystemParametersInfoW(
            SPI_GETANIMATION, info.cbSize, ctypes.byref(info), 0
        )
        return int(info.iMinAnimate) if ok else 1

    def set_min_animate(self, value: int) -> bool:
        info = _ANIMATIONINFO()
        info.cbSize = ctypes.sizeof(_ANIMATIONINFO)
        info.iMinAnimate = 1 if value else 0
        return bool(
            ctypes.windll.user32.SystemParametersInfoW(
                SPI_SETANIMATION, info.cbSize, ctypes.byref(info), SPIF_SENDCHANGE
            )
        )


class WindowAnimationController:
    """Temporarily disables Windows minimize/maximize animations so shields never lag behind."""

    def __init__(self, backup_path: Path, backend: AnimationBackend | None = None) -> None:
        self.backup_path = Path(backup_path)
        self.backend: AnimationBackend = backend or Win32AnimationBackend()
        self._lock = threading.RLock()
        self._disabled = False

    @property
    def is_disabled(self) -> bool:
        with self._lock:
            return self._disabled or self.backup_path.exists()

    def recover_if_dirty(self) -> bool:
        with self._lock:
            if not self.backup_path.exists():
                return False
            return self.restore()

    def disable_animations(self) -> bool:
        with self._lock:
            if not self.backup_path.exists():
                original = self.backend.get_min_animate()
                self.backup_path.parent.mkdir(parents=True, exist_ok=True)
                tmp = self.backup_path.with_suffix(".json.tmp")
                tmp.write_text(json.dumps({"iMinAnimate": int(original)}, indent=2), encoding="utf-8")
                os.replace(tmp, self.backup_path)
            self.backend.set_min_animate(0)
            self._disabled = True
            return True

    def restore(self) -> bool:
        with self._lock:
            if not self.backup_path.exists():
                self._disabled = False
                return False
            try:
                data = json.loads(self.backup_path.read_text(encoding="utf-8"))
                original = int(data.get("iMinAnimate", 1))
                self.backend.set_min_animate(original)
            finally:
                try:
                    self.backup_path.unlink(missing_ok=True)
                except OSError:
                    pass
                self._disabled = False
            return True
