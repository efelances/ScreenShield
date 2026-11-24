"""Offline configuration store and Pydantic models for ScreenShield."""

from __future__ import annotations

import json
import os
import threading
import uuid
from pathlib import Path
from typing import Literal

from pydantic import BaseModel, Field


LanguageCode = Literal["tr", "en", "de", "es"]
ThemeMode = Literal["dark", "light"]
ShieldMode = Literal["direct_overlay", "safe_mirror"]
MirrorMode = Literal["allowlist", "monitor_redact"]
MaskStyle = Literal["blur", "solid"]
MatchType = Literal["contains", "regex"]


class PrivacyRule(BaseModel):
    """Rule matching window titles or process names that must be shielded."""

    id: str = Field(default_factory=lambda: f"rule_{uuid.uuid4().hex[:8]}")
    label: str = Field(min_length=1, max_length=100)
    pattern: str = Field(min_length=1, max_length=200)
    match_type: MatchType = "contains"
    category: str = Field(default="custom", min_length=1, max_length=40)
    enabled: bool = True


class StaticZone(BaseModel):
    """Normalized (0..1) static screen region to blur or block."""

    id: str = Field(default_factory=lambda: f"zone_{uuid.uuid4().hex[:8]}")
    label: str = Field(min_length=1, max_length=100)
    x: float = Field(ge=0.0, le=1.0)
    y: float = Field(ge=0.0, le=1.0)
    width: float = Field(gt=0.0, le=1.0)
    height: float = Field(gt=0.0, le=1.0)
    style: MaskStyle = "blur"
    enabled: bool = True


class HotkeyConfig(BaseModel):
    """Global Win32 hotkey combinations."""

    panic: str = "Ctrl+Alt+H"
    share_mode: str = "Ctrl+Alt+M"
    zones: str = "Ctrl+Alt+Z"


class AppConfig(BaseModel):
    """Top-level persistent user configuration."""

    language: LanguageCode = "tr"
    theme: ThemeMode = "dark"
    high_contrast: bool = False
    shield_mode: ShieldMode = "direct_overlay"
    mirror_mode: MirrorMode = "allowlist"
    mask_style: MaskStyle = "blur"
    buffer_delay_ms: int = Field(default=150, ge=0, le=300)
    direct_padding_px: int = Field(default=4, ge=0, le=24)
    fps: int = Field(default=24, ge=5, le=60)
    monitor_index: int = Field(default=1, ge=1, le=16)
    auto_focus_assist: bool = True
    clipboard_guard_enabled: bool = True
    clipboard_auto_clear: bool = False
    hide_control_from_capture: bool = True
    allowlist_hwnds: list[int] = Field(default_factory=list)
    blocked_hwnds: list[int] = Field(default_factory=list)
    hotkeys: HotkeyConfig = Field(default_factory=HotkeyConfig)
    rules: list[PrivacyRule] = Field(default_factory=list)
    zones: list[StaticZone] = Field(default_factory=list)


def default_privacy_rules() -> list[PrivacyRule]:
    """Built-in privacy rules covering messaging, vaults, secrets, mail, and banking."""
    return [
        PrivacyRule(
            id="builtin_whatsapp",
            label="WhatsApp",
            pattern="whatsapp",
            match_type="contains",
            category="messaging",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_telegram",
            label="Telegram",
            pattern="telegram",
            match_type="contains",
            category="messaging",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_signal",
            label="Signal",
            pattern="signal",
            match_type="contains",
            category="messaging",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_1password",
            label="1Password",
            pattern="1password",
            match_type="contains",
            category="password_manager",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_bitwarden",
            label="Bitwarden",
            pattern="bitwarden",
            match_type="contains",
            category="password_manager",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_keepass",
            label="KeePass / KeePassXC",
            pattern="keepass",
            match_type="contains",
            category="password_manager",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_dotenv",
            label=".env Files",
            pattern=r"(?:^|[\s\\/\[\(])\.env(?:\.[a-z0-9_-]+)?(?=$|[\s\]\)—\-:])",
            match_type="regex",
            category="secrets",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_secrets_keywords",
            label="Secrets / Credentials / Keys",
            pattern=r"\b(?:secrets?|credentials?|private[_\s-]?key|id_rsa|api[_\s-]?keys?)\b",
            match_type="regex",
            category="secrets",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_gmail",
            label="Gmail",
            pattern="gmail",
            match_type="contains",
            category="email",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_outlook",
            label="Outlook",
            pattern="outlook",
            match_type="contains",
            category="email",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_proton",
            label="Proton Mail",
            pattern="proton mail",
            match_type="contains",
            category="email",
            enabled=True,
        ),
        PrivacyRule(
            id="builtin_banking",
            label="Banking / PayPal / Stripe",
            pattern=r"\b(?:banka|banking|paypal|stripe dashboard|iban|garanti|isbank|yapikredi|akbank|ziraat|enpara)\b",
            match_type="regex",
            category="finance",
            enabled=True,
        ),
    ]


def get_data_dir() -> Path:
    """Resolve ScreenShield's local data directory."""
    override = os.environ.get("SCREENSHIELD_DATA_DIR")
    if override:
        base = Path(override)
    else:
        local_app_data = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        base = Path(local_app_data) / "ScreenShield"
    base.mkdir(parents=True, exist_ok=True)
    return base


class ConfigStore:
    """Thread-safe atomic JSON store for AppConfig."""

    def __init__(self, data_dir: Path | None = None) -> None:
        self.data_dir = Path(data_dir) if data_dir is not None else get_data_dir()
        self.data_dir.mkdir(parents=True, exist_ok=True)
        self.config_path = self.data_dir / "config.json"
        self.focus_backup_path = self.data_dir / "focus_assist_backup.json"
        self.animation_backup_path = self.data_dir / "animation_backup.json"
        self._lock = threading.RLock()

    def load(self) -> AppConfig:
        """Load persisted config or create default configuration."""
        with self._lock:
            if not self.config_path.exists():
                cfg = AppConfig(rules=default_privacy_rules())
                self.save(cfg)
                return cfg
            try:
                raw = json.loads(self.config_path.read_text(encoding="utf-8"))
                cfg = AppConfig.model_validate(raw)
                if not cfg.rules and "rules" not in raw:
                    cfg.rules = default_privacy_rules()
                return cfg
            except Exception:
                cfg = AppConfig(rules=default_privacy_rules())
                self.save(cfg)
                return cfg

    def save(self, config: AppConfig) -> AppConfig:
        """Persist configuration atomically via a temporary file."""
        with self._lock:
            payload = json.dumps(config.model_dump(mode="json"), indent=2, ensure_ascii=False)
            tmp_path = self.config_path.with_suffix(".json.tmp")
            tmp_path.write_text(payload, encoding="utf-8")
            os.replace(tmp_path, self.config_path)
            return config
