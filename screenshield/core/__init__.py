"""Core modules for ScreenShield."""

from screenshield.core.config import AppConfig, ConfigStore, HotkeyConfig, PrivacyRule, StaticZone
from screenshield.core.controller import ShieldController
from screenshield.core.direct_shield import (
    CompiledRuleSet,
    DirectOverlayEngine,
    ShieldTarget,
    compute_shield_targets,
)
from screenshield.core.focus_assist import FocusAssistController, WindowAnimationController
from screenshield.core.privacy_mask import SafetyRingBuffer, apply_normalized_zones, apply_region_mask, render_curtain
from screenshield.core.secret_patterns import ClipboardGuard, detect_secrets

__all__ = [
    "AppConfig",
    "ClipboardGuard",
    "CompiledRuleSet",
    "ConfigStore",
    "DirectOverlayEngine",
    "FocusAssistController",
    "HotkeyConfig",
    "PrivacyRule",
    "SafetyRingBuffer",
    "ShieldController",
    "ShieldTarget",
    "StaticZone",
    "WindowAnimationController",
    "apply_normalized_zones",
    "apply_region_mask",
    "compute_shield_targets",
    "detect_secrets",
    "render_curtain",
]
