"""Core orchestration controller for ScreenShield."""

from __future__ import annotations

import threading
import uuid
from typing import Any

import mss

from screenshield.core.config import (
    AppConfig,
    ConfigStore,
    PrivacyRule,
    StaticZone,
)
from screenshield.core.direct_shield import DirectOverlayEngine
from screenshield.core.focus_assist import FocusAssistController, WindowAnimationController
from screenshield.core.hotkeys import GlobalHotkeyManager
from screenshield.core.mirror_engine import MirrorEngine
from screenshield.core.mirror_window import MirrorWindow, StaticZoneOverlayManager
from screenshield.core.secret_patterns import ClipboardGuard
from screenshield.core.window_watcher import (
    enable_dpi_awareness,
    enumerate_windows,
    is_window_sensitive,
    set_window_exclude_from_capture,
)


class ShieldController:
    """Coordinates mirror capture, hotkeys, Focus Assist, zones, and clipboard guard."""

    def __init__(
        self,
        store: ConfigStore | None = None,
        *,
        enable_hotkeys: bool = True,
        enable_clipboard_guard: bool = True,
        focus_assist: FocusAssistController | None = None,
        window_animations: WindowAnimationController | None = None,
    ) -> None:
        enable_dpi_awareness()
        self._lock = threading.RLock()
        self.store = store or ConfigStore()
        self.config = self.store.load()
        self._control_hwnd: int = 0
        self._zone_overlays_active = False
        self._sharing_active = False
        self._panic_active = False

        self.focus_assist = focus_assist or FocusAssistController(self.store.focus_backup_path)
        self.window_animations = window_animations or WindowAnimationController(
            self.store.animation_backup_path
        )
        # Crash recovery: restore Focus Assist & window animations if a prior run crashed.
        self.focus_assist.recover_if_dirty()
        self.window_animations.recover_if_dirty()

        self.mirror_window = MirrorWindow(on_user_close=self._on_mirror_closed_by_user)
        self.zone_overlays = StaticZoneOverlayManager()
        self.mirror_engine = MirrorEngine(self.mirror_window, self.config)
        self.direct_shield = DirectOverlayEngine(self.config)
        self.clipboard_guard = ClipboardGuard()
        self.hotkeys = GlobalHotkeyManager()
        self._hotkey_status: dict[str, bool] = {}

        if enable_clipboard_guard:
            self.clipboard_guard.configure(
                enabled=self.config.clipboard_guard_enabled,
                active_sharing=False,
                auto_clear=self.config.clipboard_auto_clear,
            )
            self.clipboard_guard.start()

        if enable_hotkeys:
            self._sync_hotkeys()

    def _on_mirror_closed_by_user(self) -> None:
        self.stop_sharing()

    def set_control_window_hwnd(self, hwnd: int) -> None:
        with self._lock:
            self._control_hwnd = int(hwnd or 0)
            if self._control_hwnd:
                set_window_exclude_from_capture(
                    self._control_hwnd, self.config.hide_control_from_capture
                )

    def _sync_hotkeys(self) -> None:
        bindings = {
            "panic": self.config.hotkeys.panic,
            "share_mode": self.config.hotkeys.share_mode,
            "zones": self.config.hotkeys.zones,
        }
        callbacks = {
            "panic": self.toggle_panic,
            "share_mode": self.toggle_sharing,
            "zones": self.toggle_zone_overlays,
        }
        try:
            self._hotkey_status = self.hotkeys.update_bindings(bindings, callbacks)
        except Exception:
            self._hotkey_status = {k: False for k in bindings}

    def start_sharing(self) -> dict[str, Any]:
        with self._lock:
            self._sharing_active = True
            if self.config.auto_focus_assist:
                try:
                    self.focus_assist.enable_silence()
                except Exception:
                    pass
            if self.config.shield_mode == "direct_overlay":
                self.mirror_engine.stop_sharing()
                try:
                    self.window_animations.disable_animations()
                except Exception:
                    pass
                self.direct_shield.start_shield()
            else:
                self.direct_shield.stop_shield()
                try:
                    self.window_animations.restore()
                except Exception:
                    pass
                self.mirror_engine.start_sharing()
            self.clipboard_guard.configure(
                enabled=self.config.clipboard_guard_enabled,
                active_sharing=True,
                auto_clear=self.config.clipboard_auto_clear,
            )
            return self.get_state()

    def stop_sharing(self) -> dict[str, Any]:
        with self._lock:
            self._sharing_active = False
            self.direct_shield.stop_shield()
            self.mirror_engine.stop_sharing()
            self.clipboard_guard.configure(
                enabled=self.config.clipboard_guard_enabled,
                active_sharing=False,
                auto_clear=self.config.clipboard_auto_clear,
            )
            try:
                self.window_animations.restore()
            except Exception:
                pass
            try:
                self.focus_assist.restore()
            except Exception:
                pass
            return self.get_state()

    def toggle_sharing(self) -> dict[str, Any]:
        with self._lock:
            if self._sharing_active:
                return self.stop_sharing()
            return self.start_sharing()

    def set_panic(self, active: bool) -> dict[str, Any]:
        with self._lock:
            self._panic_active = bool(active)
            if self.config.shield_mode == "direct_overlay":
                self.mirror_engine.set_panic(False)
                self.direct_shield.set_panic(self._panic_active)
            else:
                self.direct_shield.set_panic(False)
                self.mirror_engine.set_panic(self._panic_active)
            return self.get_state()

    def toggle_panic(self) -> dict[str, Any]:
        with self._lock:
            return self.set_panic(not self._panic_active)

    def toggle_zone_overlays(self) -> dict[str, Any]:
        with self._lock:
            self._zone_overlays_active = not self._zone_overlays_active
            self.zone_overlays.sync(self.config.zones, self._zone_overlays_active)
            return self.get_state()

    def send_mirror_to_back(self) -> dict[str, Any]:
        with self._lock:
            self.mirror_window.send_to_back()
            return self.get_state()

    def set_allowlist(self, hwnds: list[int]) -> dict[str, Any]:
        with self._lock:
            cleaned: list[int] = []
            seen: set[int] = set()
            for raw in hwnds:
                val = int(raw)
                if val > 0 and val not in seen:
                    seen.add(val)
                    cleaned.append(val)
            self.config = self.config.model_copy(update={"allowlist_hwnds": cleaned})
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            return self.get_state()

    def set_blocked_hwnds(self, hwnds: list[int]) -> dict[str, Any]:
        with self._lock:
            cleaned: list[int] = []
            seen: set[int] = set()
            for raw in hwnds:
                val = int(raw)
                if val > 0 and val not in seen:
                    seen.add(val)
                    cleaned.append(val)
            self.config = self.config.model_copy(update={"blocked_hwnds": cleaned})
            self.store.save(self.config)
            self.direct_shield.update_config(self.config)
            return self.get_state()

    def update_config(self, patch: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            prev_mode = self.config.shield_mode
            current = self.config.model_dump()
            for key, value in patch.items():
                if key in current:
                    current[key] = value
            updated = AppConfig.model_validate(current)
            hotkeys_changed = updated.hotkeys != self.config.hotkeys
            self.config = updated
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            self.direct_shield.update_config(self.config)

            if self._control_hwnd:
                set_window_exclude_from_capture(
                    self._control_hwnd, self.config.hide_control_from_capture
                )

            if self.config.shield_mode != prev_mode:
                if self._sharing_active:
                    if self.config.shield_mode == "direct_overlay":
                        self.mirror_engine.stop_sharing()
                        try:
                            self.window_animations.disable_animations()
                        except Exception:
                            pass
                        self.direct_shield.start_shield()
                    else:
                        self.direct_shield.stop_shield()
                        try:
                            self.window_animations.restore()
                        except Exception:
                            pass
                        self.mirror_engine.start_sharing()
                if self._panic_active:
                    self.set_panic(True)

            sharing = self._sharing_active
            self.clipboard_guard.configure(
                enabled=self.config.clipboard_guard_enabled,
                active_sharing=sharing,
                auto_clear=self.config.clipboard_auto_clear,
            )
            if sharing:
                if self.config.auto_focus_assist:
                    self.focus_assist.enable_silence()
                else:
                    self.focus_assist.restore()

            if self._zone_overlays_active:
                self.zone_overlays.sync(self.config.zones, True)
            if hotkeys_changed:
                self._sync_hotkeys()
            return self.get_state()

    def add_rule(self, rule_data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            payload = dict(rule_data)
            payload.setdefault("id", f"rule_{uuid.uuid4().hex[:8]}")
            rule = PrivacyRule.model_validate(payload)
            rules = [*self.config.rules, rule]
            self.config = self.config.model_copy(update={"rules": rules})
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            self.direct_shield.update_config(self.config)
            return self.get_state()

    def update_rule(self, rule_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            found = False
            updated_rules: list[PrivacyRule] = []
            for r in self.config.rules:
                if r.id == rule_id:
                    found = True
                    merged = r.model_dump()
                    for k, v in patch.items():
                        if k != "id" and k in merged:
                            merged[k] = v
                    updated_rules.append(PrivacyRule.model_validate(merged))
                else:
                    updated_rules.append(r)
            if not found:
                return None
            self.config = self.config.model_copy(update={"rules": updated_rules})
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            self.direct_shield.update_config(self.config)
            return self.get_state()

    def delete_rule(self, rule_id: str) -> dict[str, Any] | None:
        with self._lock:
            filtered = [r for r in self.config.rules if r.id != rule_id]
            if len(filtered) == len(self.config.rules):
                return None
            self.config = self.config.model_copy(update={"rules": filtered})
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            self.direct_shield.update_config(self.config)
            return self.get_state()

    def add_zone(self, zone_data: dict[str, Any]) -> dict[str, Any]:
        with self._lock:
            payload = dict(zone_data)
            payload.setdefault("id", f"zone_{uuid.uuid4().hex[:8]}")
            zone = StaticZone.model_validate(payload)
            zones = [*self.config.zones, zone]
            self.config = self.config.model_copy(update={"zones": zones})
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            if self._zone_overlays_active:
                self.zone_overlays.sync(self.config.zones, True)
            return self.get_state()

    def update_zone(self, zone_id: str, patch: dict[str, Any]) -> dict[str, Any] | None:
        with self._lock:
            found = False
            updated_zones: list[StaticZone] = []
            for z in self.config.zones:
                if z.id == zone_id:
                    found = True
                    merged = z.model_dump()
                    for k, v in patch.items():
                        if k != "id" and k in merged:
                            merged[k] = v
                    updated_zones.append(StaticZone.model_validate(merged))
                else:
                    updated_zones.append(z)
            if not found:
                return None
            self.config = self.config.model_copy(update={"zones": updated_zones})
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            if self._zone_overlays_active:
                self.zone_overlays.sync(self.config.zones, True)
            return self.get_state()

    def delete_zone(self, zone_id: str) -> dict[str, Any] | None:
        with self._lock:
            filtered = [z for z in self.config.zones if z.id != zone_id]
            if len(filtered) == len(self.config.zones):
                return None
            self.config = self.config.model_copy(update={"zones": filtered})
            self.store.save(self.config)
            self.mirror_engine.update_config(self.config)
            if self._zone_overlays_active:
                self.zone_overlays.sync(self.config.zones, True)
            return self.get_state()

    def list_windows(self) -> list[dict[str, Any]]:
        with self._lock:
            rules = list(self.config.rules)
            allowset = set(self.config.allowlist_hwnds)
            blocked_set = set(self.config.blocked_hwnds)
        windows = enumerate_windows(exclude_own_pid=True)
        items: list[dict[str, Any]] = []
        for win in windows:
            sensitive, reasons = is_window_sensitive(win, rules)
            manual_blocked = win.hwnd in blocked_set
            item = win.to_dict()
            item["sensitive"] = sensitive
            item["matched_rules"] = reasons
            item["allowlisted"] = win.hwnd in allowset
            item["manual_blocked"] = manual_blocked
            item["shielded"] = sensitive or manual_blocked
            items.append(item)
        return items

    def list_monitors(self) -> list[dict[str, Any]]:
        try:
            with mss.mss() as sct:
                mons = []
                for idx, mon in enumerate(sct.monitors[1:], start=1):
                    mons.append(
                        {
                            "index": idx,
                            "left": int(mon["left"]),
                            "top": int(mon["top"]),
                            "width": int(mon["width"]),
                            "height": int(mon["height"]),
                        }
                    )
                return mons
        except Exception:
            return [{"index": 1, "left": 0, "top": 0, "width": 1920, "height": 1080}]

    def clear_clipboard_alerts(self) -> dict[str, Any]:
        self.clipboard_guard.clear_alerts()
        return self.get_state()

    def get_state(self) -> dict[str, Any]:
        with self._lock:
            mirror_metrics = self.mirror_engine.get_metrics()
            direct_metrics = self.direct_shield.get_metrics()
            unified_metrics = {
                **mirror_metrics,
                "sharing": self._sharing_active,
                "panic": self._panic_active,
                "shield_mode": self.config.shield_mode,
                "active_shields": direct_metrics["active_shields"],
                "events_processed": direct_metrics["events_processed"],
                "last_latency_ms": direct_metrics["last_latency_ms"],
                "avg_latency_ms": direct_metrics["avg_latency_ms"],
            }
            return {
                "config": self.config.model_dump(mode="json"),
                "metrics": unified_metrics,
                "direct_metrics": direct_metrics,
                "focus_silenced": self.focus_assist.is_silenced,
                "zone_overlays_active": self._zone_overlays_active,
                "mirror_window_visible": self.mirror_window.is_visible,
                "hotkey_status": dict(self._hotkey_status),
                "clipboard_alerts": self.clipboard_guard.get_alerts(),
            }

    def shutdown(self) -> None:
        try:
            self.stop_sharing()
        except Exception:
            pass
        try:
            self.direct_shield.stop()
        except Exception:
            pass
        try:
            self.hotkeys.stop()
        except Exception:
            pass
        try:
            self.clipboard_guard.stop()
        except Exception:
            pass
        try:
            self.zone_overlays.stop()
        except Exception:
            pass
        try:
            self.mirror_engine.stop()
        except Exception:
            pass
        try:
            self.mirror_window.stop()
        except Exception:
            pass
        try:
            self.window_animations.restore()
        except Exception:
            pass
        try:
            self.focus_assist.restore()
        except Exception:
            pass
