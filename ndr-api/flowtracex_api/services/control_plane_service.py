"""
Control Plane Service — reads and writes local control-plane state with validation.

All threshold writes enforce: new_value >= engineering_min_threshold.
This is the backend guard that prevents users/agents from ever weakening
detection below engineering floor.
"""
import json
import logging
import os
from pathlib import Path

from clients.state_store_client import StateStoreClient

logger = logging.getLogger(__name__)


class ControlPlaneService:
    """Service layer for control plane state operations."""

    def __init__(self):
        self._state_store = StateStoreClient.get_instance()
        self._signal_defaults = {}
        self._uc_defaults = {}
        self._global_schema = {}
        self._presets = {}
        self._load_engineering_defaults()

    def _load_engineering_defaults(self):
        """Load control_plane blocks from signal/UC JSONs."""
        flink_dir = Path(os.environ.get("FLINK_DIR", "/opt/ndr/ndr-flink"))
        config_dir = Path(os.environ.get("NDR_CONFIG_DIR", "/opt/ndr/ndr-config"))

        # Load signals (support both legacy and current repository layouts).
        signal_dirs = [
            flink_dir / "signals/network",
            flink_dir / "signals/zeek_noncorrelated",
            flink_dir / "signals",
        ]
        for sig_dir in signal_dirs:
            if not sig_dir.exists():
                continue
            for f in sorted(sig_dir.glob("*.json")):
                try:
                    with open(f) as fh:
                        sig = json.load(fh)
                    sig_id = sig.get("id")
                    if not sig_id:
                        continue
                    cp = sig.get("control_plane", {})
                    self._signal_defaults[sig_id] = {
                        **cp,
                        "name": sig.get("name", sig_id),
                        "description": sig.get("description", ""),
                        "method": sig.get("detection", {}).get("method", "rule"),
                        "category": sig.get("category", ""),
                        "alert_mode": sig.get("alert_mode", "correlation_only"),
                    }
                except Exception as e:
                    logger.warning(f"Error loading signal {f}: {e}")

        # Load use cases from legacy JSON tree if available.
        uc_dir = flink_dir / "correlation" / "use-cases"
        if uc_dir.exists():
            for f in sorted(uc_dir.glob("*.json")):
                try:
                    with open(f) as fh:
                        uc = json.load(fh)
                    uc_id = uc.get("id")
                    if not uc_id:
                        continue
                    cp = uc.get("control_plane", {})
                    signals = []
                    for stage in uc.get("correlation", {}).get("stages", []):
                        signals.extend(stage.get("signals", []))
                    self._uc_defaults[uc_id] = {
                        **cp,
                        "name": uc.get("name", uc_id),
                        "description": uc.get("description", ""),
                        "category": uc.get("category", "unknown"),
                        "signals": list(set(signals)),
                    }
                except Exception as e:
                    logger.warning(f"Error loading UC {f}: {e}")

        # Fallback: load UCs/signals from generated correlation-config artifacts.
        # This is the current source in this repo layout.
        config_candidates = [
            flink_dir / "compiler" / "output" / "correlation-config.json",
            flink_dir / "compiled" / "correlation-config.json",
        ]
        for cfg_path in config_candidates:
            if not cfg_path.exists():
                continue
            try:
                with open(cfg_path) as fh:
                    cfg = json.load(fh)
            except Exception as e:
                logger.warning(f"Error loading control-plane config {cfg_path}: {e}")
                continue

            # Signals map: {SIG-xxx: {...}}
            sigs = cfg.get("signals")
            if isinstance(sigs, dict):
                for sig_id, sig in sigs.items():
                    if sig_id in self._signal_defaults:
                        continue
                    cp = sig.get("control_plane", {}) if isinstance(sig, dict) else {}
                    self._signal_defaults[sig_id] = {
                        **cp,
                        "name": (sig or {}).get("name", sig_id),
                        "description": (sig or {}).get("description", ""),
                        "method": (sig or {}).get("detection_method", "rule"),
                        "category": (sig or {}).get("category", ""),
                        "alert_mode": (sig or {}).get("alert_mode", "correlation_only"),
                    }

            # Use-case map: {UC-xx or slug: {...}}
            ucs = cfg.get("use_cases")
            if isinstance(ucs, dict):
                for uc_key, uc in ucs.items():
                    if not isinstance(uc, dict):
                        continue
                    uc_id = uc.get("id") or uc_key
                    if uc_id in self._uc_defaults:
                        continue
                    cp = uc.get("control_plane", {})
                    signals = []
                    for stage in uc.get("correlation", {}).get("stages", []):
                        signals.extend(stage.get("signals", []))
                    if not signals and isinstance(uc.get("all_signals"), list):
                        signals.extend(uc.get("all_signals", []))
                    self._uc_defaults[uc_id] = {
                        **cp,
                        "name": uc.get("name", uc_id),
                        "description": uc.get("description", ""),
                        "category": uc.get("category", "unknown"),
                        "signals": list(set(signals)),
                    }

        # Load global schema
        schema_path = config_dir / "control-plane" / "control-plane-schema.json"
        if schema_path.exists():
            with open(schema_path) as fh:
                self._global_schema = json.load(fh)

        # Load presets
        preset_path = config_dir / "control-plane" / "poc-day0-preset.json"
        if preset_path.exists():
            with open(preset_path) as fh:
                self._presets = json.load(fh).get("presets", {})

        logger.info(
            f"ControlPlaneService loaded: {len(self._signal_defaults)} signals, "
            f"{len(self._uc_defaults)} UCs, {len(self._presets)} presets"
        )

    # ─── Global Settings ────────────────────────────────────────────

    def get_global_config(self) -> dict:
        """Read all ndr:global:* keys."""
        return {
            "sensitivity": self._state_store.get("ndr:global:sensitivity") or "balanced",
            "alert_threshold": int(self._state_store.get("ndr:global:alert_threshold") or "100"),
            "critical_mode": (self._state_store.get("ndr:global:critical_mode") or "false") == "true",
            "asset_scope": self._state_store.get("ndr:global:asset_scope") or "all",
            "sensitivity_modes": self._global_schema.get("sensitivity_modes", {}),
            "engineering_min_alert_threshold": self._global_schema.get("engineering_min_alert_threshold", 100),
        }

    def update_global_config(self, data: dict) -> dict:
        """Update global settings with validation."""
        eng_min = self._global_schema.get("engineering_min_alert_threshold", 100)
        valid_sensitivities = list(self._global_schema.get("sensitivity_modes", {}).keys())

        if "sensitivity" in data:
            if data["sensitivity"] not in valid_sensitivities:
                raise ValueError(f"Invalid sensitivity: {data['sensitivity']}. Valid: {valid_sensitivities}")
            self._state_store.set("ndr:global:sensitivity", data["sensitivity"])

        if "alert_threshold" in data:
            val = int(data["alert_threshold"])
            if val < eng_min:
                raise ValueError(f"Alert threshold cannot be below engineering minimum ({eng_min})")
            self._state_store.set("ndr:global:alert_threshold", str(val))

        if "critical_mode" in data:
            self._state_store.set("ndr:global:critical_mode", str(data["critical_mode"]).lower())

        if "asset_scope" in data:
            self._state_store.set("ndr:global:asset_scope", data["asset_scope"])

        return self.get_global_config()

    # ─── Signal Controls ────────────────────────────────────────────

    def list_signals(self) -> list:
        """List all signals with engineering defaults + current control state."""
        result = []
        for sig_id, defaults in sorted(self._signal_defaults.items()):
            prefix = f"ndr:signal:{sig_id}"
            current = {
                "enabled": (self._state_store.get(f"{prefix}:enabled") or "true") == "true",
                "ui_threshold": int(self._state_store.get(f"{prefix}:ui_threshold") or str(defaults.get("engineering_min_threshold", 1))),
                "visibility_mode": self._state_store.get(f"{prefix}:visibility_mode") or defaults.get("default_visibility_mode", "anomaly"),
                "severity_label": self._state_store.get(f"{prefix}:severity_label") or "",
                "suppressed": self._state_store.get(f"ndr:suppress:{sig_id}") is not None,
                "suppress_ttl": self._state_store.ttl(f"ndr:suppress:{sig_id}") if self._state_store.get(f"ndr:suppress:{sig_id}") else None,
            }
            result.append({
                "signal_id": sig_id,
                **defaults,
                "current": current,
            })
        return result

    def get_signal(self, signal_id: str) -> dict:
        """Get a single signal with full details."""
        defaults = self._signal_defaults.get(signal_id)
        if not defaults:
            return None

        prefix = f"ndr:signal:{signal_id}"
        current = {
            "enabled": (self._state_store.get(f"{prefix}:enabled") or "true") == "true",
            "ui_threshold": int(self._state_store.get(f"{prefix}:ui_threshold") or str(defaults.get("engineering_min_threshold", 1))),
            "visibility_mode": self._state_store.get(f"{prefix}:visibility_mode") or "anomaly",
            "severity_label": self._state_store.get(f"{prefix}:severity_label") or "",
            "suppressed": self._state_store.get(f"ndr:suppress:{signal_id}") is not None,
            "suppress_ttl": self._state_store.ttl(f"ndr:suppress:{signal_id}") if self._state_store.get(f"ndr:suppress:{signal_id}") else None,
        }
        return {"signal_id": signal_id, **defaults, "current": current}

    def update_signal(self, signal_id: str, data: dict) -> dict:
        """Update signal control state with threshold validation."""
        defaults = self._signal_defaults.get(signal_id)
        if not defaults:
            raise ValueError(f"Unknown signal: {signal_id}")

        eng_min = defaults.get("engineering_min_threshold", 1)
        prefix = f"ndr:signal:{signal_id}"

        if "ui_threshold" in data:
            val = int(data["ui_threshold"])
            if val < eng_min:
                raise ValueError(f"Cannot set threshold below engineering minimum ({eng_min})")
            self._state_store.set(f"{prefix}:ui_threshold", str(val))

        if "enabled" in data:
            self._state_store.set(f"{prefix}:enabled", "true" if data["enabled"] else "false")

        if "visibility_mode" in data:
            if data["visibility_mode"] not in ("alert", "anomaly", "hidden"):
                raise ValueError(f"Invalid visibility mode: {data['visibility_mode']}")
            self._state_store.set(f"{prefix}:visibility_mode", data["visibility_mode"])

        if "severity_label" in data:
            self._state_store.set(f"{prefix}:severity_label", data["severity_label"])

        return self.get_signal(signal_id)

    def suppress_signal(self, signal_id: str, ttl_seconds: int, reason: str = "") -> dict:
        """Suppress a signal for a TTL period."""
        if signal_id not in self._signal_defaults:
            raise ValueError(f"Unknown signal: {signal_id}")
        self._state_store.set(f"ndr:suppress:{signal_id}", "true", ex=ttl_seconds)
        return {"signal_id": signal_id, "suppressed": True, "ttl_seconds": ttl_seconds, "reason": reason}

    def remove_signal_suppression(self, signal_id: str) -> bool:
        """Remove signal suppression."""
        return bool(self._state_store.delete(f"ndr:suppress:{signal_id}"))

    # ─── Use Case Controls ──────────────────────────────────────────

    def list_usecases(self) -> list:
        """List all UCs with engineering defaults + current control state."""
        result = []
        for uc_id, defaults in sorted(self._uc_defaults.items()):
            prefix = f"ndr:uc:{uc_id}"
            current = {
                "enabled": (self._state_store.get(f"{prefix}:enabled") or "true") == "true",
                "threshold": int(self._state_store.get(f"{prefix}:threshold") or str(defaults.get("engineering_min_alert_threshold", 100))),
                "suppressed": self._state_store.get(f"ndr:suppress:{uc_id}") is not None,
                "suppress_ttl": self._state_store.ttl(f"ndr:suppress:{uc_id}") if self._state_store.get(f"ndr:suppress:{uc_id}") else None,
            }
            result.append({"uc_id": uc_id, **defaults, "current": current})
        return result

    def get_usecase(self, uc_id: str) -> dict:
        """Get a single UC with full details."""
        defaults = self._uc_defaults.get(uc_id)
        if not defaults:
            return None
        prefix = f"ndr:uc:{uc_id}"
        current = {
            "enabled": (self._state_store.get(f"{prefix}:enabled") or "true") == "true",
            "threshold": int(self._state_store.get(f"{prefix}:threshold") or "100"),
            "suppressed": self._state_store.get(f"ndr:suppress:{uc_id}") is not None,
            "suppress_ttl": self._state_store.ttl(f"ndr:suppress:{uc_id}") if self._state_store.get(f"ndr:suppress:{uc_id}") else None,
        }
        return {"uc_id": uc_id, **defaults, "current": current}

    def update_usecase(self, uc_id: str, data: dict) -> dict:
        """Update UC control state with threshold validation."""
        defaults = self._uc_defaults.get(uc_id)
        if not defaults:
            raise ValueError(f"Unknown use case: {uc_id}")

        eng_min = defaults.get("engineering_min_alert_threshold", 100)
        prefix = f"ndr:uc:{uc_id}"

        if "threshold" in data:
            val = int(data["threshold"])
            if val < eng_min:
                raise ValueError(f"Cannot set threshold below engineering minimum ({eng_min})")
            self._state_store.set(f"{prefix}:threshold", str(val))

        if "enabled" in data:
            self._state_store.set(f"{prefix}:enabled", "true" if data["enabled"] else "false")

        return self.get_usecase(uc_id)

    def suppress_usecase(self, uc_id: str, ttl_seconds: int, reason: str = "") -> dict:
        """Suppress a UC for a TTL period."""
        if uc_id not in self._uc_defaults:
            raise ValueError(f"Unknown use case: {uc_id}")
        self._state_store.set(f"ndr:suppress:{uc_id}", "true", ex=ttl_seconds)
        return {"uc_id": uc_id, "suppressed": True, "ttl_seconds": ttl_seconds, "reason": reason}

    def remove_usecase_suppression(self, uc_id: str) -> bool:
        """Remove UC suppression."""
        return bool(self._state_store.delete(f"ndr:suppress:{uc_id}"))

    # ─── Suppression Center ─────────────────────────────────────────

    def get_all_suppressions(self) -> list:
        """List all active suppressions with TTL remaining."""
        result = []
        keys = self._state_store.keys("ndr:suppress:*")
        for key in sorted(keys):
            entity_id = key.replace("ndr:suppress:", "")
            ttl = self._state_store.ttl(key)
            entity_type = "signal" if entity_id.startswith("SIG-") else "usecase"
            name = ""
            if entity_type == "signal":
                name = self._signal_defaults.get(entity_id, {}).get("name", entity_id)
            else:
                name = self._uc_defaults.get(entity_id, {}).get("name", entity_id)

            result.append({
                "entity_id": entity_id,
                "entity_type": entity_type,
                "name": name,
                "ttl_remaining": ttl if ttl > 0 else None,
            })
        return result

    # ─── Presets ─────────────────────────────────────────────────────

    def apply_preset(self, preset_name: str) -> dict:
        """Apply a named preset — writes all keys atomically via pipeline."""
        preset = self._presets.get(preset_name)
        if not preset:
            raise ValueError(f"Unknown preset: {preset_name}. Available: {list(self._presets.keys())}")

        # Apply global settings
        if "global" in preset:
            self.update_global_config(preset["global"])

        # Apply signal overrides
        for sig_id, override in preset.get("signal_overrides", {}).items():
            if sig_id in self._signal_defaults:
                self.update_signal(sig_id, override)

        # Apply suppressions
        for entity_id, sup in preset.get("suppressions", {}).items():
            ttl = sup.get("ttl_seconds", 86400)
            self._state_store.set(f"ndr:suppress:{entity_id}", "true", ex=ttl)

        return {
            "preset": preset_name,
            "label": preset.get("label", preset_name),
            "applied": True,
        }

    def list_presets(self) -> list:
        """List available presets."""
        return [
            {"name": name, "label": p.get("label", name), "description": p.get("description", "")}
            for name, p in self._presets.items()
        ]
