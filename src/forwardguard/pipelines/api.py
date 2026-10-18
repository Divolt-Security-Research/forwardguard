"""P-API — poll provider forwarder lists and alert on deltas vs a baseline."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

from ..alert import Alert, Severity
from ..providers import REGISTRY

log = logging.getLogger(__name__)


class ApiPipeline:
    name = "P-API"

    def __init__(self, state_dir: str | Path, whitelist: list[str] | None = None) -> None:
        self.state_dir = Path(state_dir)
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.whitelist = set(whitelist or [])

    def _state_file(self, provider: str, domain: str) -> Path:
        return self.state_dir / f"{provider}__{domain}.json"

    def _load_baseline(self, provider: str, domain: str) -> set[tuple] | None:
        """Return None if no baseline has ever been established; the set otherwise.

        Distinguishing an *empty* baseline (zero forwarders known-good) from
        *no* baseline (never polled) is essential: the first legitimate addition
        would otherwise be suppressed. See test_whitelisted_destination_is_low.
        """
        f = self._state_file(provider, domain)
        if not f.exists(): return None
        return {tuple(x) for x in json.loads(f.read_text())}

    def _save_baseline(self, provider: str, domain: str, baseline: set[tuple]) -> None:
        self._state_file(provider, domain).write_text(json.dumps(sorted(list(baseline))))

    def run(self, provider_configs: list[dict[str, Any]]) -> list[Alert]:
        alerts: list[Alert] = []
        for cfg in provider_configs:
            provider_type = cfg["type"]
            if provider_type not in REGISTRY:
                log.warning("Unknown provider type: %s", provider_type); continue
            try:
                provider = REGISTRY[provider_type](cfg)
                current = {f.key() for f in provider.list_forwarders()}
            except Exception as e:  # noqa: BLE001
                alerts.append(Alert(
                    pipeline=self.name,
                    severity=Severity.MEDIUM,
                    event_type="provider_api_error",
                    domain=cfg["domain"],
                    mailbox="",
                    destination=None, forwarder_id=None,
                    details={"error": str(e), "provider": provider_type},
                ))
                continue

            baseline = self._load_baseline(provider_type, cfg["domain"])
            if baseline is None:
                self._save_baseline(provider_type, cfg["domain"], current)
                log.info("Established baseline for %s/%s (%d forwarders)",
                         provider_type, cfg["domain"], len(current))
                continue

            for key in current - baseline:
                _, _, src, dst = key
                severity = Severity.HIGH if dst not in self.whitelist else Severity.LOW
                alerts.append(Alert(
                    pipeline=self.name,
                    severity=severity,
                    event_type="forwarder_added",
                    domain=cfg["domain"],
                    mailbox=src,
                    destination=dst,
                    forwarder_id=None,
                    details={"provider": provider_type, "in_whitelist": dst in self.whitelist},
                ))
            for key in baseline - current:
                _, _, src, dst = key
                alerts.append(Alert(
                    pipeline=self.name,
                    severity=Severity.LOW,
                    event_type="forwarder_removed",
                    domain=cfg["domain"],
                    mailbox=src,
                    destination=dst,
                    forwarder_id=None,
                    details={"provider": provider_type},
                ))
            self._save_baseline(provider_type, cfg["domain"], current)
        return alerts
