"""Alert model and sink interface.

An Alert is a structured representation of a single detection event that one
or more pipelines raise. Alerts are serialised to the SMFPS Audit Event JSON
Schema (see Appendix A of the paper) before being handed to a sink.
"""
from __future__ import annotations

import json
import logging
import syslog
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import Enum
from typing import Any
from uuid import uuid4

import httpx


class Severity(str, Enum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


@dataclass(slots=True)
class Alert:
    """A single detection event in SMFPS-compatible form."""

    pipeline: str
    severity: Severity
    event_type: str
    domain: str
    mailbox: str
    destination: str | None
    forwarder_id: str | None
    details: dict[str, Any] = field(default_factory=dict)
    event_id: str = field(default_factory=lambda: str(uuid4()))
    timestamp: str = field(
        default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds")
    )

    def to_smfps(self) -> dict[str, Any]:
        """Serialise to SMFPS Audit Event schema (Appendix A of paper)."""
        return {
            "event_id":   self.event_id,
            "timestamp":  self.timestamp,
            "event_type": self.event_type,
            "actor": {
                "principal_type": "forwardguard_detector",
                "principal_id":   self.pipeline,
                "session_id":     "",
                "ip":             "",
                "user_agent":     f"ForwardGuard/{__import__('forwardguard').__version__}",
            },
            "target": {
                "domain":       self.domain,
                "mailbox":      self.mailbox,
                "forwarder_id": self.forwarder_id or "",
                "destination":  self.destination or "",
            },
            "transport": {},
            "forwardguard": {
                "pipeline":   self.pipeline,
                "severity":   self.severity.value,
                "details":    self.details,
            },
        }

    def __str__(self) -> str:
        return (
            f"[{self.severity.value.upper():8}] {self.pipeline:9} "
            f"{self.event_type:28} "
            f"{self.mailbox} -> {self.destination or '-'}"
        )


# ---------- Sinks ----------
class AlertSink:
    """Base class — override emit() in subclasses."""

    name = "base"

    def emit(self, alert: Alert) -> None:  # pragma: no cover
        raise NotImplementedError


class StdoutSink(AlertSink):
    name = "stdout"

    def emit(self, alert: Alert) -> None:
        print(alert)


class SyslogSink(AlertSink):
    """RFC-5424 syslog, LOG_AUTH facility.

    High-severity ForwardGuard alerts map to syslog LOG_ALERT; medium / low to
    LOG_WARNING / LOG_NOTICE respectively. The payload is the SMFPS JSON event.
    """

    name = "syslog"

    def __init__(self) -> None:
        syslog.openlog(ident="forwardguard", facility=syslog.LOG_AUTH)

    _priority_map = {
        Severity.CRITICAL: syslog.LOG_ALERT,
        Severity.HIGH:     syslog.LOG_ALERT,
        Severity.MEDIUM:   syslog.LOG_WARNING,
        Severity.LOW:      syslog.LOG_NOTICE,
    }

    def emit(self, alert: Alert) -> None:
        syslog.syslog(self._priority_map[alert.severity], json.dumps(alert.to_smfps()))


class WebhookSink(AlertSink):
    """POST the SMFPS event as JSON to a webhook URL (Slack / Discord / PagerDuty)."""

    name = "webhook"

    def __init__(self, url: str, timeout_s: float = 10.0) -> None:
        self.url = url
        self._client = httpx.Client(timeout=timeout_s)

    def emit(self, alert: Alert) -> None:
        try:
            self._client.post(self.url, json=alert.to_smfps())
        except httpx.RequestError as e:
            logging.getLogger(__name__).warning("Webhook POST failed: %s", e)
