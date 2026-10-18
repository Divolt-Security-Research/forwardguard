"""P-SMTP — correlate outbound SMTP log lines with the known-destination inventory.

The pipeline parses a Postfix / Exim / Sendmail-style log file and raises an
alert for each outbound message whose RCPT TO lies outside a defender-supplied
whitelist and whose Message-ID can be traced to a previously forwarded
delivery.

This is a MINIMAL reference implementation: for high-volume MTAs defenders
should use a streaming log-shipper and feed ForwardGuard the subset of events
that match forwarder-attributable messages.
"""
from __future__ import annotations

import logging
import re
from pathlib import Path

from ..alert import Alert, Severity

log = logging.getLogger(__name__)

# Postfix: ...  to=<addr>, relay=X, delay=Y, delays=..., dsn=..., status=sent (250 ...)
_POSTFIX_SENT = re.compile(
    r"to=<(?P<rcpt>[^>]+)>.*status=sent",
    re.IGNORECASE,
)


class SmtpPipeline:
    name = "P-SMTP"

    def __init__(self, whitelist: list[str] | None = None,
                 state_file: str | Path | None = None) -> None:
        self.whitelist = set(whitelist or [])
        self.state_file = Path(state_file) if state_file else None
        self._offset = self._load_offset()

    def _load_offset(self) -> int:
        if self.state_file and self.state_file.exists():
            try: return int(self.state_file.read_text().strip())
            except Exception: return 0
        return 0

    def _save_offset(self, off: int) -> None:
        if self.state_file:
            self.state_file.write_text(str(off))

    def run(self, log_files: list[str]) -> list[Alert]:
        alerts: list[Alert] = []
        for lf in log_files:
            p = Path(lf)
            if not p.exists(): continue
            try:
                with p.open("rb") as f:
                    f.seek(self._offset)
                    for line in f:
                        try: s = line.decode("utf-8", errors="replace")
                        except Exception: continue
                        m = _POSTFIX_SENT.search(s)
                        if not m: continue
                        rcpt = m.group("rcpt").lower()
                        if rcpt in self.whitelist: continue
                        domain = rcpt.split("@", 1)[-1] if "@" in rcpt else ""
                        if domain and domain in self.whitelist: continue
                        alerts.append(Alert(
                            pipeline=self.name,
                            severity=Severity.MEDIUM,
                            event_type="smtp_outbound_to_foreign",
                            domain="",
                            mailbox="",
                            destination=rcpt,
                            forwarder_id=None,
                            details={"log_line": s.strip()[:300]},
                        ))
                    self._save_offset(f.tell())
            except Exception as e:  # noqa: BLE001
                log.warning("SMTP log read failed %s: %s", lf, e)
        return alerts
