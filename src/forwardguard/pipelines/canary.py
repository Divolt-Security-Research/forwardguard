"""P-CANARY — honeypot address.

A canary mailbox is a decoy address at the defender's domain whose only publication
surface is private configuration — never DNS, directory services, or any
customer-facing surface. Any mail received at the canary is prima facie evidence
of either a catch-all forwarder (silent-forwarder sub-primitive P3) or a DNS
enumeration event. The pipeline raises a high-severity alert on any receipt.
"""
from __future__ import annotations

import email
import imaplib
import logging
from typing import Any

from ..alert import Alert, Severity

log = logging.getLogger(__name__)


class CanaryPipeline:
    name = "P-CANARY"

    def run(self, canaries: list[dict[str, Any]]) -> list[Alert]:
        alerts: list[Alert] = []
        for c in canaries:
            host, user, pw = c["host"], c["user"], c["password"]
            try:
                conn = imaplib.IMAP4_SSL(host)
                conn.login(user, pw)
                conn.select("INBOX")
                typ, data = conn.search(None, "UNSEEN")
                if typ != "OK": continue
                for num in data[0].split()[-50:]:
                    typ, msg_data = conn.fetch(num, "(BODY.PEEK[HEADER])")
                    if typ != "OK" or not msg_data: continue
                    msg = email.message_from_bytes(msg_data[0][1])
                    alerts.append(Alert(
                        pipeline=self.name,
                        severity=Severity.CRITICAL,
                        event_type="canary_mailbox_hit",
                        domain=c["domain"],
                        mailbox=user,
                        destination=None, forwarder_id=None,
                        details={
                            "from":       (msg.get("From") or "")[:200],
                            "subject":    (msg.get("Subject") or "")[:200],
                            "message_id": msg.get("Message-ID", ""),
                        },
                    ))
                conn.close(); conn.logout()
            except Exception as e:  # noqa: BLE001
                alerts.append(Alert(
                    pipeline=self.name,
                    severity=Severity.LOW,
                    event_type="canary_imap_error",
                    domain=c.get("domain", ""),
                    mailbox=c.get("user", ""),
                    destination=None, forwarder_id=None,
                    details={"error": str(e)},
                ))
        return alerts
