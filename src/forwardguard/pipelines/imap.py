"""P-IMAP — inspect IMAP inbox envelope for forwarding artefacts."""
from __future__ import annotations

import email
import imaplib
import logging
import re
from typing import Any

from ..alert import Alert, Severity

log = logging.getLogger(__name__)

# Headers that indicate a message has been forwarded through intermediate MTAs.
# A legitimate direct delivery usually has none of these.
_FORWARD_HEADERS = ("X-Forwarded-To", "X-Original-To", "Delivered-To",
                    "X-Forwarded-For", "Resent-To", "ARC-Authentication-Results")

_RECEIVED_HOP_RE = re.compile(r"from\s+([^\s]+)\s+by\s+([^\s]+)", re.IGNORECASE)


class ImapPipeline:
    name = "P-IMAP"

    def __init__(self, expected_hops: int = 2, whitelist: list[str] | None = None) -> None:
        self.expected_hops = expected_hops
        self.whitelist = set(whitelist or [])

    def _scan_message(self, raw: bytes) -> dict[str, Any]:
        msg = email.message_from_bytes(raw)
        received = msg.get_all("Received") or []
        hops = len(received)
        delivered_to = msg.get_all("Delivered-To") or []
        x_forwarded_to = msg.get_all("X-Forwarded-To") or []
        return {
            "message_id":     msg.get("Message-ID", ""),
            "subject":        (msg.get("Subject") or "")[:120],
            "hops":           hops,
            "delivered_to":   delivered_to,
            "x_forwarded_to": x_forwarded_to,
        }

    def run(self, mailboxes: list[dict[str, Any]]) -> list[Alert]:
        alerts: list[Alert] = []
        for mb in mailboxes:
            host, user, pw = mb["host"], mb["user"], mb["password"]
            try:
                conn = imaplib.IMAP4_SSL(host)
                conn.login(user, pw)
                conn.select("INBOX")
                typ, data = conn.search(None, "UNSEEN")
                if typ != "OK": continue
                for num in data[0].split()[-50:]:
                    typ, msg_data = conn.fetch(num, "(BODY.PEEK[HEADER])")
                    if typ != "OK" or not msg_data: continue
                    info = self._scan_message(msg_data[0][1])

                    if info["hops"] > self.expected_hops:
                        alerts.append(Alert(
                            pipeline=self.name,
                            severity=Severity.MEDIUM,
                            event_type="unexpected_hop_count",
                            domain=mb["domain"],
                            mailbox=user,
                            destination=None, forwarder_id=None,
                            details={"hops": info["hops"], "expected": self.expected_hops, "subject": info["subject"]},
                        ))

                    for d in info["delivered_to"]:
                        if d and d.strip().lower() != user.lower() and d not in self.whitelist:
                            alerts.append(Alert(
                                pipeline=self.name,
                                severity=Severity.HIGH,
                                event_type="foreign_delivered_to",
                                domain=mb["domain"], mailbox=user,
                                destination=d, forwarder_id=None,
                                details={"message_id": info["message_id"], "subject": info["subject"]},
                            ))
                    for d in info["x_forwarded_to"]:
                        if d and d not in self.whitelist:
                            alerts.append(Alert(
                                pipeline=self.name,
                                severity=Severity.HIGH,
                                event_type="foreign_forward_target",
                                domain=mb["domain"], mailbox=user,
                                destination=d, forwarder_id=None,
                                details={"message_id": info["message_id"], "subject": info["subject"]},
                            ))
                conn.close(); conn.logout()
            except Exception as e:  # noqa: BLE001
                alerts.append(Alert(
                    pipeline=self.name,
                    severity=Severity.LOW,
                    event_type="imap_error",
                    domain=mb.get("domain", ""),
                    mailbox=user,
                    destination=None, forwarder_id=None,
                    details={"error": str(e)},
                ))
        return alerts
