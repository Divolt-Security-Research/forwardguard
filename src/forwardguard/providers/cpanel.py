"""cPanel UAPI email-forwarder adapter.

UAPI docs: https://api.docs.cpanel.net/openapi/cpanel/operation/list_forwarders/

Auth: cPanel API token (preferred) in Authorization header:
    Authorization: cpanel <user>:<token>

Endpoint: GET https://<host>:2083/execute/Email/list_forwarders?domain=<d>
"""
from __future__ import annotations

import httpx
from .base import Provider, Forwarder


class CpanelProvider(Provider):
    name = "cpanel"

    def list_forwarders(self) -> list[Forwarder]:
        host = self.config["host"]
        user = self.config["user"]
        token = self.config["token"]
        verify = self.config.get("tls_verify", True)

        url = f"https://{host}:2083/execute/Email/list_forwarders"
        headers = {"Authorization": f"cpanel {user}:{token}"}

        with httpx.Client(timeout=15, verify=verify) as c:
            r = c.get(url, params={"domain": self.domain}, headers=headers)
            r.raise_for_status()
            body = r.json()

        if not body.get("status"):
            raise RuntimeError(f"cpanel uapi: {body.get('errors') or body}")

        rows = body.get("data") or []
        return [
            Forwarder(
                source=row["dest"],          # cPanel calls the source "dest"
                destination=row["forward"],  # and the destination "forward"
                provider=self.name,
                domain=self.domain,
                forwarder_id=str(row.get("id", "")),
                extra={"raw": row},
            )
            for row in rows
        ]
