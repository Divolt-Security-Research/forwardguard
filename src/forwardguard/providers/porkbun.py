"""Porkbun email-forwarder adapter (REST API).

API docs: https://porkbun.com/api/json/v3/documentation#Email%20Forwarding
Endpoint: POST /api/json/v3/email/forwards/<domain> with {apikey, secretapikey}
"""
from __future__ import annotations

import httpx

from .base import Forwarder, Provider


class PorkbunProvider(Provider):
    name = "porkbun"
    _ENDPOINT = "https://api.porkbun.com/api/json/v3/email/forwards/{domain}"

    def list_forwarders(self) -> list[Forwarder]:
        body = {
            "apikey":       self.config["apikey"],
            "secretapikey": self.config["secretapikey"],
        }
        url = self._ENDPOINT.format(domain=self.domain)
        with httpx.Client(timeout=15) as c:
            r = c.post(url, json=body)
            r.raise_for_status()
            data = r.json()

        if data.get("status") != "SUCCESS":
            raise RuntimeError(f"porkbun api: {data.get('message','unknown error')}")

        return [
            Forwarder(
                source=f"{row['source']}@{self.domain}",
                destination=row["destination"],
                provider=self.name,
                domain=self.domain,
                forwarder_id=str(row.get("id", "")),
            )
            for row in data.get("forwards", [])
        ]
