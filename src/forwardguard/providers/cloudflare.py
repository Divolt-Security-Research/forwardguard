"""Cloudflare Email Routing adapter.

API docs: https://developers.cloudflare.com/api/operations/email-routing-routing-rules-list-routing-rules
Endpoint: GET https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules
"""
from __future__ import annotations

import httpx
from .base import Provider, Forwarder


class CloudflareProvider(Provider):
    name = "cloudflare"
    _ENDPOINT = "https://api.cloudflare.com/client/v4/zones/{zone_id}/email/routing/rules"

    def list_forwarders(self) -> list[Forwarder]:
        zone_id = self.config["zone_id"]
        token = self.config["api_token"]
        headers = {"Authorization": f"Bearer {token}"}

        with httpx.Client(timeout=15) as c:
            r = c.get(self._ENDPOINT.format(zone_id=zone_id), headers=headers)
            r.raise_for_status()
            body = r.json()

        if not body.get("success"):
            raise RuntimeError(f"cloudflare api: {body.get('errors') or body}")

        out: list[Forwarder] = []
        for rule in body.get("result", []):
            # Each rule can have multiple matchers and multiple actions.
            # We flatten to one Forwarder per (matcher, destination).
            sources = [m.get("value", "") for m in rule.get("matchers", []) if m.get("field") == "to"]
            destinations: list[str] = []
            for act in rule.get("actions", []):
                if act.get("type") == "forward":
                    destinations.extend(act.get("value", []))
            for s in sources or [""]:
                for d in destinations:
                    out.append(Forwarder(
                        source=s or f"*@{self.domain}",
                        destination=d,
                        provider=self.name,
                        domain=self.domain,
                        forwarder_id=rule.get("tag", "") or rule.get("id", ""),
                    ))
        return out
