"""Provider adapter base class.

A provider adapter is a thin shim between ForwardGuard and a specific vendor's
API for the forwarder-configuration surface. Each adapter implements
list_forwarders() against the vendor's own API.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True, slots=True)
class Forwarder:
    """A single forwarder record as returned by a provider adapter."""

    source: str              # name@domain.tld or '*@domain.tld'
    destination: str         # external address
    provider: str            # provider-adapter name
    domain: str              # the domain under audit
    forwarder_id: str = ""   # provider-side identifier if any
    extra: dict[str, Any] = field(default_factory=dict)

    def key(self) -> tuple[str, str, str, str]:
        """A tuple suitable for set-membership comparisons across polls."""
        return (self.provider, self.domain, self.source, self.destination)


class Provider(ABC):
    """Base class — subclass per vendor adapter."""

    name: str = "base"

    def __init__(self, config: dict[str, Any]) -> None:
        self.config = config
        self.domain: str = config["domain"]

    @abstractmethod
    def list_forwarders(self) -> list[Forwarder]:
        """Enumerate currently-configured forwarders for the configured domain.

        Must be read-only. If the vendor does not expose an API, the adapter
        may fall back to an authenticated headless-browser scrape of the UI,
        but SHOULD prefer the API.
        """
