from .base import Provider, Forwarder
from .porkbun import PorkbunProvider
from .cpanel import CpanelProvider
from .cloudflare import CloudflareProvider

REGISTRY = {
    "porkbun":    PorkbunProvider,
    "cpanel":     CpanelProvider,
    "cloudflare": CloudflareProvider,
}

__all__ = ["Provider", "Forwarder", "REGISTRY"]
