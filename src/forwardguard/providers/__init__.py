from .base import Forwarder, Provider
from .cloudflare import CloudflareProvider
from .cpanel import CpanelProvider
from .porkbun import PorkbunProvider

REGISTRY = {
    "porkbun":    PorkbunProvider,
    "cpanel":     CpanelProvider,
    "cloudflare": CloudflareProvider,
}

__all__ = ["REGISTRY", "Forwarder", "Provider"]
