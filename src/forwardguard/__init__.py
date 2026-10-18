"""ForwardGuard — continuous audit tooling for silent email-forwarder detection.

Reference implementation of the four defender-side detection pipelines
specified in Section 7 of the paper
"Silent-Forwarder: Measurement and Mitigation of Covert Email Redirection
in Domain Registrars and Shared-Hosting Control Panels"
(Divolt Security Research, 2026).

Pipelines:
    P-API    - Provider-side forwarder enumeration via vendor APIs.
    P-IMAP   - Victim-side envelope inspection on the inbox.
    P-SMTP   - Victim-side submission/MTA log correlation.
    P-CANARY - Honeypot-address catch-all detection.
"""

from .alert import Alert, AlertSink
from .pipelines.api import ApiPipeline
from .pipelines.canary import CanaryPipeline
from .pipelines.imap import ImapPipeline
from .pipelines.smtp import SmtpPipeline
from .providers.base import Forwarder, Provider

__version__ = "0.1.0"
__all__ = [
    "Alert",
    "AlertSink",
    "ApiPipeline",
    "CanaryPipeline",
    "Forwarder",
    "ImapPipeline",
    "Provider",
    "SmtpPipeline",
]
