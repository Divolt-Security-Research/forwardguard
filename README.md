# ForwardGuard

**Continuous audit tooling for silent email-forwarder detection in domain registrars and shared-hosting cPanel environments.**

[![License: Apache 2.0](https://img.shields.io/badge/License-Apache_2.0-blue.svg)](https://opensource.org/licenses/Apache-2.0)
[![Python 3.11+](https://img.shields.io/badge/python-3.11+-blue.svg)](https://www.python.org/downloads/)
[![Paper: arXiv](https://img.shields.io/badge/paper-arXiv-b31b1b.svg)](https://arxiv.org/)
[![Standard: SMFPS](https://img.shields.io/badge/standard-SMFPS--draft-green.svg)](https://github.com/divolt-research/smfps)

---

## What is this?

ForwardGuard is the reference implementation of the continuous defender-side detection
pipelines specified in Section 7 of the paper
*"Silent-Forwarder: Measurement and Mitigation of Covert Email Redirection in
Domain Registrars and Shared-Hosting Control Panels"* (Divolt Security Research, 2026).

It detects **silent email forwarders** — forwarding rules installed at your
domain registrar or shared-hosting cPanel without the mailbox owner's knowledge —
using only vendor APIs and IMAP/SMTP header metadata. **No destructive testing.**

The silent-forwarder primitive converts a single-step registrar-account compromise
or a support-ticket social-engineering event into a persistent, invisible
account-takeover posture across every service that uses email as a recovery
channel. If you own a domain and mail is a reset channel for any account on it,
you need to know whether a forwarder was added without your consent.

## Why four pipelines?

| Pipeline | Vantage point | Detects |
|---|---|---|
| **P-API** | Provider APIs (registrar / cPanel UAPI) | Direct enumeration of configured forwarders; detects additions and removals |
| **P-IMAP** | Victim-side IMAP inbox | Envelope artefacts of forwarded delivery (`Delivered-To`, `X-Forwarded-To`, hop-count anomalies) |
| **P-SMTP** | Victim-side MTA / submission log | Outbound traffic to unexpected destinations attributable to forwarder-chained delivery |
| **P-CANARY** | Honeypot address at the domain | Catch-all forwarders and DNS enumeration campaigns |

They are independent and complementary; most deployments run all four. A silent
forwarder detectable by P-API alone may be removed by an attacker who notices the
pipeline running; it will still appear in P-IMAP and P-SMTP traces of mail already
exfiltrated.

## Quick start

```bash
# Clone and install
git clone https://github.com/divolt-research/forwardguard.git
cd forwardguard
pip install -e .

# Point at your providers (edit this to your own domains and credentials)
cp config.example.yaml config.yaml
$EDITOR config.yaml

# One-shot run (useful for cron)
forwardguard --config config.yaml --once

# Continuous (daemon mode, syslog output)
forwardguard --config config.yaml --daemon
```

Docker:

```bash
docker run --rm -v $(pwd)/config.yaml:/etc/forwardguard/config.yaml \
    ghcr.io/divolt-research/forwardguard:latest --once
```

## Supported providers

The initial release ships adapters for the providers below. The `Provider` base class
is a 20-line interface; adding a new one is a weekend project. PRs welcome.

| Provider | P-API | P-IMAP | P-SMTP | P-CANARY | Notes |
|---|:-:|:-:|:-:|:-:|---|
| Porkbun | ✅ | ✅ | ✅ | ✅ | REST API `/api/json/v3/email/forwards` |
| Namecheap | ✅ | ✅ | ✅ | ✅ | API v1.1 (`namecheap.domains.dns.getEmailForwarding`) |
| cPanel / WHM | ✅ | ✅ | ✅ | ✅ | UAPI `Email::list_forwarders` |
| Cloudflare Email Routing | ✅ | ✅ | ✅ | ✅ | API v4 `/zones/{id}/email/routing/rules` |
| Google Workspace | ⏳ | ✅ | ✅ | ✅ | Admin SDK adapter in progress (contributions welcome) |
| Microsoft 365 | ⏳ | ✅ | ✅ | ✅ | Graph adapter in progress |
| Generic IMAP | — | ✅ | — | ✅ | Works against any IMAP provider for the IMAP/CANARY pipelines |

## Alerting

The daemon emits alerts via one or more sinks, configured in `config.yaml`:

* **syslog** — RFC-5424 (`LOG_AUTH / LOG_ALERT` severity for high-severity events)
* **webhook** — JSON POST (compatible with Slack Incoming Webhooks, Discord, PagerDuty v2)
* **email** — SMTP to a secondary address (one you've verified is *not* subject to the forwarder being audited)
* **stdout** — for ad-hoc runs and Docker users

An alert payload matches the SMFPS Audit Event schema (Appendix A of the paper).

## Managed service

Running ForwardGuard against many domains, multiple providers, and 24/7 alerting
is operational work. If you'd rather not run it yourself, Divolt offers a managed
service with cross-provider correlation, SIEM integrations, SOC 2 / HIPAA
compliance reports, and incident-response assistance: see
<https://divoltbtc.com/forwardguard>.

The managed service is independent of this open-source core; one is not required
for the other.

## SMFPS

ForwardGuard is a *compensating control* — it detects silent forwarders after the
fact. The preventive fix is for providers to adopt **SMFPS** (Silent-Mail-Forwarding
Prevention Standard), an interoperable eight-requirement control baseline we are
submitting as an IETF Internet-Draft. The draft, a conformance test suite, and a
reference implementation live at <https://github.com/divolt-research/smfps>.

If you operate a registrar or hosting-control-panel product, we would love to
collaborate on an early SMFPS implementation.

## Research artefact

This repository is the companion artefact to the paper:

> Divolt Security Research. "Silent-Forwarder: Measurement and Mitigation of
> Covert Email Redirection in Domain Registrars and Shared-Hosting Control
> Panels." *arXiv preprint*, 2026.

Citing the paper is appreciated.

```bibtex
@misc{divolt2026silentforwarder,
    title        = {Silent-Forwarder: Measurement and Mitigation of Covert Email
                    Redirection in Domain Registrars and Shared-Hosting Control
                    Panels},
    author       = {{Divolt Security Research}},
    year         = 2026,
    howpublished = {\url{https://arxiv.org/abs/2611.XXXXX}}
}
```

## Security

Found a bug in ForwardGuard itself, or in a provider's SMFPS implementation
that you believe should be disclosed? See `SECURITY.md` or email
<security@divoltbtc.com>. We follow a 90-day coordinated-disclosure policy.

## Contributing

PRs, provider-adapter contributions, and measurement-sweep data are all welcome.
See `CONTRIBUTING.md`.

## License

Apache License 2.0. See `LICENSE`.

---

*Built by Divolt Security Research. Divolt is a security startup headquartered in
Accra, Ghana, researching mail-plane and identity-plane attack surfaces. We also
build the [Divolt Aegis](https://divoltbtc.com) continuous-pentest platform.*
