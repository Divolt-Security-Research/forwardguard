# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities in ForwardGuard or in provider SMFPS
implementations to **security@divoltbtc.com**. We follow a 90-day
coordinated-disclosure policy, counted from the date the report lands at our
inbox.

Please include:

- The affected version or commit SHA of ForwardGuard.
- A minimal reproduction (configuration excerpt, log line, or packet trace).
- Your preferred disclosure attribution (handle, name, affiliation, or none).

We will acknowledge receipt within 72 hours and provide an initial triage
within 7 calendar days.

## Scope

In scope:

- Bugs in ForwardGuard code that allow (a) false negatives in detection,
  (b) false positives with high operational cost, (c) local privilege
  escalation on the host where ForwardGuard runs, or (d) credential leakage
  through logs, state files, or sink payloads.
- SMFPS specification errata that materially weaken the control baseline.

Out of scope:

- Findings in third-party dependencies — please report upstream and we will
  patch our pins.
- Weaknesses in provider mail-forwarding implementations (these are the
  motivating subject of the paper; see the paper's Section 1.2 for our
  coordinated-disclosure stance on vendor findings).

## PGP

A PGP key for security@divoltbtc.com is published at
<https://divoltbtc.com/.well-known/security.asc>.
