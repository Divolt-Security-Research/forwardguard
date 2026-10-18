"""ForwardGuard CLI entry point."""
from __future__ import annotations

import logging
import sys
import time
from pathlib import Path

import typer
import yaml

from .alert import StdoutSink, SyslogSink, WebhookSink
from .pipelines.api    import ApiPipeline
from .pipelines.imap   import ImapPipeline
from .pipelines.smtp   import SmtpPipeline
from .pipelines.canary import CanaryPipeline

app = typer.Typer(add_completion=False, help="ForwardGuard — silent-forwarder detector.")
log = logging.getLogger("forwardguard")


def _build_sinks(cfg: dict) -> list:
    sinks = []
    for s in cfg.get("sinks", [{"type": "stdout"}]):
        t = s["type"]
        if   t == "stdout":  sinks.append(StdoutSink())
        elif t == "syslog":  sinks.append(SyslogSink())
        elif t == "webhook": sinks.append(WebhookSink(url=s["url"]))
    return sinks


def _run_once(cfg: dict) -> int:
    whitelist = cfg.get("whitelist_destinations", [])
    sinks = _build_sinks(cfg)
    alerts = []

    if cfg.get("providers"):
        alerts.extend(ApiPipeline(
            state_dir=cfg.get("state_dir", "./state"),
            whitelist=whitelist,
        ).run(cfg["providers"]))

    if cfg.get("imap_mailboxes"):
        alerts.extend(ImapPipeline(
            expected_hops=cfg.get("expected_hops", 2),
            whitelist=whitelist,
        ).run(cfg["imap_mailboxes"]))

    if cfg.get("smtp_logs"):
        alerts.extend(SmtpPipeline(
            whitelist=whitelist,
            state_file=cfg.get("smtp_state_file"),
        ).run(cfg["smtp_logs"]))

    if cfg.get("canaries"):
        alerts.extend(CanaryPipeline().run(cfg["canaries"]))

    for a in alerts:
        for s in sinks:
            try: s.emit(a)
            except Exception as e: log.error("sink %s failed: %s", s.name, e)

    log.info("Emitted %d alerts across %d sinks", len(alerts), len(sinks))
    return len(alerts)


@app.command()
def main(
    config: Path = typer.Option(..., "--config", "-c", help="Path to config.yaml"),
    once: bool = typer.Option(False, "--once", help="Single run (useful for cron)"),
    daemon: bool = typer.Option(False, "--daemon", help="Continuous loop"),
    interval: int = typer.Option(300, "--interval", help="Seconds between daemon runs"),
    verbose: bool = typer.Option(False, "-v", "--verbose"),
) -> None:
    """Run ForwardGuard against the providers declared in CONFIG."""
    logging.basicConfig(
        level=logging.DEBUG if verbose else logging.INFO,
        format="%(asctime)s %(levelname)s %(name)s - %(message)s",
    )
    if not config.exists():
        log.error("config not found: %s", config); sys.exit(2)
    cfg = yaml.safe_load(config.read_text())

    if daemon:
        log.info("ForwardGuard daemon mode, interval=%ds", interval)
        while True:
            try: _run_once(cfg)
            except Exception as e: log.exception("run cycle failed: %s", e)
            time.sleep(interval)
    else:
        n = _run_once(cfg)
        sys.exit(1 if n > 0 else 0)


if __name__ == "__main__":  # pragma: no cover
    app()
