from forwardguard.alert import Alert, Severity


def test_alert_serialises_to_smfps_schema():
    a = Alert(
        pipeline="P-API",
        severity=Severity.HIGH,
        event_type="forwarder_added",
        domain="example.test",
        mailbox="alice@example.test",
        destination="attacker@evil.test",
        forwarder_id=None,
        details={"provider": "porkbun"},
    )
    s = a.to_smfps()
    assert s["event_type"] == "forwarder_added"
    assert s["target"]["domain"] == "example.test"
    assert s["target"]["destination"] == "attacker@evil.test"
    assert s["forwardguard"]["pipeline"] == "P-API"
    assert s["forwardguard"]["severity"] == "high"
    assert s["actor"]["principal_type"] == "forwardguard_detector"
    assert s["event_id"]
    assert s["timestamp"]


def test_alert_str_render():
    a = Alert(
        pipeline="P-CANARY", severity=Severity.CRITICAL, event_type="canary_mailbox_hit",
        domain="d.test", mailbox="canary@d.test", destination=None, forwarder_id=None,
    )
    out = str(a)
    assert "CRITICAL" in out
    assert "P-CANARY" in out
    assert "canary@d.test" in out
