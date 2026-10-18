import json
import tempfile
from pathlib import Path

from forwardguard.pipelines.api import ApiPipeline
from forwardguard.providers.base import Forwarder, Provider


class _FakeProvider(Provider):
    name = "fake"
    def list_forwarders(self):
        return self.config.get("_fwds", [])


def test_baseline_establishment_emits_nothing(monkeypatch, tmp_path):
    monkeypatch.setitem(__import__("forwardguard.providers", fromlist=["REGISTRY"]).REGISTRY, "fake", _FakeProvider)
    p = ApiPipeline(state_dir=tmp_path)
    cfg = [{"type": "fake", "domain": "d.test", "_fwds": [
        Forwarder("a@d.test", "b@elsewhere.test", "fake", "d.test"),
    ]}]
    alerts = p.run(cfg)
    assert alerts == []


def test_new_forwarder_raises_high(monkeypatch, tmp_path):
    monkeypatch.setitem(__import__("forwardguard.providers", fromlist=["REGISTRY"]).REGISTRY, "fake", _FakeProvider)
    p = ApiPipeline(state_dir=tmp_path, whitelist=[])
    # Baseline run
    p.run([{"type":"fake","domain":"d.test","_fwds":[
        Forwarder("a@d.test","b@ok.test","fake","d.test"),
    ]}])
    # New forwarder appears
    alerts = p.run([{"type":"fake","domain":"d.test","_fwds":[
        Forwarder("a@d.test","b@ok.test","fake","d.test"),
        Forwarder("ceo@d.test","attacker@evil.test","fake","d.test"),
    ]}])
    added = [a for a in alerts if a.event_type == "forwarder_added"]
    assert len(added) == 1
    assert added[0].severity.value == "high"
    assert added[0].destination == "attacker@evil.test"


def test_whitelisted_destination_is_low(monkeypatch, tmp_path):
    monkeypatch.setitem(__import__("forwardguard.providers", fromlist=["REGISTRY"]).REGISTRY, "fake", _FakeProvider)
    p = ApiPipeline(state_dir=tmp_path, whitelist=["archive@ok.test"])
    p.run([{"type":"fake","domain":"d.test","_fwds":[]}])
    alerts = p.run([{"type":"fake","domain":"d.test","_fwds":[
        Forwarder("a@d.test","archive@ok.test","fake","d.test"),
    ]}])
    assert alerts[0].severity.value == "low"
