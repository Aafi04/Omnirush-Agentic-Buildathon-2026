"""Public redaction/export contract; all credentials below are synthetic."""
from copy import deepcopy
import hashlib
import html
import json
from pathlib import Path

import pytest

from agenttrace.engine.analysis import analyze
from agenttrace.engine.policy import POLICIES, Policy
from agenttrace.importer import ingest
from agenttrace.redaction import Redactor
from agenttrace.reports import LIMITATIONS, SOURCE_SEMANTICS, public_analysis


ROOT = Path(__file__).resolve().parents[2]
MARKER = "AGENTTRACE_SYNTHETIC_SECRET_001"


def analysis(body=MARKER, headers=None, event_id="event-1"):
    event = {"schema_version": "1.0", "trace_id": "trace-1", "event_id": event_id,
             "call_id": "call-1", "timestamp": "2026-10-18T10:00:00Z", "type": "tool_call",
             "tool": "http.request", "arguments": {"method": "POST", "url": "https://collector.invalid",
                                                      "body": body, "headers": headers or {}}}
    source = (json.dumps(event) + "\r\n\r\n").encode()
    return analyze(ingest(source), POLICIES["baseline"]), source


def reordered(value):
    if isinstance(value, dict):
        return {key: reordered(value[key]) for key in reversed(list(value))}
    if isinstance(value, list):
        return [reordered(item) for item in value]
    return value


@pytest.mark.parametrize("sample", ["benign", "risky", "forensic"])
@pytest.mark.parametrize("policy", ["baseline", "strict"])
def test_six_sample_policy_integrations(sample, policy):
    source = (ROOT / "samples" / f"{sample}.jsonl").read_bytes()
    raw = analyze(ingest(source), POLICIES[policy])
    original = deepcopy(raw)
    public = public_analysis(raw)
    reports = public["reports"]
    document = json.loads(reports["json"])
    assert raw == original
    assert public_analysis(raw) == public
    assert public_analysis(reordered(raw)) == public
    assert reports["json"].endswith("\n") and not reports["json"].endswith("\n\n")
    assert reports["json"] == json.dumps(document, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"
    assert reports["report_sha256"] == hashlib.sha256(reports["json"].encode()).hexdigest()
    assert document["source_sha256"] == hashlib.sha256(source).hexdigest()
    assert document["source_sha256_semantics"] == SOURCE_SEMANTICS
    assert "report_sha256" not in document
    assert "policy" not in document and "decisions" not in document
    assert document["findings"] == public["findings"]
    assert document["comparison"] == public["comparison"]
    assert len(document["event_index"]) == len(raw["events"])
    ids = {item["event_id"] for item in document["event_index"]}
    for finding in document["findings"]:
        assert set(finding["event_ids"]) <= ids
    assert all(set(event) <= {"event_id", "call_id", "type", "timestamp", "tool", "status"} for event in document["event_index"])
    other = analyze(ingest(source), POLICIES["strict" if policy == "baseline" else "baseline"])
    assert public_analysis(other)["reports"] == reports


def test_fingerprint_exact_bytes_and_benign_payload_exclusion():
    raw, source = analysis(body="BENIGN_PAYLOAD_MUST_NOT_BE_EXPORTED")
    public = public_analysis(raw)
    document = json.loads(public["reports"]["json"])
    assert document["source_sha256"] == hashlib.sha256(source).hexdigest()
    assert hashlib.sha256(source.replace(b"\r\n", b"\n")).hexdigest() != document["source_sha256"]
    assert public["events"][0]["arguments"]["body"] == "BENIGN_PAYLOAD_MUST_NOT_BE_EXPORTED"
    assert "BENIGN_PAYLOAD_MUST_NOT_BE_EXPORTED" not in public["reports"]["json"]
    assert "BENIGN_PAYLOAD_MUST_NOT_BE_EXPORTED" not in html.unescape(public["reports"]["markdown"])


def test_secret_propagation_to_secondary_fields_and_ids():
    raw, _ = analysis(headers={"aUtHoRiZaTiOn": "Bearer synthetic-header-value-long"}, event_id="e-" + MARKER)
    secret = "synthetic-header-value-long"
    raw["events"][0]["arguments"]["metadata"] = {"password": secret, "argv": [secret]}
    raw["warnings"] = [{"message": secret}]
    raw["rules"][0]["limitations"].append(secret)
    raw["comparison"]["baseline"]["policy"]["tools"][secret] = "block"
    raw["comparison"]["baseline"]["decisions"][0]["matches"].append({"source": "tool:" + secret, "decision": "block"})
    public = public_analysis(raw)
    serialized = json.dumps(public)
    assert secret not in serialized and MARKER not in serialized
    assert public["events"][0]["event_id"] == public["findings"][0]["event_ids"][0]
    assert public["comparison"]["baseline"]["decisions"][0]["event_id"] == public["events"][0]["event_id"]
    ref = public["events"][0]["arguments"]["metadata"]["password"]
    assert ref == public["warnings"][0]["message"]
    assert ref == public["events"][0]["arguments"]["metadata"]["argv"][0]
    assert public["sanitization"]["redactions"] > 0
    assert "not a cryptographic" in public["sanitization"]["notice"]


@pytest.mark.parametrize("key", ["Authorization", "Proxy-Authorization", "X-API-Key", "cookie", "set-cookie",
                                  "token", "password", "passwd", "secret", "api_key", "apikey", "access_token",
                                  "refresh_token", "client_secret", "private_key"])
def test_sensitive_keys_case_insensitive(key):
    secret = "synthetic_value_123456"
    data = {"nested": {key.swapcase(): secret}, "secondary": secret}
    clean = Redactor().collect(data).sanitize(data)
    assert secret not in json.dumps(clean)
    assert clean["secondary"] == clean["nested"][key.swapcase()]


@pytest.mark.parametrize("text,secret", [
    ('{"password":"synthetic json value"}', "synthetic json value"),
    ("TOKEN=synthetic_env_value", "synthetic_env_value"),
    ("export client_secret='synthetic shell value'", "synthetic shell value"),
    ("https://example.invalid/?access_token=synthetic_query_value&ok=1", "synthetic_query_value"),
    ("Bearer synthetic_bearer_value", "synthetic_bearer_value"),
    ("Basic c3ludGhldGljOnBhc3N3b3Jk", "c3ludGhldGljOnBhc3N3b3Jk"),
    ("https://syntheticuser:syntheticpass@example.invalid", "syntheticpass"),
    ("AKIA" + "S" * 16, "AKIA" + "S" * 16),
    ("sk-proj-" + "S" * 24, "sk-proj-" + "S" * 24),
    ("ghp_" + "S" * 36, "ghp_" + "S" * 36),
    (MARKER, MARKER),
])
def test_string_heuristics_and_repetition(text, secret):
    data = {"text": text, "copy": secret}
    clean = Redactor().collect(data).sanitize(data)
    assert secret not in json.dumps(clean)


@pytest.mark.parametrize("delimiter", ["-----BEGIN PRIVATE KEY-----", "-----BEGIN RSA PRIVATE KEY-----", "-----BEGIN PRI"])
def test_truncated_private_blocks_and_evidence(delimiter):
    body = "SYNTHETICKEYBODY" * 30
    raw, _ = analysis(delimiter + "\n" + body)
    raw["warnings"] = [{"message": body[:200]}]
    raw["findings"].append({"event_ids": ["event-1"], "evidence": body[15:100],
                             "evidence_items": [{"field": "arguments.body", "value": body[15:100], "truncated": True}]})
    public = public_analysis(raw)
    assert "SYNTHETICKEYBODY" not in json.dumps(public)


def test_long_header_prefix_and_key_collision_preserve_values():
    secret = "synthetic_header_" + "Q" * 400
    data = {"headers": {"Authorization": "Bearer " + secret},
            "evidence_items": [{"field": 'arguments.headers["Authorization"]', "value": secret[:249], "truncated": True}],
            "keys": {MARKER: "first", "[REDACTED:secret-0003]": "second"}}
    redactor = Redactor().collect(data)
    # Force a collision independently of discovery order.
    ref = redactor.sanitize(MARKER)
    data["keys"] = {MARKER: "first", ref: "second"}
    clean = redactor.sanitize(data)
    assert len(clean["keys"]) == 2
    assert set(clean["keys"].values()) == {"first", "second"}
    assert "synthetic_header_" not in json.dumps(clean)
    assert "Q" * 20 not in json.dumps(clean)


def test_encoded_values_and_no_generic_hex_version_redaction():
    data = {"password": "synthetic space/value", "copy": "synthetic%20space%2Fvalue", "version": "1.0",
            "decision": "allow", "source_sha256": "a" * 64, "ordinary": "b" * 64}
    clean = Redactor().collect(data).sanitize(data)
    assert clean["password"] == clean["copy"]
    assert clean["version"] == "1.0" and clean["decision"] == "allow"
    assert clean["source_sha256"] == "a" * 64 and clean["ordinary"] == "b" * 64


def test_multiple_private_blocks_and_nested_fingerprint_named_secret():
    first, second = "SYNTHETICFIRSTBODY12345", "SYNTHETICSECONDBODY12345"
    data = {"body": f"-----BEGIN PRIVATE KEY-----\n{first}\n-----END PRIVATE KEY-----\n"
                    f"-----BEGIN RSA PRIVATE KEY-----\n{second}\n-----END RSA PRIVATE KEY-----",
            "password": second, "nested": {"source_sha256": second}, "copy": first}
    clean = Redactor().sanitize(data)
    assert first not in json.dumps(clean) and second not in json.dumps(clean)


def test_short_url_credentials_do_not_destroy_ordinary_schema_fields():
    data = {"url": "https://a:p@example.invalid", "arguments": {}, "decision": "allow", "version": "1.0"}
    clean = Redactor().sanitize(data)
    assert "a:p" not in clean["url"]
    assert clean["arguments"] == {} and clean["decision"] == "allow" and clean["version"] == "1.0"


def test_markdown_is_data_not_instructions():
    raw, _ = analysis()
    attack = "<script>alert(1)</script>\n# heading\n[x](javascript:evil) | `code`\n```\n![x](https://evil.invalid)"
    raw["warnings"] = [{"message": attack}]
    exported = public_analysis(raw)["reports"]
    markdown = exported["markdown"]
    assert json.dumps(attack, ensure_ascii=True) in html.unescape(markdown)
    for dangerous in ("<script>", "javascript:", "```", "[x]", "https://evil.invalid", "|", "`"):
        assert dangerous not in markdown
    assert json.loads(exported["json"])["warnings"][0]["message"] == attack


def test_inconsistent_evidence_references_refused_without_echoing():
    raw, _ = analysis()
    raw["findings"][0]["event_ids"] = ["missing-sensitive-event"]
    with pytest.raises(ValueError, match="missing evidence reference") as error:
        public_analysis(raw)
    assert "missing-sensitive-event" not in str(error.value)


def test_ten_thousand_distinct_credentials_use_bounded_patterns():
    data = [{"token": f"synthetic-{index:05d}-" + "X" * 100, "secondary": f"synthetic-{index:05d}-" + "X" * 100}
            for index in range(10_000)]
    redactor = Redactor().collect(data)
    clean = redactor.sanitize(data)
    assert len(clean) == 10_000
    assert all(item["token"] == item["secondary"] for item in clean)
    assert len(redactor._values) == 10_000
    assert all(len(pattern) <= 32 for pattern in redactor._patterns)


@pytest.mark.parametrize("stem", [MARKER, "synthetic-id-prefix-" + "X" * 40])
def test_distinct_sensitive_identifiers_keep_all_typed_references(stem):
    trace_id = "t-" + stem
    base = {"schema_version": "1.0", "trace_id": trace_id, "timestamp": "2026-10-18T10:00:01Z"}
    events = [
        base | {"event_id": f"e-{stem}-b", "call_id": f"c-{stem}-b", "type": "tool_call", "tool": "process.exec",
                "arguments": {"argv": ["sudo", "id"], "cwd": "/workspace", "shell": False}},
        base | {"event_id": f"e-{stem}-a", "call_id": f"c-{stem}-a", "type": "tool_call", "tool": "custom.tool",
                "timestamp": "2026-10-18T10:00:00Z", "arguments": {"password": stem}},
        base | {"event_id": f"e-{stem}-result", "call_id": f"c-{stem}-b", "type": "tool_result", "status": "ok", "output": None},
        base | {"event_id": f"e-{stem}-orphan", "call_id": f"c-{stem}-orphan", "type": "tool_result", "status": "error", "output": None},
    ]
    trace = ingest(("\n".join(json.dumps(event) for event in events) + "\n").encode())
    raw = analyze(trace, POLICIES["strict"])
    public = public_analysis(raw)
    assert public["trace_id"] == "[REDACTED:trace-0001]"
    assert [event["event_id"] for event in public["events"]] == [f"[REDACTED:event-{index:04d}]" for index in range(1, 5)]
    assert [event["call_id"] for event in public["events"]] == ["[REDACTED:call-0001]", "[REDACTED:call-0002]",
                                                                    "[REDACTED:call-0001]", "[REDACTED:call-0003]"]
    known = {event["event_id"] for event in public["events"]}
    assert all(event["trace_id"] == public["trace_id"] for event in public["events"])
    assert public["findings"][0]["event_ids"] == ["[REDACTED:event-0001]"]
    assert public["decisions"][1]["blocked_by_event_id"] == "[REDACTED:event-0001]"
    assert public["decisions"][1]["recorded_continuation_after_block"] is True
    assert all(set(warning["event_ids"]) <= known for warning in public["warnings"])
    assert public["unknown_coverage"][0]["event_id"] == "[REDACTED:event-0002]"
    document = json.loads(public["reports"]["json"])
    for key in ("findings", "comparison", "unknown_coverage", "warnings"):
        assert document[key] == public[key]
    assert document["comparison"]["strict"]["decisions"] == public["decisions"]
    assert stem not in json.dumps(public)
    assert public_analysis(reordered(raw)) == public
    assert public_analysis(analyze(trace, POLICIES["baseline"]))["reports"] == public["reports"]


@pytest.mark.parametrize("secret", ["policy", "review", "1.0", "event_id", "decision", "schema_version",
                                   "block", "R002", "high", "unknown_action", "tool_call", "2.0"])
def test_payload_secrets_matching_schema_vocabulary_keep_public_shape(secret):
    base = {"schema_version": "1.0", "trace_id": "schema-trace", "timestamp": "2026-10-18T10:00:00Z"}
    payload = {"password": secret, secret: secret, "copy": secret, "nested": {"policy": secret},
               "decision": secret, "schema_version": secret, "event_id": secret}
    events = [
        base | {"event_id": "first", "call_id": "first", "type": "tool_call", "tool": "process.exec",
                "arguments": {"argv": ["sudo", "id"], "cwd": "/workspace", "shell": False}},
        base | {"event_id": "second", "call_id": "second", "type": "tool_call", "tool": secret, "arguments": payload},
        base | {"event_id": "result", "call_id": "second", "type": "tool_result", "status": "ok", "output": payload},
    ]
    trace = ingest(("\n".join(json.dumps(event) for event in events) + "\n").encode())
    raw = analyze(trace, POLICIES["baseline"])
    public = public_analysis(raw)
    document = json.loads(public["reports"]["json"])
    assert public["schema_version"] == "1.0"
    assert public["policy"]["schema_version"] == "1.0" and public["policy"]["version"] == "2.0"
    assert public["events"][0]["type"] == "tool_call" and public["events"][2]["status"] == "ok"
    assert public["findings"][0]["rule_id"] == "R002" and public["findings"][0]["rule_version"] == "1.0"
    assert public["findings"][0]["severity"] == "high"
    assert public["decisions"][0]["decision"] == "review"
    assert public["decisions"][1]["decision"] == "review"
    assert public["comparison"]["strict"]["decisions"][0]["decision"] == "block"
    assert public["comparison"]["baseline"]["counts"] == {"allow": 0, "review": 2, "block": 0}
    assert public["events"][1]["tool"].startswith("[REDACTED:")
    for sanitized_payload in (public["events"][1]["arguments"], public["events"][2]["output"]):
        assert secret not in sanitized_payload
        assert secret not in sanitized_payload.values()
        assert sanitized_payload["password"].startswith("[REDACTED:")
        assert sanitized_payload["copy"].startswith("[REDACTED:")
    for key in ("findings", "comparison", "unknown_coverage", "warnings", "engine_config", "rules"):
        assert document[key] == public[key]
    assert document["comparison"]["baseline"]["decisions"] == public["decisions"]
    assert public_analysis(reordered(raw)) == public
    assert public_analysis(analyze(trace, POLICIES["strict"]))["reports"] == public["reports"]


def test_controlled_vocab_in_dynamic_policy_keys_and_metadata_is_not_exempt():
    secret = "review"
    base = {"schema_version": "1.0", "trace_id": "metadata-trace", "timestamp": "2026-10-18T10:00:00Z"}
    event = base | {"event_id": "one", "call_id": "one", "type": "tool_call", "tool": secret,
                    "arguments": {"password": secret, "review": {"review": secret}}}
    policy = Policy(policy_id="custom", tools={"review": "block", "password": "review"})
    trace = ingest(json.dumps(event).encode())
    raw = analyze(trace, policy)
    raw["rules"][0]["metadata"] = {"password": secret, "review": secret, "decision": secret}
    raw["engine_config"]["metadata"] = {"password": secret, "review": secret}
    raw["warnings"].append({"event_ids": ["one"], "metadata": {"review": secret}, "message": secret})
    public = public_analysis(raw)
    assert "review" not in public["policy"]["tools"]
    assert public["policy"]["tools"]["password"].startswith("[REDACTED:")
    assert "tool:review" not in json.dumps(public)
    for metadata in (public["rules"][0]["metadata"], public["engine_config"]["metadata"], public["warnings"][-1]["metadata"]):
        assert "review" not in metadata and "review" not in metadata.values()
    assert public["warnings"][-1]["message"].startswith("[REDACTED:")
    assert public["decisions"][0]["decision"] == "block"


def test_markdown_readable_words_and_replay_limitations():
    raw, _ = analysis()
    raw["warnings"].append({"message": "Ordinary readable words https://example.invalid <tag> `fence`\n# heading"})
    reports = public_analysis(raw)["reports"]
    assert "Ordinary readable words https" in reports["markdown"]
    assert "https://example.invalid" not in reports["markdown"]
    phrase = "Counterfactual policy replay evaluates recorded actions only; does not execute or predict subsequent behavior"
    assert phrase in LIMITATIONS
    assert phrase in reports["markdown"] and phrase in json.loads(reports["json"])["limitations"]
