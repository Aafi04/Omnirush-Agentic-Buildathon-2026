import json
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from agenttrace.api import app
from agenttrace.engine.analysis import analyze
from agenttrace.engine.policy import POLICIES, Policy, evaluate
from agenttrace.engine.rules import detect, unknown_reason
from agenttrace.importer import MAX_BYTES, ImportFailure, ingest
from agenttrace.schemas import ToolCall

ROOT = Path(__file__).resolve().parents[2]
client = TestClient(app)


def event(**updates):
    data = {"schema_version": "1.0", "trace_id": "test", "event_id": "e1", "timestamp": "2026-10-18T10:00:00Z",
            "type": "tool_call", "call_id": "c1", "tool": "process.exec",
            "arguments": {"argv": ["git", "status"], "cwd": "/workspace", "shell": False}}
    return data | updates


def raw(*events):
    return "\n".join(json.dumps(e) for e in events).encode()


def test_health_and_samples():
    assert client.get("/api/health").json()["status"] == "ok"
    sample = client.get("/api/samples/benign").json()
    assert sample["synthetic"] is True
    response = client.post("/api/analyze", content=sample["jsonl"].encode())
    assert response.status_code == 200
    result = response.json()
    assert result["findings"] == []
    assert [d["decision"] for d in result["decisions"]] == ["allow"]
    assert result["warnings"] == []


def test_risky_evidence_and_recorded_continuation():
    trace = ingest((ROOT / "samples/risky.jsonl").read_bytes())
    result = analyze(trace, POLICIES["strict"])
    assert [(f["rule_id"], f["event_ids"]) for f in result["findings"]] == [("R002", ["risky-1"])]
    assert [d["decision"] for d in result["decisions"]] == ["block", "block"]
    assert result["decisions"][1]["event_id"] == "risky-3"
    assert len(result["events"]) == 3
    assert result["source_sha256"] == analyze(trace, POLICIES["strict"])["source_sha256"]
    assert "Does not execute" in result["disclaimer"]
    assert result["warnings"] == [{"code": "incomplete_call", "event_ids": ["risky-3"]}]


@pytest.mark.parametrize("argv,flavor,expected", [
    (["sudo", "id"], "posix", True), (["/bin/su"], "posix", True), (["doas", "id"], "posix", True),
    (["echo", "sudo"], "posix", False), (["sudoers"], "posix", False), (["SUDO"], "posix", False),
    ([r"C:\tools\sudo"], "windows", True), (["sh", "-c", "sudo id"], "posix", False),
])
def test_exact_direct_detection(argv, flavor, expected):
    call = ingest(raw(event(arguments={"argv": argv, "cwd": "/workspace", "shell": False, "path_flavor": flavor}))).events[0]
    assert bool(detect(call)) is expected


def test_shell_is_unknown_not_direct_execution():
    call = ingest(raw(event(arguments={"argv": ["sudo id"], "cwd": "/workspace", "shell": True}))).events[0]
    assert detect(call) == []
    assert unknown_reason(call)
    assert evaluate(call, [], unknown_reason(call), Policy(policy_id="permissive", unknown="allow"))["decision"] == "review"


@pytest.mark.parametrize("tool_decision,rule_decision,expected", [
    ("allow", "block", "block"), ("block", "allow", "block"), ("review", "allow", "review"), ("allow", "allow", "allow"),
])
def test_policy_precedence(tool_decision, rule_decision, expected):
    call = ToolCall.model_validate(event())
    policy = Policy(policy_id="test", rules={"R002": rule_decision}, tools={"process.exec": tool_decision})
    assert evaluate(call, [{"rule_id": "R002"}], None, policy)["decision"] == expected


@pytest.mark.parametrize("updates", [
    {"schema_version": "2.0"}, {"event_id": ""}, {"timestamp": "yesterday"}, {"timestamp": "2026-02-30T00:00:00Z"},
    {"arguments": {"argv": [], "cwd": "/workspace", "shell": False}},
    {"arguments": {"argv": ["git"], "cwd": "/workspace", "shell": "false"}},
    {"tool": "filesystem.write", "arguments": {"path": "/tmp/a"}},
    {"tool": "http.request", "arguments": {"method": "GET", "url": "file:///etc/passwd"}},
])
def test_invalid_events(updates):
    response = client.post("/api/analyze", content=raw(event(**updates)))
    assert response.status_code == 422
    assert response.json() == {"error": {"code": "invalid_event", "line": 1}}


@pytest.mark.parametrize("payload,code", [
    (b"", "empty_trace"), (b"\xff", "invalid_utf8"), (b"not-json", "invalid_event"),
    (b'{"a":1,"a":2}', "invalid_event"), (b'{"a":NaN}', "invalid_event"),
    (b"[" * 21 + b"]" * 21, "nesting_limit"), (b"x" * (65536 + 1), "line_too_large"),
], ids=["empty", "utf8", "json", "duplicate-key", "nan", "depth", "line-size"])
def test_bad_input(payload, code):
    with pytest.raises(ImportFailure) as error:
        ingest(payload)
    assert error.value.code == code


@pytest.mark.parametrize("second,code", [
    (event(), "duplicate_event_id"),
    (event(event_id="e2"), "duplicate_call_id"),
    (event(event_id="e2", trace_id="other"), "mixed_trace_ids"),
])
def test_duplicate_and_mixed_ids(second, code):
    with pytest.raises(ImportFailure) as error:
        ingest(raw(event(), second))
    assert error.value.code == code
    assert error.value.line == 2


def test_event_limit():
    payload = raw(*(event(event_id=f"e{i}", call_id=f"c{i}") for i in range(10001)))
    with pytest.raises(ImportFailure) as error:
        ingest(payload)
    assert error.value.code == "event_limit"


def test_size_limit():
    response = client.post("/api/analyze", content=b" " * (MAX_BYTES + 1))
    assert response.status_code == 413
    assert response.json()["error"]["code"] == "input_too_large"


def test_orphans_regression_and_out_of_order_linking():
    result = {k: v for k, v in event().items() if k not in {"tool", "arguments"}}
    result.update(type="tool_result", status="ok", output="synthetic")
    trace = ingest(raw(result, event(event_id="e2", timestamp="2026-10-18T09:00:00Z")))
    assert trace.warnings == [{"code": "timestamp_regression", "event_ids": ["e2"]}]
    assert ingest(raw(result)).warnings == [{"code": "orphan_result", "event_ids": ["e1"]}]
    with pytest.raises(ImportFailure) as error:
        ingest(raw(result, result | {"event_id": "e2"}))
    assert error.value.code == "duplicate_result"


def test_content_is_never_executed(tmp_path):
    target = tmp_path / "must-not-exist"
    payload = raw(event(arguments={"argv": ["sh", "-c", f"touch {target}"], "cwd": "/workspace", "shell": False}))
    result = client.post("/api/analyze", content=payload).json()
    assert result["decisions"][0]["decision"] == "review"
    assert not target.exists()


def test_invalid_policy_and_bounded_private_errors():
    assert client.post("/api/analyze?policy=invalid", content=raw(event())).status_code == 422
    response = client.post("/api/analyze", content=b"SYNTHETIC_PRIVATE_PAYLOAD")
    assert "SYNTHETIC_PRIVATE_PAYLOAD" not in response.text
    assert response.headers["cache-control"] == "no-store"


@pytest.mark.parametrize("encoded", [b'1e999', b'"\\ud800"', b'"\\udfff"'])
def test_nonfinite_and_surrogates_rejected(encoded):
    payload = raw(event(tool="custom.test", arguments={"value": None})).replace(b'null', encoded)
    response = client.post("/api/analyze", content=payload)
    assert response.status_code == 422
    assert response.json()["error"]["code"] == "invalid_event"


def test_schema_and_static_app():
    response = client.get("/api/schema")
    assert response.status_code == 200
    assert response.json()["schema_version"] == "1.0"
    assert len(response.json()["event_schema"]["$defs"]["ToolCall"]["allOf"]) == 3
    if (ROOT / "frontend/dist").exists():
        response = client.get("/")
        assert response.status_code == 200
        assert "AgentTrace" in response.text


def test_streamed_size_limit():
    response = client.post("/api/analyze", content=iter([b" " * 1024] * 5121))
    assert response.status_code == 413
