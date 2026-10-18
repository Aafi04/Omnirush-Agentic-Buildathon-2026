"""Exercise a running built application over real loopback HTTP, without services."""
import argparse
import json
import re
import hashlib
import html as html_tools
from urllib.error import HTTPError
from urllib.request import Request, urlopen

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8000)
args = parser.parse_args()
base = f"http://127.0.0.1:{args.port}"


def read(path, data=None, headers=None):
    with urlopen(Request(base + path, data=data, headers=headers or {}), timeout=5) as response:
        assert response.status == 200
        return response.read()


assert json.loads(read("/api/health"))["status"] == "ok"
html = read("/").decode()
assert "AgentTrace" in html
assets = re.findall(r'(?:src|href)="(/assets/[^\"]+)"', html)
assert len(assets) >= 2
for asset in assets:
    assert len(read(asset)) > 100
for sample_name, policy, expected in [
    ("benign", "baseline", ["allow"]),
    ("risky", "baseline", ["review", "review"]),
    ("risky", "strict", ["block", "block"]),
]:
    sample = json.loads(read(f"/api/samples/{sample_name}"))
    assert sample["synthetic"] is True
    result = json.loads(read(f"/api/analyze?policy={policy}", sample["jsonl"].encode()))
    assert [item["decision"] for item in result["decisions"]] == expected
    if sample_name == "risky":
        assert result["findings"][0]["event_ids"] == ["risky-1"]
sample = json.loads(read("/api/samples/forensic"))
assert sample["synthetic"] is True
result = json.loads(read("/api/analyze?policy=strict", sample["jsonl"].encode()))
assert [finding["rule_id"] for finding in result["findings"]] == [f"R{i:03}" for i in range(1, 7)]
comparison = result["comparison"]
assert comparison["baseline"]["counts"] == {"allow": 1, "review": 7, "block": 0}
assert comparison["strict"]["counts"] == {"allow": 1, "review": 0, "block": 7}
assert comparison["strict"]["interventions"] == {"rule_triggered": 6, "unknown_action": 2}
assert len(comparison["differences"]) == 7
assert [item["event_id"] for item in result["unknown_coverage"]] == ["forensic-5", "forensic-7"]
last = comparison["strict"]["decisions"][-1]
assert last["decision"] == "allow" and last["recorded_continuation_after_block"] is True
assert last["blocked_by_event_id"] == "forensic-1"
assert result["sanitization"]["version"] == "1.0"
reports = result["reports"]
assert reports["report_sha256"] == hashlib.sha256(reports["json"].encode("utf-8")).hexdigest()
document = json.loads(reports["json"])
assert document["findings"] == result["findings"]
assert document["comparison"] == result["comparison"]
assert all("arguments" not in event and "output" not in event for event in document["event_index"])
assert "AGENTTRACE_SYNTHETIC_SECRET_001" not in json.dumps(result)
assert "AGENTTRACE_SYNTHETIC_SECRET_001" not in html_tools.unescape(reports["markdown"])
repeated = json.loads(read("/api/analyze?policy=baseline", sample["jsonl"].encode()))
assert repeated["reports"] == reports
override = {"workspace_roots": {"posix": ["/workspace", "/outside"], "windows": ["C:/workspace"]}}
configured = json.loads(read("/api/analyze", sample["jsonl"].encode(), {"X-AgentTrace-Config": json.dumps(override)}))
assert "R006" not in [finding["rule_id"] for finding in configured["findings"]]
try:
    read("/api/analyze", b"not-json")
    raise AssertionError("invalid import accepted")
except HTTPError as error:
    assert error.code == 422
    assert json.loads(error.read())["error"]["code"] == "invalid_event"
print("HTTP smoke passed: health, HTML/assets, samples, six rules, comparison, configuration, sanitized evidence, canonical exports, fingerprints, determinism, rejected import.")
