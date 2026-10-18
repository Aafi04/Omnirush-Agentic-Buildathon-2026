"""Exercise a running built application over real loopback HTTP, without services."""
import argparse
import json
import re
from urllib.error import HTTPError
from urllib.request import Request, urlopen

parser = argparse.ArgumentParser()
parser.add_argument("--port", type=int, default=8000)
args = parser.parse_args()
base = f"http://127.0.0.1:{args.port}"


def read(path, data=None):
    with urlopen(Request(base + path, data=data), timeout=5) as response:
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
try:
    read("/api/analyze", b"not-json")
    raise AssertionError("invalid import accepted")
except HTTPError as error:
    assert error.code == 422
    assert json.loads(error.read())["error"]["code"] == "invalid_event"
print("HTTP smoke passed: health, HTML/assets, benign/risky replay, evidence, rejected import.")
