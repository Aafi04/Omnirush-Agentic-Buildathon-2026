"""Offline machine-readable verifier for checked-in AgentTrace artifacts.

It loads the real synthetic fixtures through the importer, deterministic engine,
policy evaluator and public report boundary. It never starts a server, opens a
URL, invokes a trace action, or writes output files.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
SAMPLES = ("benign", "risky", "forensic")
RULE_IDS = [f"R{index:03d}" for index in range(1, 7)]
EXPECTED = {
    "benign": {"findings": [], "baseline": {"allow": 1, "review": 0, "block": 0}, "strict": {"allow": 1, "review": 0, "block": 0}},
    "risky": {"findings": ["R002"], "baseline": {"allow": 0, "review": 2, "block": 0}, "strict": {"allow": 0, "review": 0, "block": 2}},
    "forensic": {"findings": RULE_IDS, "baseline": {"allow": 1, "review": 7, "block": 0}, "strict": {"allow": 1, "review": 0, "block": 7}},
}


def _load_engine():
    backend = str(ROOT / "backend")
    if backend not in sys.path:
        sys.path.insert(0, backend)
    from agenttrace.engine.analysis import analyze
    from agenttrace.engine.policy import POLICIES
    from agenttrace.importer import ingest
    from agenttrace.reports import public_analysis
    return analyze, POLICIES, ingest, public_analysis


def _check(checks: list[dict[str, str]], name: str, condition: bool, detail: str) -> None:
    if not condition:
        raise ValueError(f"{name}: {detail}")
    checks.append({"name": name, "status": "passed", "detail": detail})


def verify_sample(root: Path, name: str) -> dict[str, Any]:
    analyze, policies, ingest, public_analysis = _load_engine()
    checks: list[dict[str, str]] = []
    source = (root / "samples" / f"{name}.jsonl").read_bytes()
    baseline = public_analysis(analyze(ingest(source), policies["baseline"]))
    strict = public_analysis(analyze(ingest(source), policies["strict"]))
    expected = EXPECTED[name]
    _check(checks, "source_fingerprint", baseline["source_sha256"] == hashlib.sha256(source).hexdigest(), "exact original bytes hash")
    _check(checks, "public_sanitization", baseline["sanitization"]["version"] == "1.0", "public analysis is marked sanitized")
    _check(checks, "report_digest", baseline["reports"]["report_sha256"] == hashlib.sha256(baseline["reports"]["json"].encode("utf-8")).hexdigest(), "report digest covers canonical JSON bytes")
    _check(checks, "policy_invariance", baseline["reports"] == strict["reports"], "selected policy does not change the investigation report")
    _check(checks, "expected_findings", [item["rule_id"] for item in baseline["findings"]] == expected["findings"], "fixture findings match the release matrix")
    for policy_name in ("baseline", "strict"):
        _check(checks, f"{policy_name}_counts", baseline["comparison"][policy_name]["counts"] == expected[policy_name], "policy counts match the release matrix")
    document = json.loads(baseline["reports"]["json"])
    event_index = document["event_index"]
    event_ids = {event["event_id"] for event in event_index}
    call_ids = {event["call_id"] for event in event_index}
    _check(checks, "event_index_shape", all(set(event) <= {"event_id", "call_id", "type", "timestamp", "tool", "status"} for event in event_index), "report index excludes arguments and output")
    _check(checks, "finding_references", all(set(finding["event_ids"]) <= event_ids for finding in document["findings"]), "every finding references an indexed event")
    decisions = [*document["comparison"]["baseline"]["decisions"], *document["comparison"]["strict"]["decisions"]]
    _check(checks, "decision_references", all(decision["event_id"] in event_ids and decision["call_id"] in call_ids for decision in decisions), "every policy decision references indexed event/call IDs")
    _check(checks, "continuation_references", all(item["blocked_by_event_id"] in event_ids for item in decisions if item.get("blocked_by_event_id")), "hypothetical block references are indexed")
    _check(checks, "no_raw_secret_marker", "AGENTTRACE_SYNTHETIC_SECRET_001" not in json.dumps(baseline, sort_keys=True), "synthetic secret marker is absent from public analysis")
    _check(checks, "six_rule_metadata", [rule["rule_id"] for rule in document["rules"]] == RULE_IDS, "all six rule metadata entries are present")
    return {"status": "passed", "checks": checks, "event_count": len(baseline["events"]), "finding_count": len(baseline["findings"])}


def verify_all(root: Path = ROOT) -> dict[str, Any]:
    results: dict[str, Any] = {}
    failures: list[dict[str, str]] = []
    for name in SAMPLES:
        try:
            results[name] = verify_sample(root, name)
        except Exception as error:
            results[name] = {"status": "failed", "error": type(error).__name__}
            failures.append({"fixture": name, "error": type(error).__name__})
    passed = sum(item["status"] == "passed" for item in results.values())
    return {"tool": "agenttrace-release-verify", "version": "1.0", "status": "passed" if not failures else "failed", "fixtures": results, "summary": {"fixtures_total": len(SAMPLES), "fixtures_passed": passed, "fixtures_failed": len(failures)}, "failures": failures}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, default=ROOT)
    args = parser.parse_args(argv)
    result = verify_all(args.root.resolve())
    print(json.dumps(result, sort_keys=True, separators=(",", ":"), ensure_ascii=True))
    return 0 if result["status"] == "passed" else 1


if __name__ == "__main__":
    raise SystemExit(main())
