"""Inspect each call once and compare independent policy classifications."""
from copy import deepcopy

from ..importer import ImportedTrace
from ..schemas import ToolCall
from .config import DEFAULT_CONFIG, EngineConfig
from .policy import LIMITED_COVERAGE_REASON, POLICIES, Policy, evaluate
from .rules import RULES, inspect_call

DISCLAIMER = "Classifies recorded actions only. Does not execute actions or predict what an agent would do after a block."


def _decisions(inspected, policy):
    result = []
    first_block = None
    for call, findings, reasons in inspected:
        decision = evaluate(call, findings, " ".join(reasons) or None, policy)
        decision["coverage_reasons"] = reasons + [LIMITED_COVERAGE_REASON]
        decision["recorded_continuation_after_block"] = first_block is not None
        decision["blocked_by_event_id"] = first_block
        if first_block is None and decision["decision"] == "block":
            first_block = call.event_id
        result.append(decision)
    return result


def _summary(policy, decisions):
    return {
        "policy": policy.model_dump(), "decisions": decisions,
        "counts": {name: sum(d["decision"] == name for d in decisions) for name in ("allow", "review", "block")},
        "interventions": {
            "rule_triggered": sum(d["decision"] != "allow" and any(source.startswith("rule:") for source in d["intervention_sources"]) for d in decisions),
            "unknown_action": sum(d["decision"] != "allow" and "unknown_action" in d["intervention_sources"] for d in decisions),
        },
    }


def analyze(trace: ImportedTrace, policy: Policy, config: EngineConfig = DEFAULT_CONFIG) -> dict:
    inspected = []
    findings, unknown_coverage = [], []
    for event in trace.events:
        if isinstance(event, ToolCall):
            matches, reasons = inspect_call(event, config)
            inspected.append((event, matches, reasons))
            findings.extend(matches)
            if reasons:
                unknown_coverage.append({"event_id": event.event_id, "reasons": reasons})
    baseline_policy, strict_policy = POLICIES["baseline"], POLICIES["strict"]
    baseline = _decisions(inspected, baseline_policy)
    strict = _decisions(inspected, strict_policy)
    decisions = baseline if policy == baseline_policy else strict if policy == strict_policy else _decisions(inspected, policy)
    differences = []
    for (call, matches, reasons), left, right in zip(inspected, baseline, strict):
        if left["decision"] == right["decision"]:
            continue
        changes = [f"{finding['rule_id']}: baseline={baseline_policy.rules.get(finding['rule_id'], baseline_policy.default)}, "
                   f"strict={strict_policy.rules.get(finding['rule_id'], strict_policy.default)}" for finding in matches]
        if reasons:
            changes.append(f"unknown: baseline={baseline_policy.unknown}, strict={strict_policy.unknown} (minimum review)")
        if call.tool in baseline_policy.tools or call.tool in strict_policy.tools:
            changes.append(f"tool:{call.tool}: baseline={baseline_policy.tools.get(call.tool, baseline_policy.default)}, strict={strict_policy.tools.get(call.tool, strict_policy.default)}")
        if not changes:
            changes.append(f"default: baseline={baseline_policy.default}, strict={strict_policy.default}")
        differences.append({"event_id": call.event_id, "baseline": left["decision"], "strict": right["decision"],
                            "reason": "Configured policy decisions: " + "; ".join(changes) + "."})
    return {"schema_version": "1.0", "trace_id": trace.events[0].trace_id,
            "source_sha256": trace.sha256, "policy": policy.model_dump(),
            "events": [event.model_dump() for event in trace.events],
            "warnings": trace.warnings, "findings": findings, "decisions": decisions,
            "disclaimer": DISCLAIMER, "engine_config": config.model_dump(), "rules": deepcopy(RULES),
            "unknown_coverage": unknown_coverage,
            "comparison": {"baseline": _summary(baseline_policy, baseline),
                           "strict": _summary(strict_policy, strict), "differences": differences}}
