from ..importer import ImportedTrace
from ..schemas import ToolCall
from .policy import Policy, evaluate
from .rules import detect, unknown_reason

DISCLAIMER = "Classifies recorded actions only. Does not execute actions or predict what an agent would do after a block."


def analyze(trace: ImportedTrace, policy: Policy) -> dict:
    findings, decisions = [], []
    for event in trace.events:
        if isinstance(event, ToolCall):
            matches = detect(event)
            findings.extend(matches)
            decisions.append(evaluate(event, matches, unknown_reason(event), policy))
    return {"schema_version": "1.0", "trace_id": trace.events[0].trace_id,
            "source_sha256": trace.sha256, "policy": policy.model_dump(),
            "events": [event.model_dump() for event in trace.events],
            "warnings": trace.warnings, "findings": findings, "decisions": decisions,
            "disclaimer": DISCLAIMER}
