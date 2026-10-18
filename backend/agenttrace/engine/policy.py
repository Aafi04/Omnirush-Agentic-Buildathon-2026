"""Classify every recorded call independently. Never execute or simulate it."""
from typing import Literal

from pydantic import Field

from ..schemas import Identifier, StrictModel

Decision = Literal["allow", "review", "block"]
RANK = {"allow": 0, "review": 1, "block": 2}


class Policy(StrictModel):
    schema_version: Literal["1.0"] = "1.0"
    policy_id: Identifier
    version: str = "1.0"
    rules: dict[str, Decision] = Field(default_factory=dict)
    tools: dict[str, Decision] = Field(default_factory=dict)
    default: Decision = "allow"
    unknown: Decision = "review"


POLICIES = {
    "baseline": Policy(policy_id="baseline", rules={"R002": "review"}),
    "strict": Policy(policy_id="strict", rules={"R002": "block"}, unknown="block"),
}


def evaluate(call, findings: list[dict], unknown: str | None, policy: Policy) -> dict:
    matches = []
    for finding in findings:
        rule = finding["rule_id"]
        if rule in policy.rules:
            matches.append({"source": f"rule:{rule}", "decision": policy.rules[rule]})
    if call.tool in policy.tools:
        matches.append({"source": f"tool:{call.tool}", "decision": policy.tools[call.tool]})
    if not matches:
        matches.append({"source": "default", "decision": policy.default})
    if unknown:
        matches.append({"source": "unknown_action", "decision": policy.unknown})
        matches.append({"source": "unknown_minimum", "decision": "review"})
    decision = max((match["decision"] for match in matches), key=RANK.get)
    return {"event_id": call.event_id, "call_id": call.call_id, "decision": decision,
            "matches": matches, "coverage": "unknown" if unknown else "limited",
            "coverage_reason": unknown or "Only R002 direct privileged execution is checked."}
