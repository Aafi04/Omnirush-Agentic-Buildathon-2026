"""Canonical public forensic reports derived exclusively from sanitized analysis."""
import hashlib
import json

from .redaction import PublicSanitizer, Redactor


SOURCE_SEMANTICS = (
    "SHA256 of the original raw UTF-8 source bytes, including line endings and blank lines; "
    "not a hash of parsed events, sanitized content, or this report."
)
LIMITATIONS = (
    "Counterfactual policy replay evaluates recorded actions only; does not execute or predict subsequent behavior. "
    "No confirmation of effects/transmission. Six narrow heuristic detectors have limited coverage; unknown or "
    "absent findings do not establish safety. Lexical paths do not resolve symlinks or mounts. "
    "Redaction is heuristic and is not a cryptographic secrecy guarantee."
)


def _canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False) + "\n"


def _validate_references(document):
    events = document["event_index"]
    ids = [event["event_id"] for event in events]
    if len(ids) != len(set(ids)):
        raise ValueError("Inconsistent analysis: duplicate event references")
    known = set(ids)
    calls = {event["event_id"]: event.get("call_id") for event in events}

    def visit(value):
        if isinstance(value, dict):
            for key, item in value.items():
                if key in {"event_id", "blocked_by_event_id"} and item is not None and item not in known:
                    raise ValueError("Inconsistent analysis: missing event reference")
                if key == "event_ids" and any(ref not in known for ref in item):
                    raise ValueError("Inconsistent analysis: missing evidence reference")
                visit(item)
            if "event_id" in value and "call_id" in value and calls[value["event_id"]] != value["call_id"]:
                raise ValueError("Inconsistent analysis: mismatched call reference")
        elif isinstance(value, list):
            for item in value:
                visit(item)

    for field in ("findings", "warnings", "unknown_coverage", "comparison"):
        visit(document[field])


def _safe_text(value):
    # Keep ordinary text readable in downloaded .md, but encode punctuation,
    # controls and non-ASCII (including bidi controls). Entity expansion is text,
    # never re-parsed as Markdown/HTML; colons/slashes cannot create autolinks.
    return "".join(char if char.isascii() and (char.isalnum() or char == " ")
                   else f"&#{ord(char)};" for char in str(value))


def _markdown(document):
    lines = ["# AgentTrace forensic report", "", LIMITATIONS, "", "## Investigation summary", "",
             f"- Recorded events: {len(document['event_index'])}",
             f"- Rule findings: {len(document['findings'])}",
             f"- Unknown coverage actions: {len(document['unknown_coverage'])}",
             f"- Import integrity warnings: {len(document['warnings'])}",
             f"- Changed policy outcomes: {len(document['comparison']['differences'])}"]
    for name in ("baseline", "strict"):
        run = document["comparison"].get(name, {})
        counts = run.get("counts", {})
        lines.append(f"- {name.title()}: allow {counts.get('allow', 0)}, review {counts.get('review', 0)}, block {counts.get('block', 0)}")
    lines.append("")

    def render(value, depth=0):
        prefix = "  " * depth + "- "
        if isinstance(value, dict):
            if not value:
                lines.append(prefix + "(empty object)")
            for key in sorted(value):
                child = value[key]
                if isinstance(child, (dict, list)):
                    lines.append(prefix + _safe_text(key) + ":")
                    render(child, depth + 1)
                else:
                    lines.append(prefix + _safe_text(key) + ": " + _safe_text(json.dumps(child, ensure_ascii=True, allow_nan=False)))
        elif isinstance(value, list):
            if not value:
                lines.append(prefix + "(none)")
            for index, item in enumerate(value):
                lines.append(prefix + f"Item {index + 1}:")
                render(item, depth + 1)
        else:
            lines.append(prefix + _safe_text(json.dumps(value, ensure_ascii=True, allow_nan=False)))

    for title, key in (
        ("Report format", "format_version"), ("Trace", "trace_id"),
        ("Original source fingerprint", "source_sha256"), ("Fingerprint semantics", "source_sha256_semantics"),
        ("Event schema version", "event_schema_version"), ("Rule metadata and versions", "rules"),
        ("Engine configuration snapshot", "engine_config"), ("Warnings", "warnings"),
        ("Findings and exact evidence", "findings"), ("Unknown coverage", "unknown_coverage"),
        ("Baseline and strict policy comparison", "comparison"), ("Event index (metadata only)", "event_index"),
        ("Sanitization", "sanitization"),
    ):
        lines.extend(("## " + title, ""))
        render(document[key])
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


def public_analysis(raw_analysis: dict) -> dict:
    """Return sanitized legacy fields plus canonical exports; never mutate input.

    Reports omit selected-policy shortcuts and all event arguments/output. The
    digest is external to the canonical document and covers its one final LF.
    Report redaction counts apply to the curated report; envelope counts apply
    to the sanitized original analysis (before attaching generated exports).
    """
    redactor = Redactor()
    # Selected UI policy cannot reorder the common opaque-reference namespace.
    invariant = {key: value for key, value in raw_analysis.items() if key not in {"policy", "decisions", "reports", "sanitization"}}
    redactor.collect(invariant)
    redactor.collect({key: raw_analysis[key] for key in ("policy", "decisions") if key in raw_analysis})
    sanitizer = PublicSanitizer(redactor, raw_analysis)
    sanitized = sanitizer.sanitize(invariant)
    redactor.redactions = 0
    document = {
        "format_version": "1.0", "trace_id": sanitized.get("trace_id"),
        "source_sha256": sanitized.get("source_sha256"), "source_sha256_semantics": SOURCE_SEMANTICS,
        "event_schema_version": sanitized.get("schema_version", "1.0"),
        "rules": sorted(sanitized.get("rules", []), key=lambda rule: (rule.get("rule_id", ""), rule.get("rule_version", ""))),
        "engine_config": sanitized.get("engine_config", {}), "warnings": sanitized.get("warnings", []),
        "findings": sanitized.get("findings", []), "unknown_coverage": sanitized.get("unknown_coverage", []),
        "comparison": {key: sanitized.get("comparison", {}).get(key, [] if key == "differences" else {})
                       for key in ("baseline", "strict", "differences")},
        "event_index": [{key: event[key] for key in ("event_id", "call_id", "type", "timestamp", "tool", "status") if key in event}
                        for event in sanitized.get("events", [])],
        "limitations": LIMITATIONS,
    }
    # Count replacements in curated content without sanitizing already generated
    # refs again; construct the equivalent raw projection for counting only.
    raw_projection = {key: value for key, value in invariant.items() if key not in {"events", "schema_version", "disclaimer"}}
    raw_projection["event_index"] = [{key: event[key] for key in ("event_id", "call_id", "type", "timestamp", "tool", "status") if key in event}
                                   for event in invariant.get("events", [])]
    sanitizer.sanitize({key: value for key, value in raw_projection.items() if key != "event_index"})
    sanitizer.sanitize(raw_projection["event_index"], "event")
    document["sanitization"] = redactor.metadata()
    _validate_references(document)
    report_json = _canonical(document)
    redactor.redactions = 0
    public = sanitizer.sanitize({key: value for key, value in raw_analysis.items() if key not in {"reports", "sanitization"}})
    public["sanitization"] = redactor.metadata()
    public["reports"] = {
        "format_version": "1.0", "json": report_json, "markdown": _markdown(document),
        "report_sha256": hashlib.sha256(report_json.encode("utf-8")).hexdigest(),
    }
    return public
