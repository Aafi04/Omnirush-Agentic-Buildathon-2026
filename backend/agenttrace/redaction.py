"""Deterministic, request-local heuristic redaction; never changes engine input.

Collection precedes replacement. Aho-Corasick matching avoids scanning every
secret for every string. Patterns use at most 32 characters per representation;
partial matches (at least eight characters) conservatively consume the rest of
the string. This bounds trie size by 32 * collected representations, including
for thousands of long credentials, and protects truncated evidence. It can hide
innocent suffixes. This is deliberately best effort, not a secrecy guarantee.
"""
from collections import deque
import base64
import json
import re
from urllib.parse import quote, quote_plus, unquote


NOTICE = (
    "Best-effort heuristic redaction, not a cryptographic secrecy guarantee. "
    "Unknown formats, encodings and fragments shorter than eight characters may escape detection; "
    "short known values are matched as whole strings or at token boundaries. "
    "Conservative partial matches may hide innocent suffixes; values sharing a 32-character "
    "prefix may share a reference. Raw source remains in request memory."
)
REFERENCE_SEMANTICS = (
    "Opaque secret ordinals are local to this analysis, assigned by sorted-key depth-first "
    "collection (arrays retain source order); they are not hashes or cross-report identifiers. "
    "Repeated recognized values share a reference. Redactions counts replacement occurrences, "
    "including dictionary keys, within this document. Colliding keys receive deterministic suffixes. "
    "Sensitive trace/event/call identifiers use separate unique opaque namespaces assigned in source "
    "event order, preserving typed references without hashes. Public analysis preserves trusted "
    "schema structure and controlled constants outside arbitrary payloads."
)
_NAMES = (
    r"(?:proxy[-_]?authorization|authorization|x[-_]api[-_]key|set[-_]cookie|cookie|"
    r"(?:access|refresh|auth|id)[-_]?token|token|password|passwd|secret|"
    r"api[-_]?key|client[-_]?secret|private[-_]?key|credentials?|synthetic_markers)"
)
_KEY = re.compile(r"^" + _NAMES + r"$", re.I)
_ASSIGN = re.compile(
    r"(?<![\w])(?:[\"']?" + _NAMES + r"[\"']?)\s*[:=]\s*"
    r"(?:\"(?P<double>(?:\\.|[^\"\\])*)\"|'(?P<single>[^']*)'|(?P<bare>[^\s,;&}\]\"']+))", re.I
)
_AUTH = re.compile(r"\b(?:Bearer|Basic)\s+([A-Za-z0-9._~+/=:-]+)", re.I)
_PREFIX = re.compile(
    r"AGENTTRACE_SYNTHETIC_SECRET_001|(?:AKIA|ASIA)[A-Z0-9]{16}|"
    r"sk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{12,}|"
    r"(?:gh[pousr]_[A-Za-z0-9]{12,}|github_pat_[A-Za-z0-9_]{12,})"
)
_URL = re.compile(r"[A-Za-z][A-Za-z0-9+.-]*://([^\s/@]+)@")
_PRIVATE = re.compile(r"-{2,}BEGIN\s+(?:(?:[A-Z]+\s+)*PRIVATE(?:\s+KEY)?|PRI(?:VATE)?)(?:-+)?", re.I)
_END = re.compile(r"-{2,}END[^\r\n]*?(?:KEY)?-{2,}", re.I)


class Redactor:
    """Collect an entire analysis, then sanitize copies without side effects."""

    def __init__(self):
        self._values = {}
        self._patterns = {}
        self._nodes = None
        self.redactions = 0
        self._ordinal = 0
        self._collected = False

    def _remember(self, text, ref=None):
        if not isinstance(text, str) or not text:
            return
        if text in self._values:
            return
        existing = self._patterns.get(text[:32])
        if ref is None and existing is not None:
            ref = existing[0]
        if ref is None:
            self._ordinal += 1
            ref = f"[REDACTED:secret-{self._ordinal:04d}]"
        self._values[text] = ref
        # Deliberately bounded representations, not recursive decoding.
        forms = {text, quote(text, safe=""), quote_plus(text), json.dumps(text, ensure_ascii=True)[1:-1]}
        for form in sorted(forms):
            self._patterns.setdefault(form[:32], (ref, len(form) > 32))
        self._nodes = None

    def _sensitive(self, value):
        if isinstance(value, str):
            auth = _AUTH.fullmatch(value.strip())
            self._remember(auth.group(1) if auth else value)
            if auth and value.strip().lower().startswith("basic "):
                try:
                    decoded = base64.b64decode(auth.group(1), validate=True).decode("utf-8")
                    self._remember(decoded)
                    if ":" in decoded:
                        self._remember(decoded.split(":", 1)[1])
                except (ValueError, UnicodeError):
                    pass
        elif isinstance(value, dict):
            for key in sorted(value):
                self._sensitive(value[key])
        elif isinstance(value, list):
            for item in value:
                self._sensitive(item)
        elif isinstance(value, (int, float, bool)):
            self._remember(str(value))

    def _discover(self, text):
        for match in _ASSIGN.finditer(text):
            value = next(part for part in match.groups() if part is not None)
            try:
                value = json.loads('"' + value + '"') if match.group("double") is not None else value
            except (ValueError, TypeError):
                pass
            self._sensitive(value)
            self._sensitive(unquote(value))
        for match in _AUTH.finditer(text):
            self._sensitive(match.group())
        for match in _PREFIX.finditer(text):
            self._remember(match.group())
        for match in _URL.finditer(text):
            self._remember(match.group(1))
            for part in match.group(1).split(":", 1):
                self._remember(unquote(part))
        # An unfinished delimiter/block masks through end of string. Bodies are
        # also collected independently so delimiter-free evidence is covered.
        for start in _PRIVATE.finditer(text):
            end = _END.search(text, start.end())
            block = text[start.start():end.end() if end else len(text)]
            self._remember(block)
            for line in block.splitlines()[1:]:
                if line and not line.startswith("--"):
                    self._remember(line.strip())

    def collect(self, value):
        self._collected = True
        if isinstance(value, dict):
            evidence_sensitive = value.get("truncated") is True or bool(
                re.search(_NAMES, str(value.get("field", "")), re.I)
            )
            for key in sorted(value):
                self._discover(key)
                child = value[key]
                if _KEY.fullmatch(key) or (key == "value" and evidence_sensitive):
                    self._sensitive(child)
                    if "cookie" in key.lower() and isinstance(child, str):
                        for part in child.split(";"):
                            if "=" in part:
                                self._remember(part.split("=", 1)[1].strip())
                self.collect(child)
        elif isinstance(value, list):
            for item in value:
                self.collect(item)
        elif isinstance(value, str):
            self._discover(value)
        return self

    def _compile(self):
        # node = [edges, failure, best terminal (length, ref, consume_suffix)]
        nodes = [[{}, 0, None]]
        for text, (ref, tail) in self._patterns.items():
            state = 0
            for length, char in enumerate(text, 1):
                if char not in nodes[state][0]:
                    nodes[state][0][char] = len(nodes)
                    nodes.append([{}, 0, None])
                state = nodes[state][0][char]
                if length >= 8 or length == len(text):
                    terminal = (length, ref, tail or length < len(text))
                    if nodes[state][2] is None or (nodes[state][2][2] and not terminal[2]):
                        nodes[state][2] = terminal
        queue = deque(nodes[0][0].values())
        while queue:
            state = queue.popleft()
            for char, child in nodes[state][0].items():
                queue.append(child)
                failure = nodes[state][1]
                while failure and char not in nodes[failure][0]:
                    failure = nodes[failure][1]
                nodes[child][1] = nodes[failure][0].get(char, 0)
                inherited = nodes[nodes[child][1]][2]
                if nodes[child][2] is None:
                    nodes[child][2] = inherited
        self._nodes = nodes

    def _text(self, text):
        if text in self._values:
            self.redactions += 1
            return self._values[text]
        if self._nodes is None:
            self._compile()
        nodes, state, spans = self._nodes, 0, {}
        for index, char in enumerate(text):
            while state and char not in nodes[state][0]:
                state = nodes[state][1]
            state = nodes[state][0].get(char, 0)
            terminal = nodes[state][2]
            if terminal:
                length, ref, tail = terminal
                start = index + 1 - length
                if length < 8 and (
                    (start > 0 and (text[start - 1].isalnum() or text[start - 1] == "_"))
                    or (index + 1 < len(text) and (text[index + 1].isalnum() or text[index + 1] == "_"))
                ):
                    continue
                # Keep the longest match for each start; a partial match is
                # expanded only after scanning, so full credentials win.
                spans[start] = (index + 1, ref, tail)
        result, cursor = [], 0
        merged = []
        for start, (end, ref, tail) in sorted(spans.items()):
            end = len(text) if tail else end
            if merged and start < merged[-1][1]:
                previous = merged[-1]
                merged[-1] = (previous[0], max(previous[1], end), previous[2])
            else:
                merged.append((start, end, ref))
        for start, end, ref in merged:
            if start < cursor:
                continue
            result.extend((text[cursor:start], ref))
            self.redactions += 1
            cursor = end
        result.append(text[cursor:])
        return "".join(result)

    def sanitize(self, value, _root=True, _sensitive=False):
        if _root and not self._collected:
            self.collect(value)
        if isinstance(value, str):
            return self._text(value)
        if isinstance(value, list):
            return [self.sanitize(item, False, _sensitive) for item in value]
        if isinstance(value, dict):
            result = {}
            for key in sorted(value):
                clean = self._text(key)
                candidate, ordinal = clean, 1
                while candidate in result:
                    candidate = f"{clean}[key-{ordinal:04d}]"
                    ordinal += 1
                # Original raw-byte fingerprint is intentionally public; a
                # digest-shaped string is never itself a credential heuristic.
                result[candidate] = value[key] if _root and key == "source_sha256" else self.sanitize(value[key], False, _sensitive or bool(_KEY.fullmatch(key)))
            return result
        if _sensitive and isinstance(value, (int, float, bool)):
            return self._text(str(value))
        return value

    def metadata(self):
        return {"version": "1.0", "redactions": self.redactions,
                "notice": NOTICE, "reference_semantics": REFERENCE_SEMANTICS}


# Explicit context grammar, not a global whitelist: a payload's `event_id`,
# `policy`, `decision`, etc. remain ordinary data, including their dictionary keys.
_STRUCTURE = {
    "analysis": {"schema_version": "schema_version", "trace_id": "trace_id", "source_sha256": "fingerprint",
                 "policy": "policy", "events": "event", "warnings": "warning", "findings": "finding",
                 "decisions": "decision", "disclaimer": "data", "engine_config": "config", "rules": "rule",
                 "unknown_coverage": "unknown", "comparison": "comparison"},
    "event": {"schema_version": "schema_version", "trace_id": "trace_id", "event_id": "event_id",
              "call_id": "call_id", "timestamp": "data", "type": "event_type", "tool": "data",
              "status": "status", "arguments": "data", "output": "data"},
    "policy": {"schema_version": "schema_version", "policy_id": "data", "version": "policy_version",
               "rules": "policy_rules", "tools": "policy_tools", "default": "action", "unknown": "action"},
    "finding": {"rule_id": "rule_id", "rule_version": "rule_version", "severity": "severity",
                "event_ids": "event_id", "field": "data", "evidence": "data", "message": "data",
                "title": "data", "limitations": "data", "evidence_items": "evidence_item"},
    "evidence_item": {"field": "data", "value": "data", "truncated": "data", "start": "data",
                      "end": "data", "matched_literal": "data"},
    "decision": {"event_id": "event_id", "call_id": "call_id", "decision": "action", "matches": "match",
                 "coverage": "coverage", "coverage_reason": "data", "coverage_reasons": "data",
                 "intervention_sources": "source", "recorded_continuation_after_block": "data",
                 "blocked_by_event_id": "event_id"},
    "match": {"source": "source", "decision": "action"},
    "comparison": {"baseline": "summary", "strict": "summary", "differences": "difference"},
    "summary": {"policy": "policy", "decisions": "decision", "counts": "counts", "interventions": "interventions"},
    "counts": {"allow": "data", "review": "data", "block": "data"},
    "interventions": {"rule_triggered": "data", "unknown_action": "data"},
    "difference": {"event_id": "event_id", "baseline": "action", "strict": "action", "reason": "data"},
    "warning": {"code": "warning_code", "event_ids": "event_id"},
    "unknown": {"event_id": "event_id", "reasons": "data"},
    "rule": {"rule_id": "rule_id", "rule_version": "rule_version", "severity": "severity", "title": "data", "limitations": "data"},
    "config": {"protected_roots": "roots", "workspace_roots": "roots", "allowed_hosts": "data", "synthetic_markers": "data"},
    "roots": {"posix": "data", "windows": "data"},
}
_RULE_IDS = {f"R{index:03d}" for index in range(1, 7)}
_CONTROLLED = {
    "schema_version": {"1.0"}, "rule_version": {"1.0"}, "policy_version": {"2.0"},
    "event_type": {"tool_call", "tool_result"}, "status": {"ok", "error"},
    "action": {"allow", "review", "block"}, "coverage": {"limited", "unknown"},
    "rule_id": _RULE_IDS, "severity": {"high"},
    "source": {"default", "unknown_action", "unknown_minimum"} | {f"rule:{rule}" for rule in _RULE_IDS},
    "warning_code": {"timestamp_regression", "incomplete_call", "orphan_result"},
}


class PublicSanitizer:
    """Opt-in engine-output grammar layered over a fully collected Redactor.

    Only explicit generated positions preserve structural keys and controlled
    values. No exemptions propagate into arguments/output, messages, tool names,
    evidence, dynamic tool-policy keys, or unexpected metadata. Generic Redactor
    behavior is unchanged. ID aliases are allocated before walking any report.
    """

    def __init__(self, redactor, analysis):
        self.redactor = redactor
        self.identifiers = {kind: {} for kind in ("trace", "event", "call")}
        self._generic_ids = {}
        self._sensitive_ids = {}
        for event in analysis.get("events", []):
            for kind in ("trace", "event", "call"):
                self._register(kind, event.get(kind + "_id"))
        self._register("trace", analysis.get("trace_id"))

    def _register(self, kind, value):
        if not isinstance(value, str) or value in self.identifiers[kind]:
            return
        if value not in self._sensitive_ids:
            count = self.redactor.redactions
            self._sensitive_ids[value] = self.redactor._text(value) != value
            self.redactor.redactions = count
        if self._sensitive_ids[value]:
            namespace = self.identifiers[kind]
            alias = f"[REDACTED:{kind}-{len(namespace) + 1:04d}]"
            namespace[value] = alias
            self._generic_ids.setdefault(value, alias)

    def _text(self, value, context):
        if context in {"trace_id", "event_id", "call_id"}:
            alias = self.identifiers[context[:-3]].get(value)
            if alias is not None:
                self.redactor.redactions += 1
                return alias
        if context == "fingerprint" or value in _CONTROLLED.get(context, ()):
            return value
        if value in self._generic_ids:
            self.redactor.redactions += 1
            return self._generic_ids[value]
        return self.redactor._text(value)

    def sanitize(self, value, context="analysis"):
        if isinstance(value, str):
            return self._text(value, context)
        if isinstance(value, list):
            return [self.sanitize(item, context) for item in value]
        if isinstance(value, dict):
            result = {}
            fields = _STRUCTURE.get(context, {})
            for key in sorted(value):
                child_context = fields.get(key, "secret_data" if context == "secret_data" or _KEY.fullmatch(key) else "data")
                trusted_key = key in fields
                if context in {"policy_rules", "policy_tools"}:
                    trusted_key = context == "policy_rules" and key in _RULE_IDS
                    # A credential-shaped dynamic key is never an enum exemption.
                    child_context = "data" if _KEY.fullmatch(key) else "action"
                clean = key if trusted_key else self._text(key, "data")
                candidate, ordinal = clean, 1
                while candidate in result:
                    candidate = f"{clean}[key-{ordinal:04d}]"
                    ordinal += 1
                result[candidate] = self.sanitize(value[key], child_context)
            return result
        if context == "secret_data" and isinstance(value, (int, float, bool)):
            return self.redactor._text(str(value))
        return value
