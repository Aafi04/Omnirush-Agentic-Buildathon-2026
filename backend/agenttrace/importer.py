"""Bounded, all-or-nothing import. Error messages never echo trace payloads."""
import hashlib
import json
import math
from datetime import datetime
from dataclasses import dataclass

from pydantic import ValidationError

from .schemas import ARGUMENT_SCHEMAS, EVENT_ADAPTER, ToolCall, ToolResult

MAX_BYTES = 5 * 1024 * 1024
MAX_LINE_BYTES = 64 * 1024
MAX_EVENTS = 10_000
MAX_DEPTH = 20


class ImportFailure(ValueError):
    def __init__(self, code: str, line: int | None = None, status: int = 422):
        self.code, self.line, self.status = code, line, status
        super().__init__(code)


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate key")
        result[key] = value
    return result


def reject_constant(value):
    raise ValueError("non-finite number")


def finite_float(value):
    number = float(value)
    if not math.isfinite(number):
        raise ValueError("non-finite number")
    return number


def check_unicode(value):
    """JSON permits escaped lone surrogates, but UTF-8 responses cannot encode them."""
    pending = [value]
    while pending:
        item = pending.pop()
        if isinstance(item, str):
            item.encode("utf-8", errors="strict")
        elif isinstance(item, dict):
            pending.extend(item.keys())
            pending.extend(item.values())
        elif isinstance(item, list):
            pending.extend(item)


def check_depth(line: str, number: int):
    depth, quoted, escaped = 0, False, False
    for char in line:
        if quoted:
            if escaped:
                escaped = False
            elif char == "\\":
                escaped = True
            elif char == '"':
                quoted = False
        elif char == '"':
            quoted = True
        elif char in "[{":
            depth += 1
            if depth > MAX_DEPTH:
                raise ImportFailure("nesting_limit", number)
        elif char in "]}":
            depth -= 1


@dataclass
class ImportedTrace:
    events: list[ToolCall | ToolResult]
    warnings: list[dict]
    sha256: str


def ingest(raw: bytes) -> ImportedTrace:
    if len(raw) > MAX_BYTES:
        raise ImportFailure("input_too_large", status=413)
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        raise ImportFailure("invalid_utf8") from None
    events, warnings = [], []
    ids, calls, results = set(), {}, {}
    trace_id, previous = None, None
    for number, line in enumerate(text.split("\n"), 1):
        if len(line.encode("utf-8")) > MAX_LINE_BYTES:
            raise ImportFailure("line_too_large", number)
        if not line.strip():
            continue
        if len(events) >= MAX_EVENTS:
            raise ImportFailure("event_limit", number)
        check_depth(line, number)
        try:
            data = json.loads(line, object_pairs_hook=unique_object, parse_constant=reject_constant, parse_float=finite_float)
            check_unicode(data)
            event = EVENT_ADAPTER.validate_python(data)
            if isinstance(event, ToolCall) and event.tool in ARGUMENT_SCHEMAS:
                ARGUMENT_SCHEMAS[event.tool].model_validate(event.arguments)
        except (ValueError, ValidationError, RecursionError):
            raise ImportFailure("invalid_event", number) from None
        if event.event_id in ids:
            raise ImportFailure("duplicate_event_id", number)
        if trace_id is not None and trace_id != event.trace_id:
            raise ImportFailure("mixed_trace_ids", number)
        if isinstance(event, ToolCall):
            if event.call_id in calls:
                raise ImportFailure("duplicate_call_id", number)
            calls[event.call_id] = event.event_id
        else:
            if event.call_id in results:
                raise ImportFailure("duplicate_result", number)
            results[event.call_id] = event.event_id
        current = datetime.fromisoformat(event.timestamp.replace("Z", "+00:00"))
        if previous is not None and current < previous:
            warnings.append({"code": "timestamp_regression", "event_ids": [event.event_id]})
        previous, trace_id = current, event.trace_id
        ids.add(event.event_id)
        events.append(event)
    if not events:
        raise ImportFailure("empty_trace")
    for call_id, event_id in calls.items():
        if call_id not in results:
            warnings.append({"code": "incomplete_call", "event_ids": [event_id]})
    for call_id, event_id in results.items():
        if call_id not in calls:
            warnings.append({"code": "orphan_result", "event_ids": [event_id]})
    return ImportedTrace(events, warnings, hashlib.sha256(raw).hexdigest())
