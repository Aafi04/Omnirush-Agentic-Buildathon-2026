# Event contract v1.0

The source of truth is `backend/agenttrace/schemas.py`; `GET /api/schema`
returns its generated JSON Schema, including recognized-tool argument constraints.
Frontend event types are in `frontend/src/types.ts`.

Each nonblank UTF-8 JSONL line is a single object. Source-line order is authoritative.
Blank lines are ignored; CRLF is supported. BOM-prefixed files are rejected.

Common required fields:
- `schema_version`: exactly `"1.0"`.
- `trace_id`, `event_id`, `call_id`: 1–128 characters, `[A-Za-z0-9_.:-]`.
- `timestamp`: RFC3339 with timezone and optional 1–6 fractional digits.
- `type`: `tool_call` or `tool_result`.

Calls require `tool` (1–128 characters) and `arguments` (a JSON object).
Results require `status` (`ok` / `error`) and `output` (any finite, valid-Unicode JSON value).
Unknown top-level fields are rejected.

Recognized calls validate these arguments strictly (no extra fields):
- `process.exec`: nonempty `argv` of strings (max 256 arguments, 8192 characters each),
  `cwd` (nonempty string), `shell` (boolean), optional `path_flavor` (`posix` default / `windows`).
- `filesystem.write`: `path`, `cwd` (nonempty strings), `content` (string), optional `path_flavor`.
- `http.request`: uppercase `method` (GET/POST/PUT/PATCH/DELETE/HEAD/OPTIONS),
  absolute HTTP(S) `url`, optional string-to-string `headers` and string `body`.

NUL bytes in process arguments and paths are rejected. HTTP URLs cannot contain
raw whitespace/control characters or invalid ports. Headers are limited to 64
entries: token names (1–128 ASCII characters), values up to 8192 characters,
without CR/LF/NUL. Ambiguous but structurally valid authorities (userinfo,
percent-encoded hosts, legacy numeric IPs) import with unknown destination coverage.

Unknown tool names accept JSON-object arguments and receive a minimum policy decision
of review. These schemas describe recorded data, not callable interfaces.

Within a trace: event IDs and call IDs for calls must be unique; at most one result
per call ID. Results link by call ID even if recorded before the call. Missing calls,
missing results and timestamp regressions produce event-linked integrity warnings.
Mixed trace IDs and duplicate IDs reject the entire import.

Limits: 5 MiB raw UTF-8, 64 KiB per line (before trimming), 10,000 nonblank events,
20 nested JSON containers. Duplicate JSON keys, nonfinite numbers, lone Unicode
surrogates, invalid argument types and unsupported schema versions reject the import.
Errors are bounded codes plus optional source line numbers, never payload echoes.

See `samples/benign.jsonl`, `samples/risky.jsonl` and `samples/forensic.jsonl` for
synthetic examples. Event version remains 1.0. Analysis adds comparison/coverage
fields without removing the original selected-policy fields. See
`docs/rules-and-replay.md` for rule versions, API configuration and replay semantics.

Milestone 3 sanitizes public analysis after original-data detection. Sensitive
identifiers become unique opaque aliases; all finding/warning/decision references
use the same aliases. `sanitization.version` is `1.0`; clients must not display an
unmarked legacy response. `reports.format_version` is `1.0`, with server-generated
JSON/Markdown strings and JSON report digest. Report schema is distinct from event
schema: its ordered `event_index` excludes arguments/output. See
`docs/reports-and-redaction.md` for canonical serialization and privacy limits.
