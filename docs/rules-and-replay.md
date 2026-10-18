# Six-rule forensic engine and policy replay

## Evidence contract

Rules R001–R006 are version **1.0**, severity **high**, with stable titles,
explanations and limitations returned in rule metadata and findings. Detection is
deterministic and independent of selected policy. Each finding identifies the
actual source `event_ids` and up to eight representative `evidence_items` with raw
field paths, values capped at 256 characters and explicit truncation flags. At most
one finding per rule per action is emitted; it is not an inventory of every match.
R004 additionally records excerpt start/end offsets and its exact matched literal.
Sanitized bounded events and original source SHA-256 remain in the response so
excerpts can be correlated with the authorized original file. No command, URL, path or script is executed or resolved
against a real host. UI payload excerpts are capped at 8192 code units.

## Rule signatures

### R001 — protected recursive forced deletion

- Only `process.exec`, `shell:false`, executable basename exactly `rm` (case
  normalized for Windows).
- Recognize short `-r`, `-R`, `-f`, combined/repeated flags made solely from `rRf`,
  long `--recursive`, `--force`, and `--` option termination. Options may appear
  between operands before `--`; both recursive and force must be present.
- A lexically normalized operand matches if equal to/below a protected root, **or
  an ancestor of a protected root** (e.g. `/` targets `/etc` recursively).
- Evidence: executable, matching flags, first matching operand and declared cwd.
- Unsupported options add unknown coverage. Later ambiguous option arguments are
  not treated as operands unless `--` re-establishes the boundary. Already resolved
  operands can still produce a finding. No operands also means unknown coverage.
- No parsing of shell strings, aliases, wrappers, symlinks, globs or GNU option
  arguments outside the listed grammar. A finding is an attempt signature, not
  confirmed deletion; actual `rm` implementations/options may differ.

### R002 — direct privileged execution (preserved)

- `process.exec`, `shell:false`, executable basename exactly `sudo`, `su` or `doas`.
- POSIX matching is case-sensitive; Windows basename matching is case-insensitive.
- Evidence: `arguments.argv[0]`. Paths are not consulted on the host.
- No confirmation of executable identity, privilege level or successful elevation.
  Does not match shell text, `.exe` variants, aliases or indirect wrappers. An
  ambiguous executable can have both a lexical R002 finding and unknown coverage.

### R003 — credential-sensitive write

- `filesystem.write` whose normalized absolute path ends with a full component
  suffix: `.ssh/authorized_keys`, `.ssh/id_rsa`, `.ssh/id_ed25519`,
  `.aws/credentials`, or `.config/gcloud/credentials.db`.
- Evidence: original `arguments.path` and cwd. `a/../b` is normalized; suffix
  boundaries prevent matching `authorized_keys.bak` or `.sshish/authorized_keys`.
- Windows matching is case-insensitive; POSIX is case-sensitive. Content is not
  interpreted. Legitimate credential maintenance can match. Other credential files,
  cloud SDK stores, symlink targets and actual file contents are outside this rule.

### R004 — external sensitive-literal request attempt

- `http.request` to a host not exactly allowlisted, with a literal match in body
  or a header **value**. Ambiguous destinations are treated as external for positive
  evidence and independently receive unknown coverage.
- Synthetic marker: exactly `AGENTTRACE_SYNTHETIC_SECRET_001` as a literal substring.
- Also recognizes literal private-key BEGIN headers for `PRIVATE KEY`,
  `RSA PRIVATE KEY`, `EC PRIVATE KEY`, `DSA PRIVATE KEY`, `OPENSSH PRIVATE KEY`,
  and `ENCRYPTED PRIVATE KEY`, each with standard five-hyphen BEGIN delimiters.
  Tests use these header strings only, never actual keys.
- Evidence: original URL and the specific body/header field containing the first
  representative literal, its offset-bounded excerpt and matched marker.
- Host matching canonicalizes DNS case, one trailing dot, IDNA and ordinary
  IPv4/IPv6 forms. IPv6 URL brackets are parsed; allowed hosts are bare addresses.
  Host rules are exact, not suffix/wildcard rules, and cover all ports. A subdomain
  is not trusted merely because its parent is allowed.
- Userinfo, percent-encoded authorities, backslashes, scoped IPv6, malformed host
  syntax, legacy/octal/hex/integer IPv4 representations are not trusted as allowed.
- No DNS/redirect/proxy inspection. No decoding of URL escapes in authorities or
  payloads, base64, encrypted data or nested encodings. Query strings and header
  names are not searched for sensitive literals. Encoded paths do not change host
  classification. This detects a **recorded transmission attempt**, not actual
  exfiltration, and cannot establish that arbitrary content is non-sensitive.

### R005 — narrow download-to-shell pipeline

- Direct POSIX `sh` or `bash` (bare name or absolute path), `shell:false`, exactly
  three argv entries: shell, `-c`, script.
- Script must tokenize into exactly one unquoted pipe: downloader options, one
  absolute unambiguous HTTP(S) URL, `|`, bare/absolute `sh` or `bash` without args.
- Curl options: combinations of `-fsSL`, or `--fail`, `--silent`, `--show-error`,
  `--location`; curl with no options also matches.
- Wget options: `-q`, `--quiet`, plus required stdout option `-O -`, `-O-`,
  `-qO-`, or `--output-document=-`.
- Quoted URL tokens and ordinary whitespace are supported. Expansion, backslashes,
  control newlines, redirections, compound commands, wildcard/bracket characters,
  comments, additional pipes or unsupported arguments do not match.
- Evidence: all three raw argv entries. `shlex` tokenization treats script content
  as data; it is not executed. **Every shell script stays unknown**, even a positive
  R005 match. Other download/execute patterns and shell dialects are not covered.

### R006 — lexical outside-workspace write

- `filesystem.write` whose normalized absolute path is not equal to or below any
  workspace root for its declared path flavor. Component boundaries matter:
  `/workspace-other` is outside `/workspace`.
- Evidence: original path and cwd. Relative traversal is normalized before testing.
- Unresolvable paths yield unknown coverage, not a fabricated outside-root finding.
  No actual write, symlink/mount resolution, permissions or sandbox state is checked.

## Host-independent lexical paths and configuration

All paths use the declared `path_flavor`, default POSIX, irrespective of the server
OS. POSIX uses `/`, case-sensitive normalization, absolute paths or an absolute cwd
for relative paths. Windows uses drive-absolute roots, accepts slash/backslash and
lowercases for comparison. Windows drive-relative/root-relative paths, UNC/device
paths, ADS colons, reserved device names and trailing dots/spaces are unknown.
POSIX double-leading slash and backslash paths are also conservatively unknown.
Paths containing expansion/glob-like `$`, `%`, `~`, `*`, `?`, brackets or braces,
or control characters cannot establish containment. A relative cwd is unresolved.
This intentionally marks some valid literal filenames unknown rather than allowing
ambiguous interpretation. Case normalization is not a complete filesystem emulator.
Symlinks, junctions, short names, mounts and executable identities are never resolved.

Defaults, snapshotted as `engine_config` in every analysis:

| Setting | POSIX | Windows |
| --- | --- | --- |
| protected roots | `/etc`, `/home`, `/workspace` | `C:/Windows`, `C:/Users`, `C:/workspace` |
| workspace roots | `/workspace` | `C:/workspace` |

Default allowed hosts: `localhost`, `127.0.0.1`, `::1`. Sensitive synthetic marker is
fixed to the documented public test literal; arbitrary secret lists are not accepted.
`X-AgentTrace-Config` optionally overrides root maps/hosts per request (JSON up to
8192 UTF-8 bytes). Each root map requires both flavors, each with 1–16 unambiguous
absolute roots of at most 256 characters. Host lists have 0–64 exact canonicalizable
entries; empty means no trusted hosts. No wildcard, URL, port, username or path in
allowed hosts. Missing top-level fields use defaults. Unknown config fields,
duplicate keys, excessive nesting or invalid roots/hosts return bounded errors.
The UI currently uses defaults; custom configuration is an API capability only.

## Policy v2.0 and comparison semantics

1. Import/validate once, preserving source order; inspect each tool call once.
2. Retain all positive rule findings **and** independent unknown reasons.
3. Evaluate rule and tool policy entries together. Only if none match, apply default.
4. Add unknown-action decision when coverage is unknown, plus minimum `review`.
5. Choose `block > review > allow`, independent of rule/dictionary order.

Baseline **2.0**: all six rule entries review, unknown review, default allow.
Strict **2.0**: all six rule entries block, unknown block, default allow. Policy
version changed from 1.0 because adding five rule mappings changes classification.
Rule/event versions remain 1.0. Versions are included with their actual configs.

The same trace produces both runs, counts and per-action changes in `comparison`.
`differences` lists changed decisions only and explains rule/unknown mappings.
Intervention counts count nonallow actions, not findings: `rule_triggered` means at
least one nonallow rule entry, `unknown_action` means a coverage intervention. These
categories **overlap**; they must not be added as if mutually exclusive. Tool/default
interventions remain explicit in per-call sources for custom engine policies.

Every recorded call is evaluated independently. After the first hypothetical block
in each policy run, later calls get `recorded_continuation_after_block` and that
run's `blocked_by_event_id`. A later call can still classify allow. This says only
where recorded continuation appears, **not** that it would occur after enforcing a
block. Results retain their original data and do not prove actions succeeded.

Unknown coverage includes unknown tools, unresolved paths/destinations, unsupported
rm forms, ambiguous process cwd/executable, `shell:true`, and these interpreter/
wrapper basenames: sh, bash, dash, zsh, cmd, cmd.exe, powershell, powershell.exe, pwsh,
env, python, python3, node. This finite list is not exhaustive. Remaining actions
have **limited** six-rule coverage, never a declaration of safety. No findings is
not proof of safety. R005 can coexist with unknown shell coverage; R004 can coexist
with unknown authority coverage; credential writes can trigger both R003 and R006.

## Verification fixtures and limits

- Original `benign.jsonl` and `risky.jsonl` behavior is preserved.
- `forensic.jsonl` is explicitly synthetic: one positive for each rule, an unknown
  call, and an unmatched call after a hypothetical block. No samples were executed.
- Independently specified goldens in `backend/tests/golden/` assert exact rule IDs,
  versions, severities, event IDs, matched fields/excerpts, decision/source sequences,
  coverage classifications, continuation labels, counts and difference explanations.
- Parameterized tests cover positive, negative, near-miss, normalization/host edges,
  ambiguous inputs, configuration isolation, mixed findings/coverage, all precedence
  permutations and attempts to invoke network/process effects during analysis.
- Frontend tests cover same-trace cards, category separation/overlap, difference
  reasons, local switching, evidence navigation, pagination, hostile HTML-as-text,
  payload truncation, stale-error clearing and import limits.
- HTTP smoke checks all samples, configuration, six rules and both policies; CI
  repeats full checks and Docker network-isolated build/runtime checks.

Importer limits remain 5 MiB / 10,000 events / 64 KiB per line / nesting depth 20.
Malformed recognized-tool arguments reject the entire trace with line-numbered
errors; there is no partial analysis. Findings are bounded per action; UI collections
paginate at 100. Source data and bounded rich analysis are returned locally, not
persisted automatically. Milestone 3 adds heuristic redaction and deterministic
JSON/Markdown exports after detection, without changing these rule semantics. See
`reports-and-redaction.md` for opaque references, source offsets and privacy limits.
General program semantics, real execution and prediction of subsequent behavior
remain out of scope.
