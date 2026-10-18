# AgentTrace

An offline-capable flight recorder for recorded AI-agent tool activity. Milestone 3
imports JSONL, reconstructs a timeline, applies **six deterministic detectors**, and
compares baseline/strict classifications side by side on the **same trace**, with
centralized best-effort redaction and deterministic JSON/Markdown evidence reports.

**Replay never executes an action and never predicts subsequent agent behavior.**
Every recorded call is evaluated independently, including calls recorded after a
hypothetical block. No findings is not proof of safety.

## Setup (clean Linux)

Requirements: Node **22.19.0** with npm **10.9.3**, Python **3.11.9** with venv/pip.
Runtime versions are pinned in `.nvmrc` and `.python-version`. No global dependency
installation is needed. If your Linux distribution lacks Python's venv module,
use the Docker route rather than modifying system Python.

From the repository root:

```sh
python3.11 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.lock
npm ci --no-audit --no-fund
python scripts/test.py
npm run build
```

On Windows PowerShell, create the same venv with `python -m venv .venv` and activate
with `.venv\Scripts\Activate.ps1`. All remaining commands are the same.

The initial dependency install needs network access or a prepared package cache.
**After setup, tests and the built application need no internet.** A completely
air-gapped first installation requires transferring a prebuilt Docker image or
dependency bundle. Lockfiles pin both direct and transitive packages; no paid API,
model provider, remote font, analytics or cloud service is used.

## Run

After building, with the venv active:

```sh
python -m uvicorn agenttrace.api:app --app-dir backend --host 127.0.0.1 --port 8000 --no-access-log
```

Open **http://localhost:8000**. FastAPI serves both the built UI and API.
Load **Benign sample** (0 findings, one allow decision), or **Risky sample**
(R002 evidence at `risky-1`; review under baseline, block under strict).
The risky sample also includes an unknown call at `risky-3`: review under baseline,
block under strict. Both samples are explicitly synthetic; nothing was executed.
Open **Six-rule sample** for all six detectors: baseline has 1 allow / 7 review /
0 block; strict has 1 allow / 0 review / 7 block. Six rule-triggered interventions
and two unknown-action interventions overlap on the shell pipeline. Changing the
replay selector changes the timeline locally, without reimporting or executing data.
Findings, policy interventions and unknown coverage have separate evidence links.
Import your own UTF-8 `.jsonl` file to inspect sanitized payloads and linked calls/results.

### Guided judge workflow

1. Choose **Explore demo** to load the clearly synthetic forensic recording.
2. Compare baseline's 1 allow / 7 review with strict's 1 allow / 7 block. Categories
   overlap: R005 is a rule finding **and** an unknown shell-coverage intervention.
3. Follow an action's difference link to its timeline entry and field evidence.
   Change **Replay policy** locally; later recorded continuation is not a prediction.
4. Inspect the heuristic-redaction notice and sanitized R004 evidence. A detected
   sensitive literal is represented by an opaque reference, not displayed verbatim.
5. Use **Reports** in section navigation, then **Download JSON** or **Download
   Markdown**. Downloads include analyzed conclusions/evidence but exclude raw event
   arguments/output. Review the reports before sharing: redaction can miss secrets.

The loaded header is compact; section navigation, separate findings/interventions/
unknown panels, focus styles and paginated collections support investigation without
a dashboard redesign. Raw imported filenames are deliberately not displayed.

For frontend development, run the API as above and `npm run dev` in another terminal.
Vite serves http://localhost:5173 and proxies `/api` to the loopback backend.

`.env.example` documents optional local values, but no dotenv loader is used;
pass host/port as CLI arguments. No credentials are required.

## Test and build

With the project venv active, the single cross-platform, offline test command is:

```sh
python scripts/test.py
```

It runs Pytest, Vitest/Testing Library, and the TypeScript checker, stopping on the
first nonzero exit. Linux `make test` is an alias using `.venv/bin/python`.
No package download command is invoked by the test runner.

Individual checks: `python -m pytest -q`, `npm test`, `npm run typecheck`.
Production build: `npm run build`. HTTP smoke test against a running server:
`python scripts/smoke.py` (or `python scripts/smoke.py --port 8001`).

Tests cover bounded import rejection, all six signatures and ambiguity boundaries,
policy precedence and exact goldens, sanitized field/identifier correlation, report
determinism/digests/escaping, header/private-key/credential redaction, sample/file
UI import, errors, keyboard evidence navigation, local policy switching, pagination,
and backend-report-only download bytes, filenames and object-URL cleanup.
Frontend fetches are mocked; backend tests exercise the real in-process API.
The separate smoke test exercises a real TCP server and its built assets.

## Docker deployment

```sh
docker build -t agenttrace:0.1.0 .
docker run --rm --name agenttrace -p 127.0.0.1:8000:8000 --read-only --tmpfs /tmp agenttrace:0.1.0
```

The multi-stage build installs all dependencies, runs frontend/backend checks and
builds assets; runtime uses non-root UID 10001. No host paths, mounts or secrets
are required. Official pinned Node/Python images supply all needed system libraries;
no additional OS packages are necessary. Deployment is intended for a local trusted
machine. Do not expose this unauthenticated service publicly.

An image can be exported with `docker save -o agenttrace.tar agenttrace:0.1.0`
and loaded offline with `docker load -i agenttrace.tar`. Container runtime requires
no outbound network access. Docker is not installed on the initial Windows build
host; Linux/Docker checks run in GitHub Actions. Inspect the run for your commit;
local Windows checks alone do not establish container success.

## Linux CI and rebuildability audit

`.github/workflows/ci.yml` runs on `ubuntu-latest` for pushes to `main`, pull
requests and manual dispatch. It installs the versions from `.python-version` and
`.nvmrc`, installs Python/npm dependencies from their lockfiles, and executes the
single full test command, production build and real-server smoke test. Test steps
use pip no-index/npm offline mode; tests have no external-service dependency.

The Docker build repeats frontend tests/build and backend tests in BuildKit
`RUN --network=none` layers, after dependency installation. CI also runs the built
image read-only with `--network none` and smoke-tests it from inside the container
over loopback. Dependency installation/image pulls still require network access.
These network-isolated container checks are evidence only once the workflow passes.

Local Docker builds require BuildKit (standard in current Docker). The initial
Windows audit could not execute Docker because it was not installed. See
[docs/rebuildability-audit.md](docs/rebuildability-audit.md) for all eight checks,
local verification, scope and remaining verification items. Do not infer a CI pass
from the presence of the workflow file; inspect the run for the relevant commit.

## API and contract

- `GET /api/health` → `{ "status": "ok", "version": "0.1.0" }`.
- `GET /api/schema` → versioned event JSON Schema, including known-tool constraints.
- `GET /api/samples/benign`, `/risky` or `/forensic` → labeled synthetic JSONL.
- `POST /api/analyze?policy=baseline` (or `strict`): raw UTF-8 JSONL body,
  preferably `Content-Type: application/x-ndjson`.

Successful analysis includes source SHA-256, policy ID/version/configuration,
source-ordered events, integrity warnings, findings and per-call decisions. It also
includes both runs in `comparison`, counts, difference explanations, intervention
categories, `unknown_coverage`, rule metadata, and the effective `engine_config`.
All public analysis fields cross the same backend sanitization boundary. Additional
`sanitization` metadata describes version/count/limitations; `reports` contains
canonical JSON text, Markdown text, format version and the JSON report SHA-256.
Findings preserve event references, rule/version and matched field/offset evidence.
Sensitive IDs use unique namespace aliases consistently across references; evidence
values and configuration may be redacted. Internal detection still uses original data.
Invalid inputs return HTTP 422 with `{ "error": { "code": "...", "line": 2 } }`;
the line is null for whole-file errors. Files above 5 MiB return 413. No partial
analysis is returned. See [schemas/README.md](schemas/README.md) for limits and fields.

### Detection and policy semantics

All rule versions are `1.0`; all six have high severity. R002 retains its original
direct-invocation semantics. The engine adds R001 protected deletion, R003 credential
writes, R004 external sensitive-literal requests, R005 download-to-shell pipelines,
and R006 outside-workspace writes. See [docs/rules-and-replay.md](docs/rules-and-replay.md)
for exact signatures, field evidence, unknown coverage, normalization and limitations.

Both bundled policies are now **version 2.0**. Baseline reviews all rule matches and
unknown actions; strict blocks them. Unmatched, resolved actions default to allow
under limited coverage, not a safety guarantee. Precedence is **block > review >
allow**, independent of rule order; unknown actions always have a minimum of review.
Every recorded call is evaluated independently, including recorded continuation
after a hypothetical block. Custom policy editing is not part of this milestone.

Roots and exact allowed hosts are configurable per API request using an optional
`X-AgentTrace-Config` JSON header (8 KiB maximum), e.g.:

```json
{"protected_roots":{"posix":["/etc","/home","/workspace"],"windows":["C:/Windows","C:/Users","C:/workspace"]},"workspace_roots":{"posix":["/workspace"],"windows":["C:/workspace"]},"allowed_hosts":["localhost","127.0.0.1","::1"]}
```

Omitted fields use documented defaults; the response snapshots effective settings.
The UI uses defaults; configuration editing is API-only. Invalid configuration is
rejected without echoing its contents. Configuration never changes event data.

### Report and redaction semantics

`source_sha256` hashes the **exact original UTF-8 input bytes**, including blank
lines and line endings. `reports.report_sha256` hashes the **exact UTF-8 bytes of
`reports.json`**, including its one final LF; the digest is outside that report
document. Reports have no generation timestamp, are invariant to the selected
baseline/strict UI policy, and include both full policy runs. Canonical JSON sorts
object keys, preserves source array order, uses compact separators and ASCII
escaping. It is not a claim of RFC 8785 interoperability or a digital signature.

See [docs/reports-and-redaction.md](docs/reports-and-redaction.md) for report
contents, escaping, opaque references, fingerprint privacy and heuristic limits.

### Safety and limitations

- Importers never launch commands, fetch recorded URLs, write recorded paths or
  execute trace-provided code. Paths are data and never mapped onto the host.
- Traces live only in request/browser memory. No local storage, database, automatic
  persistence or payload logs. Raw data is used for detection in request memory;
  sanitized copies are returned to the local UI. Explicit report downloads persist
  only the sanitized investigation document at the user's request.
- Payloads render as React text, never HTML. Centralized heuristic redaction covers
  common credential fields, auth/cookie headers, key blocks and synthetic markers.
  **It is not perfect secrecy**: do not import material you cannot safely inspect,
  and review every export before sharing. All checked-in examples are synthetic.
- Timeline and investigation collections paginate at 100 entries. Payload excerpts
  stop at 8,192 code units; evidence excerpts stop at 256 characters with explicit
  truncation labels. Sanitized events remain available in the bounded API response;
  reports contain an event metadata index, not raw payload copies.
  Warnings/findings remain event-linked; timestamps do not reorder events.
- Responsive CSS, labeled controls, focus styles and keyboard navigation are
  included. Automated DOM interaction tests pass; real-browser visual/accessibility
  audits and full browser end-to-end tests remain outstanding.
- Remaining planned work: custom policy/config editors,
  broader real-world trace coverage and full browser/accessibility auditing.
  No authentication, charts, live agents or hosted AI are implemented.

## Layout

`backend/agenttrace/`: typed schema, importer, pure engine, FastAPI routes.
`backend/agenttrace/redaction.py` and `reports.py`: centralized public boundary and exports.
`backend/tests/`: Pytest API/engine/boundary tests.
`frontend/src/`: React workbench, typed API client, Tailwind plus responsive styling.
`frontend/tests/`: Vitest/Testing Library interaction tests.
`samples/`: synthetic benign/risky JSONL; `schemas/`: contract notes.
`scripts/`: portable test runner and live HTTP smoke test.

Implementation and verification are performed through recorded OmniRush sessions.
