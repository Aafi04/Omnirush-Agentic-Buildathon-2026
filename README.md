# AgentTrace

An offline-capable flight recorder for recorded AI-agent tool activity. This first
vertical slice imports JSONL, reconstructs a timeline, detects **direct privileged
execution (R002)**, and classifies recorded calls under two deterministic policies.

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
Import your own UTF-8 `.jsonl` file to inspect its payloads and linked call/results.

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

Tests cover bounded import rejection, strict arguments, IDs and trace consistency,
R002 positive/negative signatures, policy precedence and unknown minimum,
integrity warnings, safe content handling, sample/file UI import, error states,
evidence navigation, policy switching, and displaying hostile HTML as text.
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
host, so container/Linux verification remains a documented verification gap.

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
- `GET /api/samples/benign` or `/risky` → labeled synthetic JSONL.
- `POST /api/analyze?policy=baseline` (or `strict`): raw UTF-8 JSONL body,
  preferably `Content-Type: application/x-ndjson`.

Successful analysis includes source SHA-256, policy ID/version/configuration,
source-ordered events, integrity warnings, findings and per-call decisions.
Findings include actual event IDs, rule/version, matched field and bounded evidence.
Invalid inputs return HTTP 422 with `{ "error": { "code": "...", "line": 2 } }`;
the line is null for whole-file errors. Files above 5 MiB return 413. No partial
analysis is returned. See [schemas/README.md](schemas/README.md) for limits and fields.

### Detection and policy semantics

**R002 v1.0**: for `process.exec` with `shell:false`, normalize only the executable
basename in `arguments.argv[0]` using declared path flavor. Match exactly `sudo`,
`su`, or `doas`. POSIX matching is case-sensitive; Windows matching is case-insensitive.
Evidence is that field, not a claim of successful privilege elevation. Shell content,
aliases, symlinks, executable identity, indirect wrappers, `.exe` variants and
privileges of the actual process are not resolved.

Unknown tools, `shell:true`, and documented interpreter/wrapper basenames
(`sh`, `bash`, `dash`, `zsh`, `cmd`, `cmd.exe`, `powershell`, `powershell.exe`,
`pwsh`, `env`, `python`, `python3`, `node`) have unknown coverage. The wrapper list
is deliberately finite, not exhaustive. Every other supported call still has
**limited coverage**: only R002 is implemented. HTTP and filesystem calls are
validated, but have no risk detectors in this slice.

Matching rule and tool decisions are combined by **block > review > allow**,
independent of entry order. The default is used only when no rule/tool entry matches.
Unknown-action policy is also applied, plus an unconditional minimum of review.
Baseline: R002 review, unknown review, default allow. Strict: R002 block,
unknown block, default allow. `engine/policy.py` contains a typed policy model;
custom policies are not editable via the API/UI yet.

### Safety and limitations

- Importers never launch commands, fetch recorded URLs, write recorded paths or
  execute trace-provided code. Paths are data and never mapped onto the host.
- Traces live only in request/browser memory. No local storage, database, automatic
  persistence or payload logs. Source payloads are returned to the local UI.
- Payloads render as React text, never HTML. **Automatic secret redaction is not
  implemented**: do not import secrets on a shared screen, and do not share API
  responses without checking them. All checked-in examples are synthetic.
- Timeline pagination caps rendered rows at 100 per page. Warnings/findings remain
  event-linked; timestamps do not reorder events.
- Responsive CSS, labeled controls, focus styles and keyboard navigation are
  included. Automated DOM interaction tests pass; real-browser visual/accessibility
  audits and full browser end-to-end tests remain outstanding.
- Remaining planned work: additional five detectors, policy editor/comparison,
  report export/redaction, broader golden fixtures, Linux/container verification.
  No authentication, charts, live agents or hosted AI are implemented.

## Layout

`backend/agenttrace/`: typed schema, importer, pure engine, FastAPI routes.
`backend/tests/`: Pytest API/engine/boundary tests.
`frontend/src/`: React workbench, typed API client, Tailwind plus responsive styling.
`frontend/tests/`: Vitest/Testing Library interaction tests.
`samples/`: synthetic benign/risky JSONL; `schemas/`: contract notes.
`scripts/`: portable test runner and live HTTP smoke test.

Implementation and verification are performed through recorded OmniRush sessions.
