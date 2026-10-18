# Rebuildability audit

Audit date: 2026-10-18. Baseline: `622fc9e` (preserved, not rewritten).
Scope: the working first vertical slice; no application regeneration or new features.

## Eight official checks

| Check | Evidence | Audit result |
| --- | --- | --- |
| Git repository with commits | Existing `main` history starts at `622fc9e`; infrastructure changes follow it | Pass locally; publication is a separate authenticated operation |
| Dependency lockfile | `package-lock.json` and fully pinned `requirements.lock`; installation uses `npm ci` and `pip -r` | Pass; existing Linux optional npm packages present; clean Linux install is checked in CI |
| Runtime version pinned | `.nvmrc`: Node 22.19.0; `.python-version`: Python 3.11.9; Docker uses matching versions | Pass; CI reads the version files |
| Dockerfile builds and runs | Multi-stage build, tests, built UI, non-root runtime, health check; CI builds and smoke-tests it | **Unverified locally**: Docker unavailable; requires successful Linux CI/container run |
| One test command | `python scripts/test.py` in the project venv; Linux `make test` alias | Pass locally: Pytest, Vitest and TypeScript |
| README setup/run/test instructions | Exact local and Docker setup/run/test commands; offline qualification documented | Pass by inspection and equivalent local commands; clean Linux execution delegated to CI |
| Secret-free `.env.example` | Only loopback HOST and PORT; no credentials or dotenv loader | Pass |
| No machine-specific absolute paths | Tracked content reviewed and scanned for developer-home/project paths; paths resolved from file locations | No machine-specific paths found; synthetic filesystem paths in fixtures are intentional data |

## Public repository hygiene

- `git status`, branch, remotes, tracked inventory and original commit were inspected
  before modifications. The tree was clean, on `main`, with no configured remotes.
- The supplied public remote was queried with `git ls-remote`; it advertised no refs.
- No `.env` file (other than the public template), virtualenv, dependency tree,
  local npm cache, logs or credential files are tracked in the baseline.
- Common token/private-key/credential-URL signatures were scanned in tracked
  baseline content; no matches were found. This is a focused review, not a guarantee
  against every possible secret format. No private credential files were inspected.
- Ignore rules already covered `.env`, `.venv`, `node_modules` and `.npm-cache`.
  They now also cover `.env.*` (except `.env.example`) and private-key file suffixes
  in both Git and Docker contexts.
- No global packages, runtime choices or application functionality were changed.

## Infrastructure improvements

- `.github/workflows/ci.yml`: Ubuntu checks with pinned runtime files, locked
  installation, full tests, production build, HTTP smoke, Docker build/runtime smoke.
- `Dockerfile`: BuildKit disables networking in both test/build layers after
  installation; runtime image includes the standard-library-only HTTP smoke script.
- CI container smoke uses a read-only filesystem and no external networking.
- GitHub Actions has read-only repository permissions and does not retain checkout
  credentials in the worktree. No deployment or image publication is configured.

## Local evidence

On Windows with Node 22.19.0 and Python 3.11.9:

- Project-venv Python `scripts/test.py`: **43 backend tests, 7 frontend tests,
  TypeScript passed**.
- `npm run build`: production build passed.
- Project-venv Python `-m pip check`: no broken requirements.
- A freshly started loopback Uvicorn server on port 8001 plus `scripts/smoke.py
  --port 8001`: passed health, HTML/assets, samples, both policies, finding evidence
  and malformed-input rejection. The temporary server was stopped afterward.
- `git diff --check`: passed; ignore checks confirmed local artifacts and `.env.*`
  are excluded, while `.env.example` remains eligible for tracking.
- One upstream Starlette/AnyIO deprecation warning remains; no test failures.

## Unresolved verification

Docker is not installed on this audit host. Docker build, actual Linux dependency
installation and network-isolated container tests must complete in GitHub Actions
or another Linux Docker environment. The workflow's existence is not a test result.
GitHub authentication/publication and CI status must be verified from live receipts;
no successful push or CI run is claimed by this document.
