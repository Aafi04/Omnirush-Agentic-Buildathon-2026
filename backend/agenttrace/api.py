"""Local-only analysis API. No trace payload logging or disk persistence."""
from pathlib import Path
from typing import Literal

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles

from .engine.analysis import analyze
from .engine.policy import POLICIES
from .importer import MAX_BYTES, ImportFailure, ingest
from .schemas import ARGUMENT_SCHEMAS, EVENT_ADAPTER

ROOT = Path(__file__).resolve().parents[2]
app = FastAPI(title="AgentTrace", version="0.1.0")


@app.exception_handler(ImportFailure)
async def import_failure(request: Request, exc: ImportFailure):
    return JSONResponse(status_code=exc.status, content={"error": {"code": exc.code, "line": exc.line}})


@app.middleware("http")
async def security_headers(request: Request, call_next):
    response = await call_next(request)
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Cache-Control"] = "no-store"
    response.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'"
    return response


@app.get("/api/health")
def health():
    return {"status": "ok", "version": "0.1.0"}


@app.get("/api/samples/{name}")
def sample(name: Literal["benign", "risky"]):
    return {"synthetic": True, "name": name, "jsonl": (ROOT / "samples" / f"{name}.jsonl").read_text(encoding="utf-8")}


@app.get("/api/schema")
def schema():
    event_schema = EVENT_ADAPTER.json_schema()
    # Constrain recognized calls while retaining unknown-tool support.
    event_schema["$defs"]["ToolCall"]["allOf"] = [
        {"if": {"properties": {"tool": {"const": tool}}},
         "then": {"properties": {"arguments": model.model_json_schema()}}}
        for tool, model in ARGUMENT_SCHEMAS.items()
    ]
    return {"schema_version": "1.0", "event_schema": event_schema}


@app.post("/api/analyze")
async def analyze_trace(request: Request, policy: Literal["baseline", "strict"] = "baseline"):
    size = 0
    raw = bytearray()
    async for chunk in request.stream():
        size += len(chunk)
        if size > MAX_BYTES:
            raise ImportFailure("input_too_large", status=413)
        raw.extend(chunk)
    return analyze(ingest(bytes(raw)), POLICIES[policy])


DIST = ROOT / "frontend" / "dist"
if DIST.is_dir():
    app.mount("/", StaticFiles(directory=DIST, html=True), name="frontend")
