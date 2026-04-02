"""FastAPI HTTP server — local scan endpoint for any agent to call.

Binds to 127.0.0.1 only. All requests must include X-Safeclaw-Secret.
"""

from __future__ import annotations

import secrets
import sys

from fastapi import FastAPI, Header, HTTPException, Request
from fastapi.responses import JSONResponse

from safeclaw.config import SafeclawConfig, load_config
from safeclaw.models import GuardResult, ScanRequest
from safeclaw.pipeline import Pipeline
from safeclaw.redactor import guard


def create_app(
    config: SafeclawConfig | None = None,
    secret: str | None = None,
) -> FastAPI:
    """Build and return the FastAPI application."""
    cfg = config or load_config()
    token = secret or secrets.token_hex(20)
    pipeline = Pipeline()

    app = FastAPI(
        title="Safeclaw",
        version="0.1.0",
        description="Local outbound data guard for AI agents.",
        docs_url=None,    # No public docs endpoint
        redoc_url=None,
    )

    # Store on app state so the CLI can read it back
    app.state.secret = token
    app.state.config = cfg

    @app.middleware("http")
    async def _require_secret(request: Request, call_next):
        if request.url.path == "/health":
            return await call_next(request)
        provided = request.headers.get("x-safeclaw-secret", "")
        if provided != token:
            return JSONResponse(status_code=401, content={"error": "Unauthorized"})
        return await call_next(request)

    @app.get("/health")
    async def health():
        return {"status": "ok", "version": "0.1.0"}

    @app.post("/scan", response_model=GuardResult)
    async def scan_endpoint(body: ScanRequest):
        try:
            return guard(body.text, config=cfg, pipeline=pipeline)
        except Exception as exc:
            if cfg.fail_open:
                print(f"safeclaw: scan error (fail_open=true): {exc}", file=sys.stderr)
                return GuardResult(safe=True, text="", entities=[])
            raise HTTPException(status_code=500, detail="Internal error") from exc

    return app


def run_server(
    port: int = 18791,
    secret: str | None = None,
    config_path: str | None = None,
) -> None:
    """Start the uvicorn server (blocking)."""
    import uvicorn

    cfg = load_config(config_path)
    app = create_app(config=cfg, secret=secret)
    token = app.state.secret

    print(f"safeclaw server listening on http://127.0.0.1:{port}")
    print(f"secret: {token}")
    print("Bound to localhost. Zero external connections.")

    uvicorn.run(app, host="127.0.0.1", port=port, log_level="warning")
