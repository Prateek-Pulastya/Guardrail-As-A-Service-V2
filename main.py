"""
GuardRail-as-a-Service — Main FastAPI application
==================================================
Entry point. Mounts the validation router, health endpoint,
Prometheus metrics, and configures structured logging.
"""

import time
import logging
import json
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, FileResponse, RedirectResponse
from prometheus_client import make_asgi_app, Counter, Histogram, Gauge

from pipeline.router import validate_router
from pipeline.tier1_rules import Tier1Engine
from pipeline.tier2_classifier import Tier2Classifier

# ── Logging ────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format='{"time":"%(asctime)s","level":"%(levelname)s","msg":"%(message)s"}',
)
logger = logging.getLogger("guardrail")

# ── Prometheus metrics ─────────────────────────────────────────────────────
REQUEST_COUNT = Counter(
    "guardrail_requests_total",
    "Total validation requests",
    ["tier", "result"],
)
REQUEST_LATENCY = Histogram(
    "guardrail_request_latency_ms",
    "End-to-end latency in milliseconds",
    buckets=[0.1, 0.5, 1, 5, 10, 25, 50, 100, 250, 500, 1000],
)
BLOCK_RATE = Gauge("guardrail_block_rate", "Rolling block rate (last 1000 requests)")

# ── Lifespan: warm up both tiers once at startup ───────────────────────────
@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info("Warming up Tier 1 engine...")
    app.state.tier1 = Tier1Engine()
    logger.info("Warming up Tier 2 classifier...")
    app.state.tier2 = Tier2Classifier()
    logger.info("GuardRail ready.")
    yield
    logger.info("GuardRail shutting down.")


app = FastAPI(
    title="GuardRail-as-a-Service",
    description="Low-latency two-tier prompt injection detection pipeline",
    version="1.0.0",
    lifespan=lifespan,
)

# Mount Prometheus metrics endpoint
metrics_app = make_asgi_app()
app.mount("/metrics", metrics_app)

# Mount validation router
app.include_router(validate_router)


@app.get("/health", tags=["ops"])
async def health():
    return {"status": "ok", "version": "1.0.0"}


# ── Web playground (self-contained, no build step) ─────────────────────────
_UI_FILE = Path(__file__).parent / "static" / "index.html"


@app.get("/ui", include_in_schema=False)
async def playground():
    return FileResponse(_UI_FILE, media_type="text/html")


@app.get("/", include_in_schema=False)
async def root():
    # Serve the playground at the root if it exists, else point at the docs.
    return FileResponse(_UI_FILE) if _UI_FILE.exists() else RedirectResponse("/docs")


@app.middleware("http")
async def metrics_middleware(request: Request, call_next):
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    REQUEST_LATENCY.observe(elapsed_ms)
    return response
