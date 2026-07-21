"""
GuardRail — Validation Router
==============================
POST /validate  →  ValidateResponse

Response contract (what eval_harness.py expects):
{
  "allowed":     bool,
  "blocked_by":  "tier1" | "tier2" | null,
  "reason":      str | null,
  "tier1_latency_ms": float,
  "tier2_latency_ms": float | null,
  "tier2_score": float | null,
  "latency_ms":  float          ← total end-to-end
}
"""

import time
import logging
from fastapi import APIRouter, Request, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("guardrail.router")

validate_router = APIRouter()


class ValidateRequest(BaseModel):
    prompt: str = Field(..., min_length=1, max_length=32_000)


class ValidateResponse(BaseModel):
    allowed: bool
    blocked_by: str | None          # "tier1" | "tier2" | None
    reason: str | None
    tier1_latency_ms: float
    tier2_latency_ms: float | None
    tier2_score: float | None
    latency_ms: float               # total


@validate_router.post(
    "/validate",
    response_model=ValidateResponse,
    tags=["validation"],
    summary="Validate a prompt for injection attacks",
)
async def validate(
    request: Request,
    body: ValidateRequest,
    tier: int | None = Query(
        default=None,
        description="1=Tier 1 only, 2=Tier 2 only, omitted=combined cascade",
    ),
):
    t_total = time.perf_counter()

    tier1 = request.app.state.tier1
    tier2 = request.app.state.tier2

    # ── Ablation: Tier 1 only ─────────────────────────────────────────────
    if tier == 1:
        t1_result = tier1.validate(body.prompt)
        total_ms = (time.perf_counter() - t_total) * 1000
        return ValidateResponse(
            allowed=not t1_result.blocked,
            blocked_by="tier1" if t1_result.blocked else None,
            reason=t1_result.reason,
            tier1_latency_ms=t1_result.latency_ms,
            tier2_latency_ms=None,
            tier2_score=None,
            latency_ms=round(total_ms, 2),
        )

    # ── Ablation: Tier 2 only ─────────────────────────────────────────────
    if tier == 2:
        t2_result = tier2.validate(body.prompt)
        total_ms = (time.perf_counter() - t_total) * 1000
        return ValidateResponse(
            allowed=not t2_result.blocked,
            blocked_by="tier2" if t2_result.blocked else None,
            reason=f"injection_score={t2_result.score}" if t2_result.blocked else None,
            tier1_latency_ms=0.0,
            tier2_latency_ms=t2_result.latency_ms,
            tier2_score=t2_result.score,
            latency_ms=round(total_ms, 2),
        )

    # ── Tier 1: fast blocklist + regex ────────────────────────────────────
    t1_result = tier1.validate(body.prompt)

    if t1_result.blocked:
        total_ms = (time.perf_counter() - t_total) * 1000
        logger.info(
            f"BLOCKED tier1 | reason={t1_result.reason!r} | "
            f"latency={t1_result.latency_ms:.3f}ms"
        )
        return ValidateResponse(
            allowed=False,
            blocked_by="tier1",
            reason=t1_result.reason,
            tier1_latency_ms=t1_result.latency_ms,
            tier2_latency_ms=None,
            tier2_score=None,
            latency_ms=round(total_ms, 2),
        )

    # ── Tier 2: DeBERTa-v3 semantic classifier ────────────────────────────
    t2_result = tier2.validate(body.prompt)

    total_ms = (time.perf_counter() - t_total) * 1000

    if t2_result.blocked:
        logger.info(
            f"BLOCKED tier2 | score={t2_result.score} | "
            f"latency={t2_result.latency_ms:.1f}ms"
        )
    else:
        logger.debug(
            f"ALLOWED | t1={t1_result.latency_ms:.3f}ms "
            f"t2={t2_result.latency_ms:.1f}ms"
        )

    return ValidateResponse(
        allowed=not t2_result.blocked,
        blocked_by="tier2" if t2_result.blocked else None,
        reason=f"injection_score={t2_result.score}" if t2_result.blocked else None,
        tier1_latency_ms=t1_result.latency_ms,
        tier2_latency_ms=t2_result.latency_ms,
        tier2_score=t2_result.score,
        latency_ms=round(total_ms, 2),
    )
