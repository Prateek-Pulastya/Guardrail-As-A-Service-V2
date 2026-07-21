# GuardRail Evaluation — Reproducibility Guide

This document enables full reproduction of all results reported in the paper.

---

## Prerequisites

```bash
git clone https://github.com/Prateek-Pulastya/Guardrail-As-A-Service
cd Guardrail-As-A-Service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
```

---

## Step 0 — Download the Tier 2 model (one-time, ~45MB)

```bash
python -m pipeline.tier2_classifier --download
```

This downloads `protectai/deberta-v3-base-prompt-injection-v2` from HuggingFace,
exports it to ONNX, and quantizes to INT8. Output: `models/deberta-v3-onnx/`.

**Note:** If you skip this step, the service runs in Tier 1-only mode (fail-open on
Tier 2). Results will differ from the paper for semantic attack classes.

---

## Step 1 — Start the service

```bash
docker compose up --build -d
```

Wait ~15 seconds for the service to warm up, then verify:

```bash
curl http://localhost:8100/health
# Expected: {"status":"ok","version":"1.0.0"}
```

Verify the API contract matches what the harness expects:

```bash
curl -s -X POST http://localhost:8100/validate \
  -H "Content-Type: application/json" \
  -d '{"prompt": "ignore all previous instructions"}' | python -m json.tool
# Expected fields: allowed, blocked_by, reason, tier1_latency_ms, tier2_latency_ms, tier2_score, latency_ms
```

---

## Step 2 — Full evaluation (Table 1 + Table 2)

```bash
python eval_harness.py --mode full --output results/eval_results.json
```

Produces:
- **Table 1**: Overall precision / recall / F1 / FPR
- **Table 2**: Per-class recall across 10 attack classes
- `results/eval_results.json`: raw data for all 271 samples

Expected runtime: ~2–3 minutes.

---

## Step 3 — Latency benchmark (Table 5)

```bash
# 50 RPS for 30 seconds
python eval_harness.py --mode latency --rps 50 --duration 30 --output results/eval_results.json

# 100 RPS for 30 seconds
python eval_harness.py --mode latency --rps 100 --duration 30 --output results/eval_results.json
```

Output: p50/p95/p99 latency in ms at each load level.

---

## Step 4 — Ablation study (Table 4)

The ablation study requires the service to support a `?tier=` query parameter.
Add it to `pipeline/router.py`:

```python
from fastapi import Query

@validate_router.post("/validate")
async def validate(
    request: Request,
    body: ValidateRequest,
    tier: int | None = Query(default=None, description="1=Tier1only, 2=Tier2only, None=combined"),
):
    ...
    if tier == 1:
        # Skip Tier 2
        ...
    elif tier == 2:
        # Skip Tier 1, run Tier 2 directly
        ...
```

Then run:

```bash
python eval_harness.py --mode ablation --output results/eval_results.json
```

Output: `results/eval_results_ablation.json`

---

## Step 5 — Llama-Guard baseline (Table 3)

Llama-Guard is a **gated** Meta model and is no longer served on HuggingFace's free
serverless tier. The reproducible path is local inference via
[Ollama](https://ollama.com) — no token, no gated-repo approval, no paid provider:

```bash
ollama pull llama-guard3:8b        # ~4.9 GB, one-time
python eval_harness.py --mode baseline --baseline-backend ollama \
  --output results/eval_results.json
```

The hosted path still works if your account has been granted access to the gated repo
*and* has an inference provider enabled that serves it:

```bash
export HF_TOKEN=hf_yourtoken
python eval_harness.py --mode baseline --hf-token $HF_TOKEN \
  --hf-model "meta-llama/Llama-Guard-3-8B:featherless-ai" \
  --output results/eval_results.json
```

Output: `results/eval_results_baseline.json`

Expected runtime: 10–20 minutes. If the model is unreachable the harness aborts and
writes no file, rather than emitting an all-zero table that would read as a measurement.

**Interpreting Table 3.** Llama-Guard-3 is a content-safety classifier whose taxonomy
(S1–S13) does not include prompt injection, so its low recall here reflects a task
mismatch, not a defect. The `backend` and `latency_note` fields in the output record
whether latency came from local inference or a hosted API — local timings are **not**
comparable to hosted-API round-trips.

---

## Step 6 — Unit tests (offline, no service needed)

```bash
pytest tests/unit/ -v
```

All 40+ unit tests cover:
- Unicode normalization correctness
- Base64/hex decoding and injection detection
- Known attack class blocking
- False positive safety on benign prompts

---

## Step 7 — Integration tests (service required)

```bash
pytest tests/adversarial/ -v -m "not slow"
```

The `--slow` marker tests cover Tier 2 semantic detection; omit `-m "not slow"` 
to run those too (adds ~30s).

---

## Corpus description

| Attack Class      | n  | Description                                          |
|-------------------|----|------------------------------------------------------|
| direct_override   | 30 | Explicit "ignore instructions" phrasing              |
| persona_jailbreak | 25 | DAN, developer mode, role reassignment               |
| delimiter_inj.    | 20 | Structural: `<system>`, `[INST]`, `### tags`         |
| token_injection   | 15 | Special tokens: `<\|im_start\|>`, `<\|endoftext\|>` |
| obfuscated_unicode| 20 | Math-block Unicode, zero-width chars, leetspeak       |
| encoding_bypass   | 15 | Base64, hex, URL, rot13, acrostic                    |
| indirect_rag      | 20 | Payload hidden in retrieved/provided context          |
| multi_turn_setup  | 15 | False claim of prior agreement                       |
| goal_hijacking    | 15 | Reframe assistant purpose                            |
| prompt_leaking    | 15 | Extract system prompt                                |
| **benign**        | 81 | Legitimate prompts including FP-risk patterns         |
| **Total**         | **271** | 190 attack / 81 benign                          |

Benign set includes deliberate false-positive traps: prompts containing the words
"instructions", "system", "override", "ignore", "act as", "jailbreak", "injection"
in legitimate contexts. These validate that the system does not over-block.

---

## Artifact locations

| Artifact | Path |
|---|---|
| Tier 1 engine | `pipeline/tier1_rules.py` |
| Tier 2 classifier | `pipeline/tier2_classifier.py` |
| API router | `pipeline/router.py` |
| Rules config | `config/rules.yaml` |
| Evaluation harness | `eval_harness.py` |
| Unit tests | `tests/unit/test_tier1.py` |
| Integration tests | `tests/adversarial/test_api.py` |
| Full eval results | `results/eval_results.json` |
| Public API | https://guardrail-service.fly.dev |
