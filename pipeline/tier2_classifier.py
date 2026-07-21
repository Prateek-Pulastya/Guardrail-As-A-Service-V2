"""
GuardRail — Tier 2 ML Classifier
==================================
DeBERTa-v3-base quantized to ONNX INT8 for fast inference.
Only called when Tier 1 passes (fail-open on service errors).

Model: protectai/deberta-v3-base-prompt-injection-v2
  - Binary classification: INJECTION (1) vs SAFE (0)
  - ONNX INT8 quantized: ~45MB, ~20–30ms on CPU

Download the model once:
    python -m pipeline.tier2_classifier --download
"""

import logging
import os
import time
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("guardrail.tier2")

MODEL_DIR = Path(__file__).parent.parent / "models" / "deberta-v3-onnx"
MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"

# Which ONNX graph to load. Measured on the 271-sample corpus at threshold 0.75
# (scripts/bench_tier2_quant.py):
#
#   model.onnx                        739 MB  recall 0.900  F1 0.942  p50 26.5 ms
#   model_quantized_avx2_reduced.onnx 244 MB  recall 0.758  F1 0.860  p50 22.1 ms
#   model_quantized_perchannel.onnx   244 MB  recall 0.732  F1 0.842  p50 21.1 ms
#
# INT8 dynamic quantization costs ~14-17 points of recall for ~5 ms and 495 MB.
# Accuracy wins by default; override with GUARDRAIL_TIER2_MODEL_FILE to trade
# accuracy for footprint.
#
# NOTE: an earlier build shipped a `model_quantized.onnx` produced with
# per_channel=False that had collapsed to predicting SAFE for every input
# (recall 0.005). Always re-run the benchmark after re-quantizing rather than
# assuming a quantized graph is merely "slightly worse".
DEFAULT_MODEL_FILE = "model.onnx"
MODEL_FILE = os.environ.get("GUARDRAIL_TIER2_MODEL_FILE", DEFAULT_MODEL_FILE)


class Tier2Result(NamedTuple):
    blocked: bool
    score: float          # injection probability [0, 1]
    label: str            # "INJECTION" | "SAFE"
    latency_ms: float


class Tier2Classifier:
    """
    Loads DeBERTa-v3 ONNX model at startup.
    Falls back to fail-open (allow) if model unavailable.
    """

    def __init__(self, threshold: float = 0.75, model_dir: Path = MODEL_DIR):
        self.threshold = threshold
        self._pipeline = None
        self._load_model(model_dir)

    def _load_model(self, model_dir: Path) -> None:
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification
            from transformers import AutoTokenizer, pipeline

            if not model_dir.exists():
                logger.warning(
                    f"Model directory {model_dir} not found. "
                    "Run: python -m pipeline.tier2_classifier --download"
                )
                return

            model_file = MODEL_FILE
            if not (model_dir / model_file).exists():
                available = sorted(p.name for p in model_dir.glob("*.onnx"))
                if not available:
                    logger.warning(
                        f"No ONNX graph in {model_dir}. "
                        "Run: python -m pipeline.tier2_classifier --download"
                    )
                    return
                logger.warning(
                    f"Tier 2 graph {model_file!r} not found; falling back to "
                    f"{available[0]!r}. Available: {available}"
                )
                model_file = available[0]

            tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
            model = ORTModelForSequenceClassification.from_pretrained(
                str(model_dir), file_name=model_file
            )
            self._pipeline = pipeline(
                "text-classification",
                model=model,
                tokenizer=tokenizer,
                truncation=True,
                max_length=512,
            )
            logger.info(f"Tier2Classifier loaded (DeBERTa-v3 ONNX, graph={model_file})")

        except ImportError as e:
            logger.warning(f"Tier 2 deps not installed ({e}). Running in Tier1-only mode.")
        except Exception as e:
            logger.error(f"Tier 2 model load failed: {e}. Fail-open active.")

    def validate(self, prompt: str) -> Tier2Result:
        if self._pipeline is None:
            # Fail-open: no model available
            return Tier2Result(
                blocked=False,
                score=0.0,
                label="SAFE",
                latency_ms=0.0,
            )

        t0 = time.perf_counter()
        try:
            result = self._pipeline(prompt)[0]
            elapsed = (time.perf_counter() - t0) * 1000
            label = result["label"]
            score = result["score"]

            # The model may output LABEL_0/LABEL_1; map to semantic labels
            if label in ("LABEL_1", "INJECTION"):
                injection_score = score
            elif label in ("LABEL_0", "SAFE"):
                injection_score = 1.0 - score
            else:
                injection_score = score

            blocked = injection_score >= self.threshold
            return Tier2Result(
                blocked=blocked,
                score=round(injection_score, 4),
                label="INJECTION" if blocked else "SAFE",
                latency_ms=round(elapsed, 2),
            )
        except Exception as e:
            elapsed = (time.perf_counter() - t0) * 1000
            logger.error(f"Tier 2 inference error: {e}. Fail-open.")
            return Tier2Result(blocked=False, score=0.0, label="SAFE", latency_ms=round(elapsed, 2))


# ── CLI: download and quantize model ──────────────────────────────────────
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser()
    parser.add_argument("--download", action="store_true", help="Download + export to ONNX")
    parser.add_argument(
        "--quantize",
        action="store_true",
        help="Additionally emit an INT8 graph. Off by default: dynamic quantization "
             "costs ~14-17 points of recall on this model. Benchmark before using it.",
    )
    parser.add_argument("--threshold", type=float, default=0.75)
    args = parser.parse_args()

    if args.download:
        print(f"Downloading {MODEL_ID} and exporting to ONNX...")
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification
            from transformers import AutoTokenizer

            MODEL_DIR.mkdir(parents=True, exist_ok=True)

            # Export to ONNX (fp32) — this is the graph the service loads by default.
            model = ORTModelForSequenceClassification.from_pretrained(
                MODEL_ID, export=True
            )
            tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
            model.save_pretrained(str(MODEL_DIR))
            tokenizer.save_pretrained(str(MODEL_DIR))

            if args.quantize:
                # per_channel=True matters: the previous per_channel=False config
                # produced a graph that predicted SAFE for every input (recall 0.005).
                # Even done correctly, INT8 costs accuracy here — verify with
                # scripts/bench_tier2_quant.py before deploying a quantized graph.
                from optimum.onnxruntime import ORTQuantizer
                from optimum.onnxruntime.configuration import AutoQuantizationConfig

                print("Quantizing to INT8 (per_channel=True)...")
                quantizer = ORTQuantizer.from_pretrained(MODEL_DIR, file_name="model.onnx")
                qconfig = AutoQuantizationConfig.avx512_vnni(
                    is_static=False, per_channel=True
                )
                quantizer.quantize(save_dir=str(MODEL_DIR), quantization_config=qconfig)
                print("INT8 graph written. Verify accuracy before enabling it:")
                print("  python scripts/bench_tier2_quant.py")

            print(f"Model saved to {MODEL_DIR}")
            print("Run 'docker compose up --build' to start the service.")
        except ImportError:
            print("Missing deps. Run: pip install optimum[onnxruntime] transformers")
