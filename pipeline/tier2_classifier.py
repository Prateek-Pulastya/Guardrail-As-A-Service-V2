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
import time
from pathlib import Path
from typing import NamedTuple

logger = logging.getLogger("guardrail.tier2")

MODEL_DIR = Path(__file__).parent.parent / "models" / "deberta-v3-onnx"
MODEL_ID = "protectai/deberta-v3-base-prompt-injection-v2"


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

            tokenizer = AutoTokenizer.from_pretrained(str(model_dir))
            model = ORTModelForSequenceClassification.from_pretrained(
                str(model_dir), file_name="model_quantized.onnx"
            )
            self._pipeline = pipeline(
                "text-classification",
                model=model,
                tokenizer=tokenizer,
                truncation=True,
                max_length=512,
            )
            logger.info("Tier2Classifier loaded (DeBERTa-v3 ONNX INT8)")

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
    parser.add_argument("--download", action="store_true", help="Download and quantize model")
    parser.add_argument("--threshold", type=float, default=0.75)
    args = parser.parse_args()

    if args.download:
        print(f"Downloading {MODEL_ID} and converting to ONNX INT8...")
        try:
            from optimum.onnxruntime import ORTModelForSequenceClassification
            from transformers import AutoTokenizer
            from optimum.onnxruntime.configuration import AutoQuantizationConfig
            from optimum.onnxruntime import ORTQuantizer

            MODEL_DIR.mkdir(parents=True, exist_ok=True)

            # Export to ONNX
            model = ORTModelForSequenceClassification.from_pretrained(
                MODEL_ID, export=True
            )
            tokenizer = AutoTokenizer.from_pretrained(MODEL_ID)
            model.save_pretrained(str(MODEL_DIR))
            tokenizer.save_pretrained(str(MODEL_DIR))

            # Quantize to INT8
            quantizer = ORTQuantizer.from_pretrained(MODEL_DIR)
            qconfig = AutoQuantizationConfig.avx512_vnni(is_static=False, per_channel=False)
            quantizer.quantize(
                save_dir=str(MODEL_DIR),
                quantization_config=qconfig,
            )
            print(f"Model saved to {MODEL_DIR}")
            print("Run 'docker compose up --build' to start the service.")
        except ImportError:
            print("Missing deps. Run: pip install optimum[onnxruntime] transformers")
