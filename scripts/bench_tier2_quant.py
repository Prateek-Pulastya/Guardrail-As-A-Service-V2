"""
Benchmark Tier 2 ONNX variants for accuracy and latency.

Motivation: the shipped INT8 graph (`model_quantized.onnx`, dynamic quantization
with per_channel=False) collapses to predicting SAFE for every input, which made
the Table 4 ablation report ~0.005 recall for Tier 2. This script scores each
available ONNX graph over the evaluation corpus so the choice of graph is made on
measured accuracy rather than assumption.

Usage:
    python scripts/bench_tier2_quant.py                 # benchmark existing graphs
    python scripts/bench_tier2_quant.py --requantize    # also build new variants first
"""

import argparse
import importlib.util
import time
from pathlib import Path

import numpy as np

MD = Path("models/deberta-v3-onnx")
THRESHOLD = 0.75


def load_corpus():
    spec = importlib.util.spec_from_file_location("eh", "eval_harness.py")
    eh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(eh)
    return [(s.prompt, s.label) for s in eh.CORPUS]


def requantize():
    """Build additional INT8 variants with settings that better suit DeBERTa-v3."""
    from optimum.onnxruntime import ORTQuantizer
    from optimum.onnxruntime.configuration import AutoQuantizationConfig

    variants = {
        # per_channel=True keeps a separate scale per output channel, which is the
        # standard remedy when a layer's weight range is too wide for one scale.
        "model_quantized_perchannel.onnx": AutoQuantizationConfig.avx512_vnni(
            is_static=False, per_channel=True
        ),
        # avx2 + per_channel + reduced range (7-bit) is the most conservative
        # dynamic setting available here.
        "model_quantized_avx2_reduced.onnx": AutoQuantizationConfig.avx2(
            is_static=False, per_channel=True, reduce_range=True
        ),
    }

    for fname, qconfig in variants.items():
        if (MD / fname).exists():
            print(f"  {fname} already exists, skipping")
            continue
        print(f"  building {fname} ...")
        try:
            quantizer = ORTQuantizer.from_pretrained(MD, file_name="model.onnx")
            quantizer.quantize(save_dir=str(MD), quantization_config=qconfig)
            produced = MD / "model_quantized.onnx"
            if produced.exists():
                target = MD / fname
                if target.exists():
                    target.unlink()
                produced.rename(target)
                print(f"    -> {fname} ({target.stat().st_size/1e6:.0f} MB)")
        except Exception as e:
            print(f"    FAILED: {type(e).__name__}: {e}")


def evaluate(file_name, corpus):
    from optimum.onnxruntime import ORTModelForSequenceClassification
    from transformers import AutoTokenizer, pipeline

    tok = AutoTokenizer.from_pretrained(str(MD))
    model = ORTModelForSequenceClassification.from_pretrained(str(MD), file_name=file_name)
    pipe = pipeline("text-classification", model=model, tokenizer=tok,
                    truncation=True, max_length=512)

    pipe("warmup")  # exclude first-call graph init from timings

    tp = fp = tn = fn = 0
    lat = []
    for prompt, label in corpus:
        t0 = time.perf_counter()
        r = pipe(prompt)[0]
        lat.append((time.perf_counter() - t0) * 1000)

        lbl = r["label"]
        score = r["score"]
        if lbl in ("LABEL_1", "INJECTION"):
            inj = score
        elif lbl in ("LABEL_0", "SAFE"):
            inj = 1.0 - score
        else:
            inj = score

        pred_attack = inj >= THRESHOLD
        if label == "attack":
            tp += pred_attack
            fn += not pred_attack
        else:
            fp += pred_attack
            tn += not pred_attack

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "file": file_name,
        "size_mb": (MD / file_name).stat().st_size / 1e6,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4),
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "p50_ms": round(float(np.percentile(lat, 50)), 2),
        "p95_ms": round(float(np.percentile(lat, 95)), 2),
    }


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--requantize", action="store_true")
    args = ap.parse_args()

    if args.requantize:
        print("Building quantization variants:")
        requantize()

    corpus = load_corpus()
    print(f"\nCorpus: {len(corpus)} samples "
          f"({sum(1 for _, l in corpus if l == 'attack')} attack / "
          f"{sum(1 for _, l in corpus if l == 'benign')} benign), threshold={THRESHOLD}\n")

    candidates = [f.name for f in sorted(MD.glob("*.onnx"))]
    rows = []
    for f in candidates:
        print(f"evaluating {f} ...")
        try:
            rows.append(evaluate(f, corpus))
        except Exception as e:
            print(f"  FAILED: {type(e).__name__}: {e}")

    hdr = f"\n{'graph':<38} {'MB':>6} {'prec':>7} {'recall':>7} {'F1':>7} {'FPR':>7} {'p50ms':>7} {'p95ms':>7}"
    print(hdr)
    print("-" * len(hdr))
    for r in rows:
        print(f"{r['file']:<38} {r['size_mb']:>6.0f} {r['precision']:>7.4f} "
              f"{r['recall']:>7.4f} {r['f1']:>7.4f} {r['fpr']:>7.4f} "
              f"{r['p50_ms']:>7.1f} {r['p95_ms']:>7.1f}")


if __name__ == "__main__":
    main()
