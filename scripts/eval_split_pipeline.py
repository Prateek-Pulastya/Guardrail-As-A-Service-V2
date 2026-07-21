"""
Evaluate the FULL cascade (Tier 1 + Tier 2) against the held-out test split.

Tier 1 runs locally from a chosen rules file; Tier 2 is queried from the running
service via POST /validate?tier=2 (the Tier 2 model is pretrained and was never
fitted to this corpus, so it needs no split discipline).

Usage:
    python scripts/eval_split_pipeline.py --rules config/rules_train_fitted.yaml --split test
"""

import argparse
import json
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.tier1_rules import Tier1Engine  # noqa: E402

SPLIT_FILE = Path("results/corpus_split.json")
BASE_URL = "http://localhost:8100"


def tier2_blocked(prompt: str) -> bool:
    data = json.dumps({"prompt": prompt}).encode()
    req = urllib.request.Request(
        f"{BASE_URL}/validate?tier=2", data=data,
        headers={"Content-Type": "application/json"},
    )
    with urllib.request.urlopen(req, timeout=120) as r:
        return not json.load(r)["allowed"]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="config/rules_train_fitted.yaml")
    ap.add_argument("--split", choices=["train", "test"], default="test")
    args = ap.parse_args()

    data = json.loads(SPLIT_FILE.read_text(encoding="utf-8"))
    samples = data[args.split]
    engine = Tier1Engine(config_path=Path(args.rules))

    rows = []
    for s in samples:
        by_t1 = engine.validate(s["prompt"]).blocked
        by_t2 = False if by_t1 else tier2_blocked(s["prompt"])
        rows.append((s, by_t1, by_t2, by_t1 or by_t2))

    def metrics(pred_fn, label_note):
        tp = fp = tn = fn = 0
        per_class = defaultdict(lambda: [0, 0])
        for s, t1, t2, comb in rows:
            pred = pred_fn(t1, t2, comb)
            if s["label"] == "attack":
                per_class[s["attack_class"]][1] += 1
                if pred:
                    tp += 1
                    per_class[s["attack_class"]][0] += 1
                else:
                    fn += 1
            else:
                fp += pred
                tn += not pred
        prec = tp / (tp + fp) if (tp + fp) else 0.0
        rec = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        print(f"  {label_note:<14} precision {prec:.4f}  recall {rec:.4f}  "
              f"F1 {f1:.4f}  FPR {fpr:.4f}   (TP {tp} FP {fp} TN {tn} FN {fn})")
        return per_class

    print(f"rules: {args.rules}   split: {args.split} (n={len(samples)})\n")
    metrics(lambda t1, t2, c: t1, "tier1 only")
    metrics(lambda t1, t2, c: t2, "tier2 only*")
    per_class = metrics(lambda t1, t2, c: c, "combined")
    print("\n  * tier2-only here = tier2's verdict on the prompts tier1 passed,\n"
          "    not a standalone tier2 run over the whole split.")

    print("\n  combined per-class recall on this split:")
    for cls, (hit, n) in sorted(per_class.items()):
        flag = "" if hit == n else "   <-- gap"
        print(f"    {cls:<22} {hit}/{n}  ({hit/n:.0%}){flag}")


if __name__ == "__main__":
    main()
