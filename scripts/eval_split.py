"""
Evaluate Tier 1 against a fixed train/test split, offline (no service needed).

Contamination guard
-------------------
`--show-misses` is only honoured for the TRAIN split. Test-set misses are never
printed, because reading them is exactly how a held-out set stops being held out:
the tuner would add terms derived from test samples and the resulting number would
no longer estimate generalisation. Test reporting is aggregate-only.

Usage:
    python scripts/eval_split.py --rules config/rules_base.yaml --split train --show-misses
    python scripts/eval_split.py --rules config/rules.yaml      --split test
    python scripts/eval_split.py --rules config/rules.yaml      --split both
"""

import argparse
import json
import sys
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.tier1_rules import Tier1Engine  # noqa: E402

SPLIT_FILE = Path("results/corpus_split.json")


def score(engine, samples):
    tp = fp = tn = fn = 0
    misses, fps = [], []
    per_class = defaultdict(lambda: {"n": 0, "hit": 0})

    for s in samples:
        blocked = engine.validate(s["prompt"]).blocked
        if s["label"] == "attack":
            per_class[s["attack_class"]]["n"] += 1
            if blocked:
                tp += 1
                per_class[s["attack_class"]]["hit"] += 1
            else:
                fn += 1
                misses.append(s)
        else:
            if blocked:
                fp += 1
                fps.append(s)
            else:
                tn += 1

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {
        "tp": tp, "fp": fp, "tn": tn, "fn": fn,
        "precision": round(prec, 4), "recall": round(rec, 4),
        "f1": round(f1, 4), "fpr": round(fpr, 4),
        "per_class": {k: dict(v) for k, v in per_class.items()},
    }, misses, fps


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="config/rules.yaml")
    ap.add_argument("--split", choices=["train", "test", "both"], default="both")
    ap.add_argument("--show-misses", action="store_true",
                    help="print missed attacks — TRAIN only, ignored for test")
    args = ap.parse_args()

    data = json.loads(SPLIT_FILE.read_text(encoding="utf-8"))
    engine = Tier1Engine(config_path=Path(args.rules))
    print(f"rules: {args.rules}\n")

    halves = ["train", "test"] if args.split == "both" else [args.split]
    for half in halves:
        m, misses, fps = score(engine, data[half])
        n = len(data[half])
        print(f"── {half.upper()}  (n={n}) " + "─" * 30)
        print(f"  precision {m['precision']:.4f}   recall {m['recall']:.4f}   "
              f"F1 {m['f1']:.4f}   FPR {m['fpr']:.4f}")
        print(f"  TP {m['tp']}  FP {m['fp']}  TN {m['tn']}  FN {m['fn']}")

        weak = {k: v for k, v in m["per_class"].items() if v["hit"] < v["n"]}
        if weak:
            print("  classes below 100% recall:")
            for k, v in sorted(weak.items()):
                print(f"    {k:<22} {v['hit']}/{v['n']}  ({v['hit']/v['n']:.0%})")

        if args.show_misses and half == "train":
            print(f"\n  TRAIN misses ({len(misses)}) — permitted input for rule authoring:")
            for s in misses:
                print(f"    [{s['attack_class']}] {s['prompt'][:96]!r}")
            if fps:
                print(f"\n  TRAIN false positives ({len(fps)}):")
                for s in fps:
                    print(f"    {s['prompt'][:96]!r}")
        elif args.show_misses and half == "test":
            print("\n  [test misses withheld by design — inspecting them would "
                  "contaminate the held-out set]")
        print()


if __name__ == "__main__":
    main()
