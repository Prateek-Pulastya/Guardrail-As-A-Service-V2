"""
Produce results/generalization.json — the held-out evaluation backing the
generalisation claims in the README.

Runs every (rules configuration x split) combination for Tier 1, plus the full
cascade on the held-out test split, and writes one JSON artifact so the reported
numbers are generated rather than transcribed.

Requires the service running (for Tier 2). Usage:
    python scripts/generalization_report.py
"""

import json
import sys
import urllib.request
from collections import defaultdict
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from pipeline.tier1_rules import Tier1Engine  # noqa: E402

SPLIT = Path("results/corpus_split.json")
OUT = Path("results/generalization.json")
BASE_URL = "http://localhost:8100"

CONFIGS = {
    "baseline": "config/rules_base.yaml",
    "train_fitted": "config/rules_train_fitted.yaml",
    "corpus_fitted": "config/rules.yaml",
}


def prf(tp, fp, tn, fn):
    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    f1 = 2 * prec * rec / (prec + rec) if (prec + rec) else 0.0
    fpr = fp / (fp + tn) if (fp + tn) else 0.0
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn,
            "precision": round(prec, 4), "recall": round(rec, 4),
            "f1": round(f1, 4), "fpr": round(fpr, 4)}


def tier1_eval(engine, samples):
    tp = fp = tn = fn = 0
    per_class = defaultdict(lambda: [0, 0])
    for s in samples:
        blocked = engine.validate(s["prompt"]).blocked
        if s["label"] == "attack":
            per_class[s["attack_class"]][1] += 1
            if blocked:
                tp += 1
                per_class[s["attack_class"]][0] += 1
            else:
                fn += 1
        else:
            fp += blocked
            tn += not blocked
    m = prf(tp, fp, tn, fn)
    m["per_class_recall"] = {k: round(h / n, 4) for k, (h, n) in per_class.items()}
    return m


def tier2_blocked(prompt):
    data = json.dumps({"prompt": prompt}).encode()
    req = urllib.request.Request(f"{BASE_URL}/validate?tier=2", data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return not json.load(r)["allowed"]


def cascade_eval(engine, samples):
    tp = fp = tn = fn = 0
    recovered = 0  # attacks tier1 missed that tier2 caught
    per_class = defaultdict(lambda: [0, 0])
    for s in samples:
        t1 = engine.validate(s["prompt"]).blocked
        t2 = False if t1 else tier2_blocked(s["prompt"])
        pred = t1 or t2
        if s["label"] == "attack":
            per_class[s["attack_class"]][1] += 1
            if pred:
                tp += 1
                per_class[s["attack_class"]][0] += 1
                if not t1:
                    recovered += 1
            else:
                fn += 1
        else:
            fp += pred
            tn += not pred
    m = prf(tp, fp, tn, fn)
    m["attacks_recovered_by_tier2"] = recovered
    m["per_class_recall"] = {k: round(h / n, 4) for k, (h, n) in per_class.items()}
    return m


def main():
    data = json.loads(SPLIT.read_text(encoding="utf-8"))
    report = {
        "protocol": (
            "Stratified split seeded at "
            f"{data['seed']}, test_frac={data['test_frac']}. Tier 1 rules in the "
            "'train_fitted' configuration were authored using only train-split "
            "misses; the test split was not inspected during authoring. The "
            "'corpus_fitted' configuration was tuned on the whole corpus and its "
            "test column is therefore NOT a generalisation estimate — it is "
            "reported only to quantify the optimism from that contamination."
        ),
        "counts": data["counts"],
        "tier1": {},
        "cascade": {},
    }

    for name, path in CONFIGS.items():
        engine = Tier1Engine(config_path=Path(path))
        report["tier1"][name] = {
            "rules_file": path,
            "train": tier1_eval(engine, data["train"]),
            "test": tier1_eval(engine, data["test"]),
        }
        print(f"tier1/{name:<14} train recall "
              f"{report['tier1'][name]['train']['recall']:.4f}   "
              f"test recall {report['tier1'][name]['test']['recall']:.4f}")

    engine = Tier1Engine(config_path=Path(CONFIGS["train_fitted"]))
    report["cascade"]["train_fitted_tier1_plus_tier2"] = {
        "test": cascade_eval(engine, data["test"])
    }
    c = report["cascade"]["train_fitted_tier1_plus_tier2"]["test"]
    print(f"cascade (train-fitted T1 + T2) test recall {c['recall']:.4f}  "
          f"FPR {c['fpr']:.4f}  recovered_by_tier2={c['attacks_recovered_by_tier2']}")

    OUT.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nwrote {OUT}")


if __name__ == "__main__":
    main()
