"""
Deterministic stratified train/test split of the evaluation corpus.

Why this exists
---------------
Tier 1's blocklist was originally tuned by reading the attacks it missed on the
*whole* corpus and adding terms derived from those exact samples. Recall measured
afterwards on that same corpus is a memorisation artefact, not a generalisation
estimate.

This script fixes the split once, deterministically, so that:
  * rules may only ever be fitted against the TRAIN half, and
  * the TEST half stays unread during tuning and gives an honest estimate.

Stratified by (label, attack_class) so every attack class and the benign set keep
their proportions in both halves. Seeded — no randomness across runs, and no
dependency on corpus ordering.

Usage:
    python scripts/corpus_split.py                 # write results/corpus_split.json
    python scripts/corpus_split.py --test-frac 0.4
"""

import argparse
import hashlib
import importlib.util
import json
from collections import defaultdict
from pathlib import Path

OUT = Path("results/corpus_split.json")
SEED = 20260721


def load_corpus():
    spec = importlib.util.spec_from_file_location("eh", "eval_harness.py")
    eh = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(eh)
    return eh.CORPUS


def stable_key(prompt: str) -> str:
    """Content-addressed id: stable under corpus reordering or insertion."""
    return hashlib.sha256(prompt.encode("utf-8")).hexdigest()[:16]


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--test-frac", type=float, default=0.4,
                    help="fraction held out (default 0.4)")
    args = ap.parse_args()

    corpus = load_corpus()

    # Group by stratum, then order deterministically *within* the stratum by a
    # seeded hash of the prompt — not by corpus position, so the split does not
    # shift if samples are appended later.
    strata = defaultdict(list)
    for s in corpus:
        strata[(s.label, s.attack_class)].append(s)

    train, test = [], []
    for stratum, samples in sorted(strata.items()):
        ordered = sorted(
            samples,
            key=lambda s: hashlib.sha256(f"{SEED}:{s.prompt}".encode()).hexdigest(),
        )
        n_test = round(len(ordered) * args.test_frac)
        test.extend(ordered[:n_test])
        train.extend(ordered[n_test:])

    payload = {
        "seed": SEED,
        "test_frac": args.test_frac,
        "protocol": (
            "Tier 1 rules may be fitted ONLY against `train`. `test` must not be "
            "inspected during rule authoring. Report generalisation on `test`."
        ),
        "counts": {
            "total": len(corpus),
            "train": len(train),
            "test": len(test),
            "train_attack": sum(1 for s in train if s.label == "attack"),
            "train_benign": sum(1 for s in train if s.label == "benign"),
            "test_attack": sum(1 for s in test if s.label == "attack"),
            "test_benign": sum(1 for s in test if s.label == "benign"),
        },
        "train": [{"id": stable_key(s.prompt), "attack_class": s.attack_class,
                   "label": s.label, "prompt": s.prompt} for s in train],
        "test": [{"id": stable_key(s.prompt), "attack_class": s.attack_class,
                  "label": s.label, "prompt": s.prompt} for s in test],
    }

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")

    c = payload["counts"]
    print(f"wrote {OUT}")
    print(f"  total {c['total']}  ->  train {c['train']} "
          f"({c['train_attack']}a/{c['train_benign']}b)  "
          f"test {c['test']} ({c['test_attack']}a/{c['test_benign']}b)")
    print("\nper-class distribution:")
    print(f"  {'class':<22} {'train':>6} {'test':>6}")
    for (label, cls), samples in sorted(strata.items()):
        tr = sum(1 for s in train if s.attack_class == cls and s.label == label)
        te = sum(1 for s in test if s.attack_class == cls and s.label == label)
        print(f"  {cls:<22} {tr:>6} {te:>6}")


if __name__ == "__main__":
    main()
