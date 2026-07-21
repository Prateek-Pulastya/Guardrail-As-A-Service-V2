"""
Evaluate GuardRail on NotInject — an external over-defense benchmark.

NotInject (Li & Liu, 2024, arXiv:2410.22770; published as PIGuard, ACL 2025) is
339 samples that are ALL benign but deliberately seeded with trigger words common
in prompt injection attacks. Every block is therefore a false positive. The three
splits carry one, two, and three trigger words respectively, so FPR by split shows
how detection degrades as trigger density rises.

This is the sharpest external test available for GuardRail: Tier 1 is a 197-term
keyword blocklist, which is precisely the design NotInject was built to punish.

Data is fetched from the HuggingFace datasets-server (public, no token) and cached
under data/. Requires the service running.

Usage:
    python scripts/eval_notinject.py
    python scripts/eval_notinject.py --base-url http://localhost:8100
"""

import argparse
import json
import sys
import urllib.parse
import urllib.request
from collections import defaultdict
from pathlib import Path

CACHE = Path("data/notinject.json")
OUT = Path("results/notinject_results.json")
SPLITS = ["NotInject_one", "NotInject_two", "NotInject_three"]
DS = "leolee99/NotInject"


def fetch_dataset() -> list[dict]:
    if CACHE.exists():
        return json.loads(CACHE.read_text(encoding="utf-8"))

    rows = []
    for split in SPLITS:
        offset = 0
        while True:
            url = (
                "https://datasets-server.huggingface.co/rows"
                f"?dataset={urllib.parse.quote(DS, safe='')}"
                f"&config=default&split={split}&offset={offset}&length=100"
            )
            with urllib.request.urlopen(url, timeout=120) as r:
                payload = json.load(r)
            for item in payload["rows"]:
                row = item["row"]
                rows.append({
                    "split": split,
                    "prompt": row["prompt"],
                    "word_list": row.get("word_list", []),
                    "category": row.get("category", "unknown"),
                })
            offset += len(payload["rows"])
            if offset >= payload.get("num_rows_total", 0) or not payload["rows"]:
                break
        print(f"  fetched {split}")

    CACHE.parent.mkdir(parents=True, exist_ok=True)
    CACHE.write_text(json.dumps(rows, indent=2, ensure_ascii=False), encoding="utf-8")
    return rows


def validate(base_url: str, prompt: str, tier: int | None):
    url = f"{base_url}/validate" + (f"?tier={tier}" if tier else "")
    data = json.dumps({"prompt": prompt}).encode("utf-8")
    req = urllib.request.Request(url, data=data,
                                 headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=120) as r:
        return json.load(r)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--base-url", default="http://localhost:8100")
    args = ap.parse_args()

    print(f"Loading NotInject ({DS})...")
    rows = fetch_dataset()
    print(f"  {len(rows)} samples (all benign by construction)\n")

    modes = {"tier1": 1, "tier2": 2, "combined": None}
    blocked = {m: [] for m in modes}

    for i, row in enumerate(rows, 1):
        if i % 50 == 0:
            print(f"  [{i}/{len(rows)}]")
        for mode, tier in modes.items():
            try:
                resp = validate(args.base_url, row["prompt"], tier)
            except Exception as e:
                print(f"  request failed on sample {i} ({mode}): {e}", file=sys.stderr)
                continue
            if not resp["allowed"]:
                blocked[mode].append({
                    "prompt": row["prompt"],
                    "split": row["split"],
                    "category": row["category"],
                    "word_list": row["word_list"],
                    "blocked_by": resp["blocked_by"],
                    "reason": resp.get("reason"),
                })

    n = len(rows)
    report = {
        "dataset": DS,
        "citation": "Li & Liu (2024), InjecGuard/NotInject, arXiv:2410.22770 "
                    "(published as PIGuard, ACL 2025)",
        "n_samples": n,
        "note": "All NotInject samples are benign. Every block is a false positive; "
                "FPR here measures over-defense, not detection.",
        "results": {},
    }

    print("\n" + "=" * 62)
    print("NotInject — over-defense (all 339 samples are benign)")
    print("=" * 62)
    print(f"{'mode':<12} {'blocked':>8} {'FPR':>9}   {'accuracy':>9}")
    print("-" * 62)
    for mode in modes:
        b = len(blocked[mode])
        report["results"][mode] = {
            "blocked": b,
            "fpr": round(b / n, 4),
            "accuracy": round((n - b) / n, 4),
            "by_split": dict(sorted(
                defaultdict(int, {
                    s: sum(1 for x in blocked[mode] if x["split"] == s)
                    for s in SPLITS
                }).items())),
            "by_category": dict(sorted(
                {c: sum(1 for x in blocked[mode] if x["category"] == c)
                 for c in {x["category"] for x in blocked[mode]}}.items())),
            "false_positives": blocked[mode],
        }
        r = report["results"][mode]
        print(f"{mode:<12} {b:>8} {r['fpr']:>9.4f}   {r['accuracy']:>9.4f}")

    print("\nfalse positives by trigger-word count:")
    print(f"  {'split':<20} {'n':>5} {'tier1':>7} {'tier2':>7} {'combined':>9}")
    for s in SPLITS:
        tot = sum(1 for r in rows if r["split"] == s)
        print(f"  {s:<20} {tot:>5} "
              f"{report['results']['tier1']['by_split'].get(s, 0):>7} "
              f"{report['results']['tier2']['by_split'].get(s, 0):>7} "
              f"{report['results']['combined']['by_split'].get(s, 0):>9}")

    fps = report["results"]["combined"]["false_positives"]
    if fps:
        print(f"\nsample false positives (combined), showing up to 15 of {len(fps)}:")
        for x in fps[:15]:
            print(f"  [{x['blocked_by']}] triggers={x['word_list']} "
                  f"{x['prompt'][:70]!r}")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    OUT.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
    print(f"\nSaved -> {OUT}")


if __name__ == "__main__":
    main()
