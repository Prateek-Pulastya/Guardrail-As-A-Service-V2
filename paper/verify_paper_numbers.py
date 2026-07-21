"""
Check every quantitative claim in the paper against the committed artifacts.

A paper that quotes numbers which drift from the results directory is worse than
one with no numbers at all, so this runs mechanically rather than by eye.

    python paper/verify_paper_numbers.py
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
R = ROOT / "results"


def load(name):
    return json.loads((R / name).read_text(encoding="utf-8"))


def main() -> int:
    gen = load("generalization.json")
    ni = load("notinject_results.json")
    opi_user = load("open_prompt_injection_results.json")
    opi_data = load("open_prompt_injection_results_data.json")
    bip = load("bipia_results.json")
    corpus = load("eval_results.json")

    checks = []

    def eq(label, claimed, actual, tol=5e-4):
        ok = abs(float(claimed) - float(actual)) <= tol
        checks.append((ok, label, claimed, actual))

    # Abstract / Table 1 — in-sample and held out
    eq("corpus in-sample recall = 1.000", 1.000, corpus["summary"]["recall"])
    eq("corpus in-sample FPR = 0.000", 0.000, corpus["summary"]["fpr"])
    eq("baseline test recall = 0.7632", 0.7632, gen["tier1"]["baseline"]["test"]["recall"])
    eq("baseline train recall = 0.7895", 0.7895, gen["tier1"]["baseline"]["train"]["recall"])
    eq("train-fitted test recall = 0.7895", 0.7895,
       gen["tier1"]["train_fitted"]["test"]["recall"])
    eq("corpus-fitted test recall = 1.0000", 1.0000,
       gen["tier1"]["corpus_fitted"]["test"]["recall"])
    eq("cascade held-out recall = 1.000", 1.000,
       gen["cascade"]["train_fitted_tier1_plus_tier2"]["test"]["recall"])
    eq("tier2 rescues 16 attacks", 16,
       gen["cascade"]["train_fitted_tier1_plus_tier2"]["test"]["attacks_recovered_by_tier2"])

    # Table 2 — Open-Prompt-Injection
    eq("OPI tier1 overall (user) = 0.40", 0.40, opi_user["results"]["tier1"]["recall"], 0.005)
    eq("OPI tier2 overall = 0.13", 0.13, opi_user["results"]["tier2"]["recall"], 0.005)
    eq("OPI combined (data) = 1.00", 1.00, opi_data["results"]["combined"]["recall"])
    eq("OPI ignore strategy (user) = 1.00", 1.00,
       opi_user["results"]["tier1"]["by_strategy"]["ignore"]["recall"])
    eq("OPI naive strategy (user) = 0.00", 0.00,
       opi_user["results"]["tier1"]["by_strategy"]["naive"]["recall"])
    eq("OPI FPR clean (data) = 0.006", 0.0056,
       opi_data["results"]["combined"]["fpr_on_clean"], 0.001)

    # Table 3 — BIPIA
    eq("BIPIA source=user = 0.035", 0.035, bip["results"]["tier1_source_user"]["recall"])
    eq("BIPIA source=data = 0.480", 0.480, bip["results"]["tier1_source_data"]["recall"])

    # Table 4 — NotInject
    eq("NotInject tier1 blocked = 0", 0, ni["results"]["tier1"]["blocked"])
    eq("NotInject tier2 blocked = 137", 137, ni["results"]["tier2"]["blocked"])
    eq("NotInject tier2 FPR = 0.4041", 0.4041, ni["results"]["tier2"]["fpr"])
    eq("NotInject combined FPR = 0.0000", 0.0000, ni["results"]["combined"]["fpr"])
    eq("NotInject n = 339", 339, ni["n_samples"])

    # Corpus composition
    eq("corpus total = 271", 271, corpus["summary"]["total"])
    eq("corpus attacks = 190", 190, corpus["summary"]["attacks"])
    eq("corpus benign = 81", 81, corpus["summary"]["benign"])
    eq("split train n = 163", 163, gen["counts"]["train"])
    eq("split test n = 108", 108, gen["counts"]["test"])

    failed = [c for c in checks if not c[0]]
    for ok, label, claimed, actual in checks:
        mark = "ok  " if ok else "FAIL"
        print(f"  {mark} {label:<44} claimed={claimed}  actual={actual}")

    print(f"\n{len(checks) - len(failed)}/{len(checks)} paper claims match the artifacts")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
