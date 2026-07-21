"""
Verify README claims that are cheap to check mechanically:
  * every file named in the file-structure tree exists
  * every relative markdown link resolves
  * the rule counts quoted in prose match config/rules.yaml

Run before committing documentation changes:
    python scripts/check_docs.py
"""

import re
import sys
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parent.parent
SEARCH_DIRS = ["", "pipeline", "scripts", "config", "tests/unit", "tests/adversarial",
               "docs", "monitoring", ".github/workflows", "results"]


def check_tree(readme: str) -> list[str]:
    m = re.search(r"Guardrail-As-A-Service/\n(.*?)\n```", readme, re.S)
    if not m:
        return ["file-structure tree not found in README"]
    problems = []
    for line in m.group(1).splitlines():
        hit = re.search(r"([\w./-]+\.(?:py|ya?ml|md|gif|toml|txt))", line)
        if not hit:
            continue
        name = hit.group(1)
        if any((ROOT / d / name).exists() for d in SEARCH_DIRS):
            continue
        # Tree entries may be written relative to a parent node (e.g.
        # "unit/test_tier1.py" nested under "tests/"), so fall back to matching
        # any tracked path that ends with the quoted suffix.
        if any(str(p).replace("\\", "/").endswith(name)
               for p in ROOT.rglob("*" + Path(name).name)
               if ".venv" not in str(p) and ".git" not in str(p)):
            continue
        problems.append(f"tree lists missing file: {name}")
    return problems


def check_links(readme: str) -> list[str]:
    problems = []
    for text, target in re.findall(r"\[([^\]]+)\]\(([^)]+)\)", readme):
        if target.startswith(("http://", "https://", "#", "mailto:")):
            continue
        path = target.split("#")[0]
        if path and not (ROOT / path).exists():
            problems.append(f"broken link [{text}] -> {target}")
    return problems


def check_counts(readme: str) -> list[str]:
    cfg = yaml.safe_load((ROOT / "config" / "rules.yaml").read_text(encoding="utf-8"))
    n_terms = len(cfg["blocklist"])
    problems = []
    for quoted in re.findall(r"(\d+)-term blocklist", readme):
        if int(quoted) != n_terms:
            problems.append(
                f"README says '{quoted}-term blocklist', rules.yaml has {n_terms}")
    return problems


def main() -> int:
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    problems = check_tree(readme) + check_links(readme) + check_counts(readme)
    if problems:
        print("Documentation check FAILED:")
        for p in problems:
            print(f"  - {p}")
        return 1
    print("Documentation check passed: tree, links and rule counts all consistent.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
