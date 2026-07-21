"""
Pre-flight checks for the AISec LaTeX submission.

No local TeX distribution, so this catches the errors that are checkable without
compiling: undefined citations, dangling refs, unbalanced braces/environments,
and, most importantly, anonymity leaks in a double-blind build.

    python paper/latex/check_tex.py
"""

import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
TEX = (HERE / "main.tex").read_text(encoding="utf-8")
BIB = (HERE / "refs.bib").read_text(encoding="utf-8")

# Strings that must not appear in a double-blind submission.
IDENTIFYING = [
    "Prateek", "Pulastya", "prateekpulastya", "@gmail",
    "github.com/Prateek", "Guardrail-As-A-Service",
]

problems = []

# 1. citations resolve
bib_keys = set(re.findall(r"@\w+\{([^,]+),", BIB))
cited = set()
for group in re.findall(r"\\cite\{([^}]+)\}", TEX):
    cited.update(k.strip() for k in group.split(","))
for key in sorted(cited - bib_keys):
    problems.append(f"\\cite{{{key}}} has no entry in refs.bib")
for key in sorted(bib_keys - cited):
    problems.append(f"refs.bib entry '{key}' is never cited (will not appear)")

# 2. labels and refs
labels = set(re.findall(r"\\label\{([^}]+)\}", TEX))
refs = set(re.findall(r"\\ref\{([^}]+)\}", TEX))
for key in sorted(refs - labels):
    problems.append(f"\\ref{{{key}}} has no matching \\label")

# 3. brace balance
depth, line_no = 0, 0
for i, line in enumerate(TEX.splitlines(), 1):
    stripped = re.sub(r"(?<!\\)%.*$", "", line)
    depth += stripped.count("{") - stripped.count("}")
    if depth < 0 and not line_no:
        line_no = i
if depth != 0:
    problems.append(f"unbalanced braces: net {depth:+d}"
                    + (f", first negative at line {line_no}" if line_no else ""))

# 4. environments open/close
begins = re.findall(r"\\begin\{(\w+\*?)\}", TEX)
ends = re.findall(r"\\end\{(\w+\*?)\}", TEX)
for env in set(begins) | set(ends):
    if begins.count(env) != ends.count(env):
        problems.append(f"environment '{env}': {begins.count(env)} begin, "
                        f"{ends.count(env)} end")

# 5. anonymity
for token in IDENTIFYING:
    if token.lower() in TEX.lower():
        problems.append(f"ANONYMITY LEAK: '{token}' appears in main.tex")

# 6. the review build must actually be anonymous
if "anonymous" not in TEX.split("\n")[TEX.split("\n").index(
        next(l for l in TEX.split("\n") if "documentclass" in l))]:
    problems.append("documentclass is missing the 'anonymous' option")

# 7. table column counts match their headers
for env in re.findall(r"\\begin\{tabular\}\{([^}]*)\}(.*?)\\end\{tabular\}",
                      TEX, re.S):
    spec, body = env
    ncol = len(re.findall(r"[lcr]", spec))
    for row in body.split(r"\\"):
        row = re.sub(r"\\(toprule|midrule|bottomrule|footnotesize|small)", "", row)
        if not row.strip() or "multicolumn" in row:
            continue
        cells = row.count("&") + 1
        if cells != ncol:
            problems.append(f"table row has {cells} cells, spec declares {ncol}: "
                            f"{row.strip()[:60]!r}")

print(f"cited keys: {len(cited)}   bib entries: {len(bib_keys)}   "
      f"labels: {len(labels)}   tables: {begins.count('tabular')}")
if problems:
    print("\nFAILED:")
    for p in problems:
        print(f"  - {p}")
    sys.exit(1)
print("\nPre-flight OK: citations resolve, refs match, braces balanced, "
      "environments paired, no anonymity leaks.")
