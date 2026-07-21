"""
Download the verified related-work corpus as PDFs from arXiv.

All entries were confirmed to exist via search/fetch before being listed here.
arXiv PDFs are open access; this fetches one file per paper with a polite delay.

Usage:  python scripts/fetch_papers.py
"""

import time
import urllib.error
import urllib.request
from pathlib import Path

OUT = Path(r"E:\Learning\Projects\research papers")

# (arxiv_id, short_slug) — filename becomes "<slug>__arXiv-<id>.pdf"
PAPERS = [
    # ── Foundations / threat model ────────────────────────────────────────
    ("2310.12815", "Liu-2024-Formalizing-Benchmarking-PromptInjection-USENIXSec"),
    ("2312.14197", "Yi-2023-BIPIA-Indirect-PromptInjection-Benchmark"),
    ("2403.02691", "Zhan-2024-InjecAgent-Tool-Integrated-Agents"),

    # ── Closest prior work to the two-tier / fast-first-layer design ──────
    ("2603.11875", "Corll-2026-Mirror-Design-Pattern-Data-Geometry"),
    ("2604.18248", "Munirathinam-2026-Beyond-Pattern-Matching-Seven-Techniques"),

    # ── Evaluation critique / adaptive attacks (most load-bearing) ────────
    ("2510.09023", "Nasr-Carlini-Tramer-2025-Attacker-Moves-Second"),
    ("2504.11168", "Hackett-2025-Bypassing-LLM-Guardrails-Evasion-LLMSec"),
    ("2410.22770", "Li-Liu-2024-InjecGuard-NotInject-Over-defense"),
    ("2505.12368", "CAPTURE-2025-Context-Aware-PromptInjection-Testing"),
    ("2604.08499", "PIArena-2026-Platform-for-PromptInjection-Evaluation"),
    ("2602.00750", "Bypassing-PromptInjection-Detectors-Evasive-Injections"),

    # ── Competing detectors / guardrail models ───────────────────────────
    ("2506.05446", "Sentinel-2025-ModernBERT-PromptInjection-Detector"),
    ("2409.19521", "GenTel-Safe-2024-Benchmark-and-Shielding-Framework"),
    ("2410.21146", "Palisade-2024-PromptInjection-Detection-Framework"),
    ("2510.14005", "PIShield-2025-Intrinsic-LLM-Features"),
    ("2508.20890", "PromptSleuth-2025-Semantic-Intent-Invariance"),
    ("2510.22628", "Sentra-Guard-2025-Realtime-Multilingual-Defense"),

    # ── Efficient / lightweight guardrails (latency positioning) ─────────
    ("2411.17713", "LlamaGuard3-1B-INT4-2024-Compact-Safeguard"),
    ("2411.14398", "Lightweight-Safety-Guardrails-Finetuned-BERT-Embeddings"),
    ("2605.07982", "GLiGuard-2026-Schema-Conditioned-Classification"),
    ("2504.19333", "MultiTaskGuard-2025-Unified-MultiTask-Guardrailing"),

    # ── Agent / RAG-side defenses (scoping + future work) ────────────────
    ("2502.05174", "MELON-2025-Provable-Defense-Indirect-PromptInjection"),
    ("2508.15310", "IPIGuard-2025-Tool-Dependency-Graph-Defense"),
    ("2410.02644", "ASB-2024-Agent-Security-Bench"),
    ("2602.10453", "SoK-2026-Landscape-of-PromptInjection-Threats"),
]

UA = "Mozilla/5.0 (research-paper-fetch; contact via local use)"


def fetch(arxiv_id: str, slug: str) -> tuple[str, str]:
    dest = OUT / f"{slug}__arXiv-{arxiv_id}.pdf"
    if dest.exists() and dest.stat().st_size > 20_000:
        return "skip", f"already present ({dest.stat().st_size/1024:.0f} KB)"

    url = f"https://arxiv.org/pdf/{arxiv_id}"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": UA})
        with urllib.request.urlopen(req, timeout=120) as r:
            data = r.read()
    except urllib.error.HTTPError as e:
        return "fail", f"HTTP {e.code}"
    except Exception as e:
        return "fail", f"{type(e).__name__}: {e}"

    if not data.startswith(b"%PDF"):
        return "fail", "response was not a PDF"

    dest.write_bytes(data)
    return "ok", f"{len(data)/1024:.0f} KB"


def main() -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    counts = {"ok": 0, "skip": 0, "fail": 0}
    failures = []

    for i, (aid, slug) in enumerate(PAPERS, 1):
        status, detail = fetch(aid, slug)
        counts[status] += 1
        if status == "fail":
            failures.append((aid, slug, detail))
        print(f"[{i:>2}/{len(PAPERS)}] {status.upper():<4} {aid:<12} {detail}")
        if status == "ok":
            time.sleep(3)  # be polite to arXiv

    print(f"\ndownloaded={counts['ok']}  skipped={counts['skip']}  failed={counts['fail']}")
    for aid, slug, detail in failures:
        print(f"  FAILED {aid} ({slug}): {detail}")


if __name__ == "__main__":
    main()
