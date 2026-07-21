# References — and what each one changed here

Every paper below was retrieved and read before being cited; none are recalled from
memory. Papers are grouped by how much they actually affected the project, because
"related work" and "work that changed the code" are different claims and conflating
them is a way of overstating rigour.

The PDFs are not in this repository (they are third-party copyrighted material).
[`scripts/fetch_papers.py`](scripts/fetch_papers.py) downloads all 25 from arXiv into
a local folder.

---

## 1. Papers that changed the design or the numbers

These produced specific, traceable commits. Each row names the resulting change.

### Nasr, Carlini, Sitawarin, Schulhoff, Hayes, Ilie, Pluto, Song, Chaudhari, Shumailov, Thakurta, Xiao, Terzis, Tramèr (2025)
**The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections.** arXiv:2510.09023

> Evaluates 12 published defenses under adaptive attack; success rates exceed 90%.
> "The majority of defenses originally reported near-zero attack success rates."

**What it changed.** This is why the held-out split exists. GuardRail was reporting
1.000 recall on a corpus its blocklist had been tuned against by reading that corpus's
own missed attacks — precisely the pattern this paper says the field keeps mistaking
for robustness. Commit `5d787f7` added a seeded, stratified 60/40 split, reconstructed
the pre-tuning ruleset, and refit using train-split misses only. Held-out recall came
out at **0.7895** against the claimed 1.000 — a 21-point overstatement.

*Not yet addressed:* this paper's central demand is evaluation against an **adaptive**
attacker who optimises against the deployed defense. Nothing here does that. Every
number in this repo is against static corpora, so all of them should be read as upper
bounds.

### Li & Liu (2024)
**InjecGuard: Benchmarking and Mitigating Over-defense in Prompt Injection Guardrail Models.** arXiv:2410.22770 · dataset: `leolee99/NotInject` · published as **PIGuard**, ACL 2025

> NotInject: 339 benign samples seeded with trigger words common in injection attacks.
> State-of-the-art guard models drop to near-random accuracy (~60%).

**What it changed.** Provided the over-defense benchmark
([`scripts/eval_notinject.py`](scripts/eval_notinject.py), commit `4ba14ee`). The
result inverted the expectation: the 197-term keyword blocklist scored **0/339
(FPR 0.000)**, while the DeBERTa classifier blocked **137/339 (FPR 0.404)**, degrading
with trigger density (20% → 50% → 51% at one, two, three trigger words).

That measurement directly caused commit `3fd8b4f`: **Tier 2 now ships monitor-only.**
It scores and logs but does not block, because a 40% false-block rate is not a
shippable default. The paper's framing — that trigger-word bias, not capability, is
what breaks guard models in practice — is the reason that decision was made on FPR
rather than on recall.

### Liu, Jia, Geng, Jia & Gong (2024)
**Formalizing and Benchmarking Prompt Injection Attacks and Defenses.** USENIX Security 2024 · arXiv:2310.12815 · code: github.com/liu00222/Open-Prompt-Injection

> Formal framework for prompt injection; releases a benchmark of 5 attack strategies
> across 10 models and 7 tasks.

**What it changed.** Two things, one of them structural.

First, the benchmark itself
([`scripts/eval_open_prompt_injection.py`](scripts/eval_open_prompt_injection.py),
commit `ca20810`); attack templates and injected instructions transcribed from upstream
source. GuardRail scored **40%** — catching only the two strategies containing the
literal string "Ignore previous instructions." and missing all three that inject a
well-formed instruction with no override phrasing.

Second, and more important: diagnosing that 40% exposed a **threat-model mismatch**
rather than a missing rule. This framework's attacks inject instructions into the
*data* an application processes, whereas GuardRail was screening every request as the
user's own turn — where instructions are legitimate and the benign corpus contains
"Summarize this document for me." Commit `76743c1` added the `source` field
(`"user"` / `"data"`) so callers declare which trust boundary the text crossed, plus
instruction-shape patterns that apply only to untrusted data. Recall went **0.40 →
1.00** at 0.6% FPR, with the user path byte-identical.

### Yi, Xie, Wang, Wang, Wang, Liu, Sun & Wu (2023)
**Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models (BIPIA).** arXiv:2312.14197 · code: github.com/microsoft/BIPIA

> First benchmark for indirect prompt injection; attacks embedded in external content.

**What it changed.** Supplied the result that sets the project's honest ceiling
([`scripts/eval_bipia.py`](scripts/eval_bipia.py), commit `aabe82a`). BIPIA's text
attacks carry no override vocabulary *and* no formatted task spec — they are ordinary
requests ("Write a script to rename all files"). The instruction-shape patterns that
score 1.00 on Open-Prompt-Injection score **0.48** here, and **0.082** before the verb
list was widened.

That gap is the central finding now carried into the paper: those patterns were written
against Open-Prompt-Injection's templates, so scoring well there was partly in-sample.
Per-category recall tracks vocabulary overlap, not attack severity (Substitution
Ciphers 51%; Marketing, Entertainment, Misinformation 2%). **Pattern matching over
instruction surface form does not generalise across instruction phrasings.**

BIPIA also exposed a genuine bug: `_normalize` collapsed newlines, so an instruction
appended on its own line lost the sentence boundary its anchor needed — measured 20.8%
versus 48.0% for the same patterns on raw text. Fixed in the same commit.

### Corll (2026)
**The Mirror Design Pattern: Strict Data Geometry over Model Scale for Prompt Injection Detection.** arXiv:2603.11875

> A sparse character n-gram linear SVM reaches 95.97% recall / 92.07% F1 at
> sub-millisecond latency on a 524-case holdout, against 44.35% for Prompt Guard.
> Argues the first screening layer must be "fast, deterministic, non-promptable,
> and auditable."

**What it changed.** This is the closest prior work and it constrains what this project
may claim. Its thesis — that the first layer should be deterministic and auditable
rather than large — is GuardRail's thesis. It also reports on a **genuine holdout**,
which is the standard the 1.000-on-training-corpus figure was measured against and
failed. Any novelty claim here has to be made relative to Mirror, not in a vacuum.

### Hackett, Birch, Trawicki, Suri & Garraghan (2025)
**Bypassing LLM Guardrails: An Empirical Analysis of Evasion Attacks against Prompt Injection and Jailbreak Detection Systems.** LLMSec 2025 · arXiv:2504.11168

> Character-injection and adversarial-ML evasion against six systems including Azure
> Prompt Shield and Meta Prompt Guard, with up to 100% evasion success.

**What it changed.** Nothing yet — recorded here because it is the specific, published
attack against the component GuardRail relies on most (Unicode normalisation and the
de-obfuscation pass), and pretending otherwise would misrepresent the threat coverage.
The de-obfuscation pass handles leetspeak, small-caps, fullwidth, combining marks and
separator fragmentation, but has **not** been evaluated against the optimised character
-injection attacks described here. This is the highest-priority open item.

### Munirathinam (2026)
**Beyond Pattern Matching: Seven Cross-Domain Techniques for Prompt Injection Detection.** arXiv:2604.18248

> Open-source detectors have converged on two designs — regex pattern matching and
> fine-tuned transformer classifiers — which share known failure modes.

**What it changed.** Framing and honesty about novelty: it names GuardRail's exact
architecture as the converged baseline, so "two-tier rules + transformer" is not itself
a contribution. It also independently predicts both failure modes this project then
measured — patterns missing paraphrases (BIPIA, 0.48) and classifiers falling to
adaptive pressure.

### Chi, Malvai, Ahmadinejad et al. — **Llama Guard 3-1B-INT4** (2024), arXiv:2411.17713
**What it changed.** Reference point for quantized-guardrail deployment claims, and a
useful contrast: quantization is presented there as near-free, whereas here INT8
dynamic quantization cost **14–17 points of recall** even when configured correctly,
and a misconfigured graph (`per_channel=False`) collapsed to predicting SAFE for every
input — producing a fake "Tier 2 contributes nothing" result until it was caught
(commit `e8cb63e`). Benchmark quantized graphs; do not assume graceful degradation.

---

## 2. Context — read, cited, not yet acted on

Relevant to positioning and future work; no code in this repo derives from them.

| Paper | Relevance |
|---|---|
| **InjecAgent** — Zhan et al. (2024), arXiv:2403.02691 | Indirect injection in tool-integrated agents. Scopes what GuardRail does *not* cover: it screens text, not tool-call chains. |
| **Agent Security Bench** — Zhang et al. (2024), arXiv:2410.02644 | Broader agent attack/defense benchmark; the natural next evaluation if this moves to agent settings. |
| **MELON** — Zhu et al. (2025), arXiv:2502.05174 | Provable-ish IPI defense via masked re-execution — a fundamentally different strategy from detection. |
| **IPIGuard** — arXiv:2508.15310 | Tool-dependency-graph defense; again structural rather than lexical. |
| **SoK: Landscape of Prompt Injection Threats** — arXiv:2602.10453 | Taxonomy that situates the text/model/execution intervention layers. GuardRail is text-level only. |
| **CAPTURE** — arXiv:2505.12368 | Context-aware benchmark measuring detection *and* over-defense together; a natural follow-up to running NotInject and BIPIA separately. |
| **PIArena** — arXiv:2604.08499 | Unified evaluation platform; documents defenses that looked strong then failed on diverse data. |
| **Evasive Injections** — arXiv:2602.00750 | Multi-probe evasion against activation-based detectors. |
| **PIShield** — arXiv:2510.14005 | Detection from internal LLM representations — the "model the function, not the wording" direction this project's BIPIA result points toward. |
| **Sentinel** (ModernBERT) — arXiv:2506.05446 · **GenTel-Safe** — arXiv:2409.19521 · **Palisade** — arXiv:2410.21146 · **PromptSleuth** — arXiv:2508.20890 · **Sentra-Guard** — arXiv:2510.22628 | Competing detectors. These, not Llama Guard, are the correct comparison set — see the note below. |
| **Lightweight Safety Guardrails via fine-tuned BERT** — arXiv:2411.14398 · **GLiGuard** — arXiv:2605.07982 · **MultiTaskGuard** — arXiv:2504.19333 | Efficiency-oriented guardrails; relevant to the latency positioning. |

---

## 3. A correction this reading forced

The evaluation originally compared GuardRail against **Llama Guard 3-8B** and reported
0.1316 recall for it. That comparison is a **category error**, and reading the
literature above is what made it obvious: Llama Guard is a *content-safety* classifier
whose taxonomy (S1–S13: violent crimes, weapons, self-harm, …) does not include prompt
injection. Its low recall reflects a task mismatch, not a defect — its perfect
precision and 0.000 FPR show it behaving correctly at its actual job.

The baseline is retained in `results/eval_results_baseline.json` with that caveat
recorded in-band, and the defensible reading is stated in the README: *content-safety
guardrails do not transfer to prompt-injection detection*. The correct comparison set
is the detector group in §2 (Sentinel, GenTel-Safe, Palisade, PromptSleuth, InjecGuard).

---

## 4. Citation keys

```bibtex
@inproceedings{liu2024formalizing,
  title     = {Formalizing and Benchmarking Prompt Injection Attacks and Defenses},
  author    = {Liu, Yupei and Jia, Yuqi and Geng, Runpeng and Jia, Jinyuan and Gong, Neil Zhenqiang},
  booktitle = {USENIX Security Symposium},
  year      = {2024}
}

@article{yi2023bipia,
  title   = {Benchmarking and Defending Against Indirect Prompt Injection Attacks on Large Language Models},
  author  = {Yi, Jingwei and Xie, Yueqi and Zhu, Bin and Hines, Keegan and Kiciman, Emre and Sun, Guangzhong and Xie, Xing and Wu, Fangzhao},
  journal = {arXiv preprint arXiv:2312.14197},
  year    = {2023}
}

@article{li2024injecguard,
  title   = {InjecGuard: Benchmarking and Mitigating Over-defense in Prompt Injection Guardrail Models},
  author  = {Li, Hao and Liu, Xiaogeng},
  journal = {arXiv preprint arXiv:2410.22770},
  year    = {2024}
}

@article{nasr2025attacker,
  title   = {The Attacker Moves Second: Stronger Adaptive Attacks Bypass Defenses Against LLM Jailbreaks and Prompt Injections},
  author  = {Nasr, Milad and Carlini, Nicholas and Sitawarin, Chawin and Schulhoff, Sander V. and Hayes, Jamie and Ilie, Michael and Pluto, Juliette and Song, Shuang and Chaudhari, Harsh and Shumailov, Ilia and Thakurta, Abhradeep and Xiao, Kai Yuanqing and Terzis, Andreas and Tram{\`e}r, Florian},
  journal = {arXiv preprint arXiv:2510.09023},
  year    = {2025}
}

@inproceedings{hackett2025bypassing,
  title     = {Bypassing LLM Guardrails: An Empirical Analysis of Evasion Attacks against Prompt Injection and Jailbreak Detection Systems},
  author    = {Hackett, William and Birch, Lewis and Trawicki, Stefan and Suri, Neeraj and Garraghan, Peter},
  booktitle = {LLMSec},
  year      = {2025}
}

@article{corll2026mirror,
  title   = {The Mirror Design Pattern: Strict Data Geometry over Model Scale for Prompt Injection Detection},
  author  = {Corll, J Alex},
  journal = {arXiv preprint arXiv:2603.11875},
  year    = {2026}
}

@article{munirathinam2026beyond,
  title   = {Beyond Pattern Matching: Seven Cross-Domain Techniques for Prompt Injection Detection},
  author  = {Munirathinam, Thamilvendhan},
  journal = {arXiv preprint arXiv:2604.18248},
  year    = {2026}
}
```

> Author lists for BIPIA and Llama Guard 3-1B-INT4 are taken from the papers' arXiv
> listings. Verify every entry against the publisher record before submission — this
> file is a working bibliography, not a checked one.
