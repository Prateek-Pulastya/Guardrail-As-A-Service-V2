# Changelog

All notable changes to this project are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); this project uses
[Semantic Versioning](https://semver.org/).

## [Unreleased]

Planned for the next version (see README "Results" and the release-readiness notes):
- Swap Tier 2 for an over-defense-aware model (PIGuard, MIT) and re-measure
  held-out recall, NotInject FPR, and BIPIA; if it cuts the 40% false-block rate
  while holding recall, Tier 2 can block and monitor-only mode goes away.
- Adaptive-attacker evaluation (paraphrase/clause-rewrite, search-based, and
  character-injection) rather than static corpora only.
- Baselines table against Llama Prompt Guard 2 and standalone ProtectAI under the
  same `source` conditions.
- Fresh held-out test set written by someone who never saw the rules.

## [1.0.0] - 2026-10-22

Initial public release.

### Added
- Two-tier prompt-injection detection service: Aho–Corasick blocklist + regex
  (Tier 1) followed by a DeBERTa-v3 ONNX classifier (Tier 2), behind
  `POST /validate`.
- `source` trust-boundary field (`user` / `data`): declaring `data` applies
  instruction-shape patterns and moves Open-Prompt-Injection recall 0.40 → 1.00.
- De-obfuscation scan (leetspeak, small-caps, fullwidth, combining marks,
  separator fragmentation) as a second Tier 1 pass.
- `POST /explain` and a self-contained web playground (`/ui`) that animates the
  screening trace.
- Evaluation harness and committed results for the in-house corpus, a held-out
  split, and three external benchmarks (Open-Prompt-Injection, BIPIA, NotInject).
- Prometheus metrics and Grafana dashboards.
- LICENSE (MIT), CITATION.cff, SECURITY.md.

### Changed
- Tier 2 ships **monitor-only** by default: it over-defends (40% false blocks on
  NotInject), so it scores and logs but does not block; blocking is opt-in.
- Default Tier 2 graph is fp32 `model.onnx`; INT8 is opt-in (`--quantize` /
  `GUARDRAIL_TIER2_MODEL_FILE`) because INT8 cost 14–17 points of recall here.
- `docker-compose.yml` binds all host ports to `127.0.0.1`; Grafana password is an
  overridable env var.

### Fixed
- INT8 dynamic quantization had silently collapsed Tier 2 to always-`SAFE`;
  default switched to fp32 and a startup canary + `/health` now surface a
  collapsed graph instead of failing open unnoticed.
- Held-out evaluation protocol added after finding the blocklist had been tuned on
  the full corpus (in-sample recall 1.000 vs held-out 0.789).
