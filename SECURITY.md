# Security Policy

## Reporting a vulnerability

Email **prateekpulastya@gmail.com** with "SECURITY" in the subject. Please include
a minimal reproduction a reviewer can replay from scratch. Do not open a public
issue for a vulnerability. There is no bounty; this is a research artifact.

## Supported versions

| Version | Supported |
|---|---|
| 1.0.0 | yes |
| < 1.0.0 | no |

## Security posture — read before deploying

GuardRail is a research artifact, not a production-hardened security control.

- **Not a standalone defense.** On external benchmarks the detector's recall is
  0.40–0.48 (Open-Prompt-Injection, BIPIA). It catches override vocabulary and
  misses well-formed instructions that carry none. Use it as one cheap layer,
  never as the only barrier in front of a model that can take consequential
  actions.
- **No adaptive-attacker robustness.** All evaluation is against static corpora.
  Adaptive attacks bypass detectors of this class at high rates; assume a
  motivated attacker gets through.
- **Tier 2 is monitor-only by default.** The learned tier scores and logs but does
  not block, because it over-defends (40% false blocks on NotInject). Blocking is
  opt-in via `POST /validate?tier=2`. Only Tier 1 blocks on the default path.
- **Fail-open.** If the Tier 2 model is missing or errors, requests pass. A
  silently-collapsed Tier 2 is surfaced by the startup canary and `/health`
  (`tier2.canary_ok`, `status: "degraded"`); monitor it.
- **Local-only defaults.** `docker-compose.yml` binds all host ports to
  `127.0.0.1` and ships a default Grafana password (`guardrail`, overridable via
  `GRAFANA_ADMIN_PASSWORD`). Change the password and review exposure before
  binding any port to a public interface.

## Supply chain

The Tier 2 model (`protectai/deberta-v3-base-prompt-injection-v2`) is downloaded at
build time. `/health` reports the loaded graph filename and its sha256 so you can
pin and verify the weights you actually run.
