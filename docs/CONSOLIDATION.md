# OmniGuard Next — consolidation baseline

Status: migration in progress; **not production-validated**.

## Source repositories

- [omniguard](https://github.com/we-do-care-global/omniguard) — gateway, dashboard, SDK, security modules and benchmark reports.
- [omniguard-production-](https://github.com/we-do-care-global/omniguard-production-) — separate release-oriented variant; verify diffs before selecting modules.
- [OmniGuard-Next](https://github.com/WeDoCareGlobal/OmniGuard-Next) — canonical destination.
- [agentguard-next](https://github.com/WeDoCareGlobal/agentguard-next) — downstream consumer; do not copy its governance engine into the gateway.

## Merge contract

1. Import gateway, dashboard, SDK and tests from the best-validated source, preserving license, provenance and original commit references.
2. Compare every imported path against both upstream variants; do not assume identical README means identical code.
3. Resolve divergence per module, preferring tested fail-closed behavior over a newer version label.
4. Preserve default-deny tool authorization, untrusted-input handling, auditable decisions and explicit health/readiness checks.
5. Remove hard-coded secrets; require environment-injected configuration and safe development defaults.
6. Add CI for lint, type checking, unit/integration tests, dependency/SBOM checks and container build.
7. Test the AgentGuard-to-OmniGuard request/response contract (ALLOW/BLOCK, unavailable, timeout, malformed response).
8. Validate documented benchmark results independently; never treat README badges as verified CI evidence.
9. Merge only after green checks and human review. Do not archive source repositories until parity and provenance are confirmed.

## Proposed canonical layout

```
omniguard-gateway/    # enforcement service
omniguard-dashboard/  # operator UI
sdk/                  # client integrations
tests/                # unit, integration, security regressions
reports/              # reproducible evidence, SBOM and release risks
docs/                 # architecture and migration decisions
.github/workflows/    # CI and supply-chain checks
```

## Open verification gates

- [ ] Compare upstream file trees and hashes at pinned commits.
- [ ] Import and reconcile application source and assets.
- [ ] Confirm API schema and AgentGuard compatibility.
- [ ] Run all tests and container build on the destination branch.
- [ ] Review deployment secrets, licenses and release artifacts.

This document is a migration baseline, not a claim that code consolidation is complete.
