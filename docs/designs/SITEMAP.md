# Design Documents Sitemap

Living index of checked-in technical specifications for `coldpin` (Coldpin; EGM living-documentation standard).

| Document | Status | Author | Last Updated | Scope |
|---|---|---|---|---|
| [coldpin.md](coldpin.md) | Approved | hynko431 | 2026-11-20 | Locked v1.3.0 architecture: zero-dep Node 24 CLI + local stdio MCP server (`lib/**/*.mjs`), lexical taint scoping & non-regex obfuscation calibration, provenance-aware 3-tier parity, Split-Plane SQLite DDL, and multi-marketplace manifests. |

## Related Verification & Governance Records

- [Fact Ledger](../fact-ledger.md) — Verified P/S+/S/K citations for all regulatory dates, ATT&CK/ATLAS/OWASP MCP IDs, and standards.
- [Testing & Verification](../../TESTING.md) — Test layers, mutation checks, and verification boundaries.
- [Benchmarks](../../skills/coldpin/BENCHMARK.md) — Executed Tier 1–2 measurements and Tier 3 live-eval readiness.
- [SkillSpector Self-Audit](../verification/skill-inspector-self-audit.md) — Deterministic security self-audit of the `coldpin` skill, MCP manifests, and compiled runtime parity.
