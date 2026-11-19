---
last_reviewed: 2026-11-19
review_by: 2027-02-19
status: current
owner_lens: enterprise-policy-and-compliance
sources: India DPDP Act 2023 + Rules 2025; CERT-In Directions 2022-04-28; EU CRA Reg. 2024/2847; EU NIS2 Dir. 2022/2555; GDPR; NIST SP 800-218 (SSDF); ISO/IEC 27001:2022; SOC 2
---

# Enterprise Policy Schema, Registry Isolation & Compliance

*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*

## 1. `.coldpin.policy.json` Discovery & Schema

Loaded in precedence order: explicit `--policy <path>` -> `<CWD>/.coldpin.policy.json` -> `<git-root>/.coldpin.policy.json` -> `~/.coldpin.policy.json` -> legacy `.npx-guard.policy.json` fallback -> built-in defaults.

```json
{
  "private_scopes": ["@acme", "@acme-internal"],
  "private_prefixes": ["acme-internal-"],
  "private_registries": {
    "@acme": "https://artifactory.acme.internal/api/npm/npm-internal"
  },
  "default_registry": "https://registry.npmjs.org",
  "allow_public_fallback": false,
  "allowed_orgs": [],
  "denied_orgs": ["@known-compromised-org"],
  "blocked_licenses": ["AGPL-3.0", "AGPL-3.0-only", "SSPL-1.0"],
  "cooldown_hours": 72,
  "max_compressed_bytes": 20971520,
  "max_uncompressed_bytes": 52428800,
  "max_files": 5000,
  "max_single_file_bytes": 10485760,
  "block_on_kev": true,
  "block_on_critical_cve": true,
  "block_on_high_cve": false,
  "require_provenance": false,
  "require_source_link": false,
  "bisect_max_commits": 200,
  "bisect_max_days": 180,
  "intel_ttl_seconds": 21600,
  "offline_mode": false
}
```

## 2. Private Registry & Dependency Confusion Isolation

- Bind every internal scope in committed `.npmrc`:
  ```ini
  @acme:registry=https://artifactory.acme.internal/api/npm/npm-internal/
  //artifactory.acme.internal/api/npm/npm-internal/:_authToken=${NPM_TOKEN}
  ```
- Private scopes and `private_prefixes` NEVER query public `registry.npmjs.org` or `api.osv.dev`.
- Scopes within 1 Levenshtein edit of a declared private scope (e.g., `@amce/cli` vs `@acme`) fail closed (`blocked_typo`) to prevent accidental internal namespace leaks.
- Secrets (`${NPM_TOKEN}`) are read only from environment variables and never written to stdout, stderr, cache DB, or `audit.jsonl`.

## 3. Compliance & Incident Notification Clocks (Default India-First, Then EU/UK, US)

| Regime | Relevance | Earliest Clock | Notes |
|---|---|---|---|
| **India CERT-In Directions (2022-04-28)** | Supply-chain compromise on enterprise hosts in India | **6 hours** `[Standard]` | 180-day ICT log retention in India; NIC/NPL NTP sync `[Standard, verify current text]`. |
| **India DPDP Act 2023 + Rules 2025** | Developer PII in central audit logs | Per Board rules `[verify]` | Use pseudonymous `actor_id_hash` in `audit.jsonl`; core duties `2027-05-13 [verify]`. |
| **EU Cyber Resilience Act (Reg. 2024/2847)** | SBOM & vulnerability handling for products with digital elements | **24h** early warning / **72h** notice `[Standard]` | Use `--sbom` (CycloneDX 1.5); reporting `2026-09-11`, main duties `2027-12-11 [verify]`. |
| **EU NIS2 & GDPR** | Supply-chain security & personal data breach | **24h** (NIS2) / **72h** (GDPR Art. 33) `[Standard]` | Track single earliest clock in incident timeline. |
| **SOC 2 CC7.2 / ISO 27001:2022 A.8.15 / NIST SSDF** | Audit evidence & dependency verification | Contractual (typically 24–72h) `[Typical]` | Local `audit.jsonl` provides local tamper-evidence only; ship off-host to WORM storage for enterprise non-repudiation. |
