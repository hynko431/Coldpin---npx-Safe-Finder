---
last_reviewed: 2026-11-20
review_by: 2027-02-20
status: current
owner_lens: fact-ledger
sources: see rows
---

# Fact Ledger (`coldpin`)

Rule: every volatile regulatory date, standard revision, and external security taxonomy claim cited in `coldpin` carries a dated verification row here. Verification levels:
- **P** = confirmed against a primary-source page or official gazette
- **S+** = confirmed by two or more independent reputable sources citing the official host
- **S** = single secondary source; re-check before compliance-bearing decisions
- **K** = stable long-standing knowledge (still dated)

| # | Claim | Primary Source | Level | Verified | Used In | Next Review |
|---|---|---|---|---|---|---|
| 1 | MITRE ATT&CK techniques `T1195.001` (Compromise Software Dependencies), `T1195.002` (Compromise Software Supply Chain), `T1059.007` (JavaScript), `T1552.001` (Credentials In Files), `T1041` (Exfiltration Over C2), `T1027` (Obfuscated Files), `T1554` (Compromise Host Software Binary), `T1546` (Event Triggered Execution), `T1499` (Endpoint DoS), `T1608.001` (Upload Malware) | `attack.mitre.org/techniques/` | K | 2026-11-19 | `threat-taxonomy.md`, `src/` | 2027-02-19 |
| 2 | MITRE ATLAS techniques `AML.T0051` / `AML.T0051.001` (Indirect Prompt Injection), `AML.T0054` (LLM Jailbreak), `AML.T0010` (ML/AI Supply Chain Compromise) & OWASP LLM Top 10 `LLM01:2025` | `atlas.mitre.org`, `owasp.org` | K | 2026-11-19 | `threat-taxonomy.md`, `SKILL.md` | 2027-02-19 |
| 3 | India CERT-In Directions (2022-04-28): 6-hour cyber-incident reporting clock, 180-day ICT log retention in India, NIC/NPL NTP sync | `cert-in.org.in` | K | 2026-11-19 | `enterprise-policy-schema.md` | 2027-02-19 |
| 4 | India DPDP Act 2023 + DPDP Rules 2025 notified 2025-11-13; consent-manager provisions 2026-11-13; core fiduciary obligations 2027-05-13 (re-check primary Gazette before legal reliance) | `meity.gov.in` Gazette G.S.R. 846(E) | S+ | 2026-11-19 | `enterprise-policy-schema.md` | 2027-02-19 |
| 5 | EU Cyber Resilience Act Reg. (EU) 2024/2847: reporting duties 2026-09-11 (24h early warning, 72h notification); main obligations including SBOM 2027-12-11 (re-check OJ text before legal reliance) | `eur-lex.europa.eu` OJ L 2024/2847 | S+ | 2026-11-19 | `enterprise-policy-schema.md` | 2027-02-19 |
| 6 | EU NIS2 Dir. (EU) 2022/2555 (24h early warning / 72h notification) & GDPR Art. 33 (72h supervisory breach notification) | `eur-lex.europa.eu` | K | 2026-11-19 | `enterprise-policy-schema.md` | 2027-02-19 |
| 7 | SARIF 2.1.0 OASIS Standard & CycloneDX 1.5 OWASP Standard & CISA TLP 2.0 | `oasis-open.org`, `cyclonedx.org`, `cisa.gov/tlp` | K | 2026-11-19 | `evidence-card-spec.md`, `src/verdict/` | 2027-05-19 |
| 8 | SLSA v1.0 Build Track (L0–L3) & in-toto Attestation Statement v1 (`application/vnd.in-toto+json`, `model_signing/signature/v1.0`) | `slsa.dev`, `in-toto.io`, `sigstore.dev` | K | 2026-11-19 | `sign_and_verify_skill.ts`, `enterprise-policy-schema.md` | 2027-05-19 |
| 9 | Node.js `v24.1.0` enables `node:sqlite` (`DatabaseSync`) and native TypeScript type-stripping (`stripTypeScriptTypes`) by default; Node 22 reaches EOL `2027-04-30` while Node 24 receives security updates through `2028-04-30` | `nodejs.org`, verified locally via `node --version` | P | 2026-11-20 | `package.json`, `docs/designs/coldpin.md` | 2027-02-20 |
| 10 | Model Context Protocol (`2025-11-25`, `2025-06-18`, `2025-03-26`), Official MCP Registry `server.json` (`2025-12-11` schema, `description <= 100` chars, `package.json` `mcpName` verification), & OWASP MCP Top 10:2025 (`MCP01:2025`–`MCP10:2025`) | `modelcontextprotocol.io`, `static.modelcontextprotocol.io`, `registry.modelcontextprotocol.io`, `owasp.org` | S+ | 2026-11-20 | `server.json`, `src/mcp/`, `docs/harnesses.md` | 2027-02-20 |
| 11 | npm Trusted Publishing keyless GitHub Actions OIDC (`npm >= 11.5.1`) with automatic Sigstore provenance & Antigravity plugin CLI strict validation (`agy.exe v1.5.13`) | `npmjs.com`, `antigravity.google`, verified locally via `agy.exe` | P | 2026-11-20 | `.github/workflows/release.yml`, `mcp_config.json`, `docs/harnesses.md` | 2027-02-20 |

## Approved URL Host Allow-List (Checked by `scripts/verify_hygiene.py`)

`registry.npmjs.org`, `api.osv.dev`, `json.schemastore.org`, `github.com`, `attack.mitre.org`, `atlas.mitre.org`, `owasp.org`, `cert-in.org.in`, `meity.gov.in`, `eur-lex.europa.eu`, `oasis-open.org`, `cyclonedx.org`, `cisa.gov`, `slsa.dev`, `in-toto.io`, `sigstore.dev`, `www.apache.org`, `artifactory.acme.internal`, `model_signing`, `keepachangelog.com`, `modelcontextprotocol.io`, `static.modelcontextprotocol.io`, `registry.modelcontextprotocol.io`, `antigravity.google`, `npmjs.com`, `nodejs.org`.
