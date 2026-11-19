---
last_reviewed: 2026-11-19
review_by: 2027-02-19
status: current
owner_lens: maintenance-cadence
sources: Enterprise Commons MAINTENANCE.md; Google EGM runtime_packaging.md; NVIDIA Auto-Ontology BENCHMARK.md
---

# Maintenance Cadence (`coldpin`)

| Cadence | Task | Command / Owner |
|---|---|---|
| **Every edit** | Unit, quarantine, taint, prompt-injection & Git E2E tests | `npm test` |
| **Every edit** | Structural skill lint, link check & multi-harness manifest drift | `npm run lint:skill` |
| **Every edit** | Hygiene, BOM, Unicode, secret scan & URL allow-list check | `npm run verify:hygiene` |
| **Every edit** | Static coverage + positive/decoy trigger selection proxy | `npm run eval:static` |
| **Every edit** | SkillSpector-class static self-audit + SARIF emission | `npm run audit:self` |
| **Every release** | Real 20-fixture corpus benchmark, mutation checks & `BENCHMARK.md` refresh | `npm run bench` |
| **Every release** | Cryptographic in-toto DSSE `skill.oms.sig` sign & verify | `npm run sign:skill` / `npm run sign:verify` |
| **Every release** | Reproducible multi-host bundles (`antigravity`, `claude`, `openai`) | `npm run pack:plugin` |
| **Weekly (scheduled CI)** | Reference & Fact Ledger staleness check (`30d` window) | `npm run check:stale` (exit `1` if any `review_by` date has passed) |
| **Quarterly** | Review volatile Fact Ledger rows (`docs/fact-ledger.md`) against primary pages; run live Tier-3 multi-agent sandbox evals when API keys are configured | Skill Maintainer / AppSec |
| **On upstream change** | New ATT&CK, ATLAS, EU CRA, India DPDP, or CERT-In updates | Update `docs/fact-ledger.md` row first, then `references/` |

## Rules

- No volatile regulatory date or external threshold enters `skill-src/` without a corresponding row in `docs/fact-ledger.md`.
- Every file under `skill-src/coldpin/references/` carries `last_reviewed`, `review_by` (3 months for regulation-heavy files, 6 months max), and `status`.
- Keep `skill-src/coldpin/SKILL.md` strictly `<= 220` lines and `<= 24 KB`.
- Never hand-edit `.agents/skills/coldpin/`; always regenerate via `scripts/pack_plugin.py --sync-workspace`.
- Regenerate `skill.oms.sig` and `BENCHMARK.md` whenever any file in `skill-src/coldpin/` or `src/` changes, and bump `CHANGELOG.md` (semver).

Next quarterly review: `2027-02-19`.
