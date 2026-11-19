<!-- SPDX-License-Identifier: Apache-2.0 -->

## Skill Inspector: `coldpin`

**Source:** `skill-src/coldpin/` + `src/` + `scripts/` + `rules/` + multi-harness manifests
**Verdict:** `APPROVE` — Zero blocking HIGH/CRITICAL findings; documented network and read-only git/probe surfaces are bounded, hardened, and controllable.
**Risk:** 12/100 · LOW · ALLOW_WITH_STANDARD_CONTROLS
**Install posture:** Suitable for local developer workspaces and CI verification pipelines on Node.js >= 24; not a substitute for runtime EDR or isolated detonation on dynamically fetched payloads.

### Bottom Line
Deterministic SkillSpector-class static scanning (`--no-llm` equivalent, with zero whole-file skips on `src/`) and source-aware review found **0 blocking findings** and **3 documented low-risk capabilities**. The implementation matches the stated zero-execution `npx` discovery and vetting purpose without hidden hooks, persistence, symlinks, dynamic `eval`, or silent package installs.

### Signal Overview
| Source | Result | Interpretation |
|---|---|---|
| Deterministic static self-audit | `0` blocking, `3` documented LOW | Clean across Unicode, secrets, `shell=True`, shell APIs, dynamic `eval`, persistence, symlinks, and manifest hooks. |
| Source-aware semantic review | Purpose & permission fit verified | `SKILL.md` enforces human confirmation, private-scope isolation, and non-LLM verdict authority. |
| Sensitive surface | Hardened read-only `git` (`core.fsmonitor=false`, `core.hooksPath=/dev/null`), SSRF/redirect-hardened HTTPS `fetch`, read-only `--version` probe | Strictly scoped, disabled in `--offline` mode, private scopes never hit public endpoints, cross-origin redirects strip bearer tokens. |

### Key Evidence
| Rule | Severity | Location | Review judgment |
|---|---|---|---|
| `SS-03-BOUNDED-EXEC` | `LOW` | `src/analysis/parity-and-bisect.ts:140` | Acceptable: required for Git parity/bisect or --version probe; never executes untrusted package scripts. |
| `SS-03-BOUNDED-EXEC` | `LOW` | `src/config/policy.ts:409` | Acceptable: required for Git parity/bisect or --version probe; never executes untrusted package scripts. |
| `SS-09-BOUNDED-NETWORK` | `LOW` | `src/intel/registry-osv.ts:138` | Acceptable: documented core capability, blocked for private scopes and --offline. |

### Diagnosis
Every observed sensitive call site (`src/intel/registry-osv.ts` HTTPS registry/OSV fetch, `src/analysis/parity-and-bisect.ts` hardened read-only `git`, and `src/config/policy.ts` read-only `git`/`rea` `--version` probe) was located dynamically by line number, verified to disable shell interpolation and Git config hooks, and remains controllable via `--offline` and `.coldpin.policy.json`. External `skillspector` CLI binary was not installed on `PATH` on this host, so this report reflects the repo's deterministic SkillSpector-equivalent static checker plus manual source review.

### Guardrails
1. Keep `.coldpin.policy.json` configured with `private_scopes` and `private_prefixes` before running against internal organization repositories.
2. Never add automatic command-approval hooks to `plugin.json`; require explicit human confirmation before executing any emitted `npx` command.
3. Re-run `npm run audit:self` and inspect `dist/skillspector-self-audit.sarif` on every PR and release.
