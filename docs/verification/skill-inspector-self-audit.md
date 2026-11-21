<!-- SPDX-License-Identifier: Apache-2.0 -->

## Skill Inspector: `coldpin`

**Source:** `skills/` (3 skills) + `src/` + `lib/` (1:1 parity-verified) + `scripts/` + `catalog/` + `rules/` (3) + `agents/` (7) + `hooks.json` (3 groups) + multi-harness & MCP manifests
**Verdict:** `APPROVE` — Zero blocking HIGH/CRITICAL findings; documented network and read-only async git/probe surfaces are bounded, hardened, and controllable; MCP schema pin, read-only agents, fail-safe PreToolUse hooks, rules hygiene, and compiled lib/ parity verified.
**Risk:** 12/100 · LOW · ALLOW_WITH_STANDARD_CONTROLS
**Install posture:** Suitable for local developer workspaces, Antigravity App/CLI (`>= v1.5.13`), IDE MCP hosts (stdio), and CI verification pipelines on Node.js >= 24; not a substitute for runtime EDR or isolated detonation on dynamically fetched payloads.

### Bottom Line
Deterministic SkillSpector-class static scanning (`--no-llm` equivalent, with zero whole-file skips on `src/`) and source-aware review found **0 blocking findings** and **3 documented low-risk capabilities**. The implementation matches the stated zero-execution `npx` discovery, vetting, local `stdio` MCP server, read-only aspect subagents, and fail-safe `PreToolUse` guarding purpose without auto-approval hooks, listening sockets, persistence, symlinks, dynamic `eval`, silent package installs, or compiled runtime drift.

### Signal Overview
| Source | Result | Interpretation |
|---|---|---|
| Deterministic static self-audit (`SS-03`–`SS-15`) | `0` blocking, `3` documented LOW | Clean across Unicode, secrets, `shell=True`, import-aware child_process, dynamic `eval`, persistence, symlinks, `SS-08` hook least privilege, MCP schema pin, MCP config least privilege, `src/` ↔ `lib/` 1:1 parity, `SS-14` read-only agents, and `SS-15` rules hygiene. |
| Source-aware semantic review | Purpose & permission fit verified | `SKILL.md`, `rules/`, `agents/`, `hooks.json`, and `lib/mcp.mjs` enforce operator-only control plane, human confirmation, private-scope isolation, and non-LLM verdict authority. |
| Sensitive surface | Hardened read-only async `git` (`core.fsmonitor=false`, `core.hooksPath=/dev/null`, `http.followRedirects=false`, minimal env), SSRF/DNS/redirect-hardened HTTPS `fetch`, read-only `--version` probe | Strictly scoped, disabled in `--offline` mode, private scopes never hit public endpoints, HTTPS-only Bearer auth, cross-origin redirects strip credentials. |

### Key Evidence
| Rule | Severity | Location | Review judgment |
|---|---|---|---|
| `SS-03-BOUNDED-EXEC` | `LOW` | `src/analysis/parity-and-bisect.ts:1` | Acceptable: required for Git parity/bisect or --version probe; never executes untrusted package scripts. |
| `SS-03-BOUNDED-EXEC` | `LOW` | `src/config/policy.ts:1` | Acceptable: required for Git parity/bisect or --version probe; never executes untrusted package scripts. |
| `SS-09-BOUNDED-NETWORK` | `LOW` | `src/intel/registry-osv.ts:271` | Acceptable: documented core capability, blocked for private scopes and --offline. |

### Diagnosis
Every observed sensitive call site (`src/intel/registry-osv.ts` HTTPS registry/OSV fetch, `src/analysis/parity-and-bisect.ts` hardened read-only async `git`, and `src/config/policy.ts` read-only async `git`/`rea` `--version` probe) was located dynamically by line number, verified to disable shell interpolation, Git redirects, and Git hooks, and remains controllable via `--offline` / `COLDPIN_OFFLINE=1` and operator policy. All 20 compiled ESM files under `lib/` match `src/` 1:1 cryptographically (`SS-13`), and the canonical MCP `tools/list` + `resources/list` + `prompts/list` catalog matches `catalog/mcp-schema-pin.json` (`SS-11`). External `skillspector` CLI binary was not installed on `PATH` on this host, so this report reflects the repo's deterministic SkillSpector-equivalent static checker plus manual source review.

### Guardrails
1. Keep `.coldpin.policy.json` configured with `private_scopes` and `private_prefixes` before running against internal organization repositories; in MCP mode configure policy via `COLDPIN_POLICY_PATH` or `COLDPIN_PRIVATE_*` env vars.
2. Never add automatic command-approval hooks (`auto_approve`, `permissionOverrides`, `overwrite`) to `hooks.json` or `plugin.json`; require explicit human confirmation before executing any emitted `npx` command.
3. Re-run `npm run audit:self` and inspect `dist/skillspector-self-audit.sarif` on every PR and release.
