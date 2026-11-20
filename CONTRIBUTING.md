<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to `coldpin`

Thank you for contributing to `coldpin` (Coldpin). This project follows strict supply-chain hygiene and zero-dependency standards.

## Engineering Rules

1. **Zero External Runtime Dependencies:** `src/` must run natively on Node.js `>= 24.0.0` (`node:sqlite`, `node:zlib`, `node:crypto`, `node:module`, `fetch`) using `erasableSyntaxOnly` TypeScript. Governance scripts under `scripts/` must use Python `>= 3.11` stdlib or Node 24 stdlib only. Keep `package.json` `"files"` restricted to vetted runtime and documentation paths.
2. **One Canonical Skill Source:** Edit skill prose only under `skill-src/coldpin/`. Never hand-edit `.agents/skills/coldpin/`; regenerate it via `npm run pack:plugin`.
3. **Version Parity:** Keep version numbers synchronized across `src/types.ts` (`ENGINE_VERSION`), `package.json`, `plugin.json`, `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.codex-plugin/plugin.json`, `rules/triage-rules.json`, `skill-src/coldpin/SKILL.md`, and `skill-src/coldpin/skill-card.md` (enforced by `scripts/lint_skill.py`).
4. **Rule Lifecycle Hygiene:** Every new static detection rule must:
   - Be registered in `rules/triage-rules.json` with severity, owner, and MITRE ATT&CK/ATLAS mapping.
   - Include both a positive adversarial fixture AND a negative benign fixture in `tests/benchmark-corpus.ts`.
   - Pass mutation verification proving the assertion turns red when the attack is introduced.
5. **No Fabricated Evidence:** Never fabricate Tier 3 multi-agent benchmark scores or overclaim static coverage.
6. **Fact Ledger Discipline:** Any new regulatory date, compliance threshold, or external URL host added to docs or references must carry a dated entry in `docs/fact-ledger.md`.

## Mandatory Pre-PR Verification

Refresh measured and signed artifacts whenever `src/`, `rules/`, `skill-src/`, or corpus files change, then run the full 9-gate pipeline:

```sh
npm run bench
npm run audit:self
npm run sign:skill
npm run verify:all
```

Every gate (unit/E2E/hardening tests, skill lint, hygiene, staleness, static eval, SkillSpector self-audit, benchmark verification, cryptographic DSSE signature verification, and reproducible multi-host packaging) must exit `0` with zero CRLF or untracked-file drift. Complete the checklist in `.github/PULL_REQUEST_TEMPLATE.md` when opening a pull request.

## CI & Release Workflows

- **Cross-Platform CI (`.github/workflows/ci.yml`):** Runs `npm run verify:all` on both `ubuntu-latest` and `windows-latest` (`fail-fast: false`) on pushes to `main`, pull requests, manual dispatch, and a weekly Monday staleness schedule, using commit-SHA-pinned actions and uploading `dist/skillspector-self-audit.sarif` on Ubuntu.
- **Tag-Driven Releases (`.github/workflows/release.yml`):** Triggered by pushing a `v*` tag (matching `package.json` version) or via manual dispatch. Runs `npm run verify:all`, builds reproducible `dist/coldpin-{antigravity,claude,openai}.zip` bundles, writes `dist/SHA256SUMS.txt`, and publishes a GitHub Release via built-in `gh release create`.
