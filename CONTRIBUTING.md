<!-- SPDX-License-Identifier: Apache-2.0 -->

# Contributing to `coldpin`

Thank you for contributing to `coldpin` (Coldpin). This project follows strict supply-chain hygiene and zero-dependency standards.

## Engineering Rules

1. **Zero External Runtime Dependencies:** `src/` must run natively on Node.js `>= 24.0.0` (`node:sqlite`, `node:zlib`, `node:crypto`, `node:module`, `fetch`) using `erasableSyntaxOnly` TypeScript. Governance scripts under `scripts/` must use Python 3.11+ stdlib or Node 24 stdlib only.
2. **One Canonical Skill Source:** Edit skill prose only under `skill-src/coldpin/`. Never hand-edit `.agents/skills/coldpin/`; regenerate it via `npm run pack:plugin`.
3. **Rule Lifecycle Hygiene:** Every new static detection rule must:
   - Be registered in `rules/triage-rules.json` with severity, owner, and MITRE ATT&CK/ATLAS mapping.
   - Include both a positive adversarial fixture AND a negative benign fixture in `tests/benchmark-corpus.ts`.
   - Pass mutation verification proving the assertion turns red when the attack is introduced.
4. **No Fabricated Evidence:** Never fabricate Tier 3 multi-agent benchmark scores or overclaim static coverage.
5. **Fact Ledger Discipline:** Any new regulatory date, compliance threshold, or external URL host added to docs or references must carry a dated entry in `docs/fact-ledger.md`.

## Mandatory Pre-PR Verification

Run the complete local verification pipeline before submitting a pull request:

```sh
npm run bench
npm run sign:skill
npm run verify:all
```

Every gate (unit/E2E/hardening tests, skill lint, hygiene, staleness, static eval, SkillSpector self-audit, benchmark verification, cryptographic DSSE signature verification, and reproducible multi-host packaging) must exit `0`.
