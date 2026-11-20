<!-- SPDX-License-Identifier: Apache-2.0 -->

# Skill Benchmark: `coldpin`

> **Tier 1–2 Verdict: PASS (Local Deterministic Gates Verified)** · **Tier 3 Live Multi-Agent Uplift: NOT RUN (N/A)**

## Publication Recommendation

Tier 1 (static validation, hygiene, SkillSpector self-audit) and Tier 2 (49-fixture adversarial/benign corpus, cold vs. warm Split-Plane SQLite cache, 18 mutation proofs, and positive/decoy trigger selection) passed with **100.0% adversarial recall**, **0.0% false-positive rate**, and **18/18 mutation proofs**. Tier 3 live multi-agent sandbox evaluation (Antigravity / Claude Code / Codex token uplift vs. no-skill baseline) has **not** been executed in this offline environment and is recorded as `N/A` without estimation.

## Evaluation Metadata

- Skill: `coldpin` (`v1.2.1`)
- Evaluation date: `2026-11-20`
- Host runtime: `Node v24.1.0` on `win32/x64`
- Corpus: 49 deterministic fixtures (21 benign CLI archetypes + 28 adversarial/fail-closed attacks) + 18 mutation checks + 10 trigger selection prompts (5 positive + 5 negative decoys)
- Dataset digest: `sha256:a4ccfa8810bff2c32587bb4c0205d3f00ae1d052ba444a70bc1d61ccb092fb62` (`evals/evals.json` + `tests/selection.jsonl` + `tests/benchmark-corpus.ts` + `rules/triage-rules.json`)
- Peak process RSS observed: `77.7 MiB`
- Tier 1 evidence: **Executed locally**
- Tier 2 evidence: **Executed locally**
- Tier 3 evidence: **Not run** (requires live LLM API keys + isolated sandbox containers)

## Tier Status

| Tier | Purpose | Status | Evidence |
|---|---|---|---|
| Tier 1 | Static lint, hygiene, link, secret, Unicode, manifest sync & SkillSpector self-audit | **PASSED** | `lint_skill.py`, `verify_hygiene.py`, `staleness_check.py`, `self_audit_skillspector.py` |
| Tier 2 | Deterministic 49-fixture security corpus, Git cache timings, 18 mutation proofs & trigger selection | **PASSED** | Recall `100.0%` (28/28), FPR `0.0%` (0/21), Mutations `18/18`, Selection `10/10` (5 pos + 5 decoys) |
| Tier 3 | Live multi-agent sandbox evaluation (Antigravity / Claude Code / Codex vs. no-skill baseline) | **NOT RUN (N/A)** | Requires live LLM API & isolated container sandbox; coverage is never estimated |

## Results at a Glance

| Dimension | Tier 1–2 Measured Result | Tier 3 Live Agent Uplift |
|---|---|---|
| Security (Adversarial Recall) | `100.0%` (28/28 adversarial & fail-closed fixtures caught) | `N/A` (not run) |
| Security (False-Positive Rate) | `0.0%` (0/21 benign CLIs misclassified; target `< 5%`) | `N/A` (not run) |
| Correctness (Mutation Proofs) | `100.0%` (18/18 regressions caught red) | `N/A` (not run) |
| Discoverability (Trigger Proxy) | `100.0%` (5/5 positive matched, 5/5 decoys avoided) | `N/A` (not run) |
| Latency (Tier 1 In-Memory Unpack + Triage) | Benign p50 `5.59 ms`, p95 `14.84 ms` · Adv p95 `8.06 ms` | `N/A` (not run) |
| Efficiency (Git Bisect Split-Plane SQLite Cache) | Cold `7849.7 ms` (84 intra-run hits) → Warm `3345.8 ms` (104 hits across 8 walked commits) | `N/A` (not run) |

## Executed Corpus Breakdown

| Case ID | Category | Verdict | Pass | Elapsed (ms) |
|---|---|---|---:|---:|
| `benign-01-json-formatter` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 73.60 |
| `benign-02-comments-mentioning-eval` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 7.22 |
| `benign-03-color-env-vars` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 7.47 |
| `benign-04-typescript-source` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 8.74 |
| `benign-05-short-cli-tsx` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.59 |
| `benign-06-short-cli-zx` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.06 |
| `benign-07-scoped-org-cli` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.30 |
| `benign-08-localhost-dev-server` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.92 |
| `benign-09-readme-markdown` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 10.41 |
| `benign-10-legit-eslint-target` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 7.78 |
| `benign-11-regex-url-parser` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.19 |
| `benign-12-map-get-cache` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.56 |
| `benign-13-template-logging` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 3.95 |
| `benign-14-http-client-no-creds` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.58 |
| `benign-15-esm-cli-args` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.77 |
| `benign-16-multifile-esm-path-join` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.23 |
| `benign-17-static-import-and-aliased-git` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 6.21 |
| `benign-18-multihop-clean-fetch-helper` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 4.48 |
| `benign-19-regex-var-and-array-literal` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 5.93 |
| `benign-20-esbuild-scoped-env-alias` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 6.53 |
| `benign-21-unicode-regexp-parser` | benign | `VERIFIED_CLEAN_WITHIN_SCOPE` | PASS | 14.84 |
| `adv-01-postinstall-curl-pipe-sh` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 8.06 |
| `adv-02-cred-taint-exfiltration` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.07 |
| `adv-03-folded-computed-eval` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.34 |
| `adv-04-base64-hidden-shell` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 6.84 |
| `adv-05-zip-slip-traversal` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.11 |
| `adv-06-duplicate-tar-differential` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.85 |
| `adv-07-zip-bomb-cap` | adversarial | `QUARANTINE_SUSPICIOUS` | PASS | 21.47 |
| `adv-08-indirect-prompt-injection-bidi` | adversarial | `QUARANTINE_SUSPICIOUS` | PASS | 5.14 |
| `adv-09-typosquat-homoglyph-es1int` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.89 |
| `adv-10-uninspected-wasm-fail-closed` | adversarial | `UNVERIFIABLE_UNKNOWN` | PASS | 3.85 |
| `adv-11-template-literal-taint-exfil` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.58 |
| `adv-12-unicode-escape-eval` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.13 |
| `adv-13-multihop-taint-dns-exfil` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.20 |
| `adv-14-child-process-curl-pipe` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.91 |
| `adv-15-hex-obfuscator-0x` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.40 |
| `adv-16-cross-file-split-taint` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.73 |
| `adv-17-manifest-bin-shell-injection` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 5.15 |
| `adv-18-path-join-ssh-key-steal` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.44 |
| `adv-19-reflect-env-and-wrapper-sink` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.12 |
| `adv-20-tar-eof-polyglot-smuggling` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 3.71 |
| `adv-21-computed-dynamic-import-data-uri` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.54 |
| `adv-22-aliased-esm-child-process-exec` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 3.61 |
| `adv-23-multihop-wrapper-and-indirect-eval` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 3.96 |
| `adv-24-cross-file-exported-sink-wrapper` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.16 |
| `adv-25-no-semi-indirect-call-opt-chain` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.85 |
| `adv-26-create-require-and-barrel-reexport` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 7.31 |
| `adv-27-closure-captured-taint` | adversarial | `MALICIOUS_INDICATORS_FOUND` | PASS | 4.67 |
| `adv-28-dense-hex-escape-obfuscation` | adversarial | `QUARANTINE_SUSPICIOUS` | PASS | 3.59 |

## Mutation / Anti-Drift Verification (REA `rea-ci-tests-audit` Pattern)

| Mutation Check | Result | Observed State Transition |
|---|---|---|
| `mut-01-taint-injection-flips-verdict` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-02-audit-tamper-flips-valid` | PASS | `valid=true -> valid=false` |
| `mut-03-private-scope-typo-blocks-egress` | PASS | `private -> blocked_typo` |
| `mut-04-tarball-hook-drift-flips-parity` | PASS | `MANIFEST_PARITY_VERIFIED -> TARBALL_SOURCE_DRIFT` |
| `mut-05-template-literal-exfil-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-06-git-arg-injection-rejected` | PASS | `https=true -> opt=false, ext=false` |
| `mut-07-tarball-only-compromise-blocks-latest` | PASS | `USE_PINNED_LATEST -> ROLLBACK_TO_SAFE_ANCHOR@1.0.0` |
| `mut-08-tar-checksum-corruption-rejected` | PASS | `ok=true -> ok=false` |
| `mut-09-bin-shell-injection-blocked` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-10-cross-file-split-taint-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-11-tar-eof-smuggling-rejected` | PASS | `ok=true -> ok=false` |
| `mut-12-ipv6-mapped-ssrf-blocked` | PASS | `pub=true -> meta=false, gitLoop=false` |
| `mut-13-aliased-esm-exec-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-14-multihop-wrapper-global-env-caught` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-15-provenance-epistemic-and-digest-tamper` | PASS | `strict_unanchored=UNVERIFIABLE_UNKNOWN -> tampered=MALICIOUS_INDICATORS_FOUND` |
| `mut-16-no-semi-opt-chain-and-prov-purl-strict` | PASS | `asi=VERIFIED_CLEAN_WITHIN_SCOPE->MALICIOUS_INDICATORS_FOUND, nonPurl=verification_failed, wrongVer=verification_failed` |
| `mut-17-scoped-shadow-vs-closure-taint` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> MALICIOUS_INDICATORS_FOUND` |
| `mut-18-unicode-regex-vs-dense-escape-obfuscation` | PASS | `VERIFIED_CLEAN_WITHIN_SCOPE -> QUARANTINE_SUSPICIOUS` |

## Findings and Observations

<details>
<summary>Show observed coverage limits and non-blocking notes</summary>

- **INFO** TIER3/not_run: Live multi-agent sandbox runs (token uplift & model trajectory scoring) were not executed in this offline local run.
- **INFO** ENGINE/rea_absent: External `rea-agents` MCP/CLI binary is not installed on this host; `adv-10-uninspected-wasm-fail-closed` properly fails closed to `UNVERIFIABLE_UNKNOWN`.
- **INFO** SIGNING/local_dev_key: Local `skill.oms.sig` uses an explicit `local-dev-self-signed` ECDSA P-256 key; production distribution should swap to CI Sigstore Fulcio keyless OIDC.

</details>

## Scoring Methodology

<details>
<summary>Show dimension definitions, thresholds, and anti-fabrication rules</summary>

| Dimension | Question | Target Threshold |
|---|---|---|
| Security (Recall) | Are malicious/adversarial/fail-closed fixtures caught deterministically? | `>= 95%` (PASS) |
| Security (FPR) | Are legitimate CLIs (including TypeScript, regexes, short names, comments) spared? | `< 5%` (PASS) |
| Correctness (Mutation) | Do perturbed attacks reliably turn green checks red? | `100%` (PASS) |
| Discoverability | Are positive prompts matched and unrelated decoys rejected? | `>= 90%` (PASS) |
| Efficiency | Does Split-Plane SQLite caching reduce repeated Git history scan time? | Warm `< Cold` (PASS) |

- `N/A` indicates that live multi-agent trajectory counters were not executed; coverage and token deltas are never estimated or fabricated.

</details>

## Freshness

Regenerate this benchmark via `npm run bench` whenever `src/`, `skill-src/`, `rules/`, `evals/evals.json`, or `tests/selection.jsonl` changes.
