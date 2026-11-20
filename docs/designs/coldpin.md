# `coldpin` (Coldpin) — Locked Design Specification (v1.2)

* **Author:** hynko431
* **Status:** Approved (Phase 0 Goldfish Blockers Resolved + v1.2 Round 2 Security & Provenance Hardening)
* **Date:** 2026-11-20

---

## Overview

`coldpin` (**Coldpin**) is a local-first enterprise Antigravity skill and zero-dependency Node 24 TypeScript CLI for safe `npx` tool discovery, zero-execution artifact inspection, tarball-to-source parity checking, and pre-compromise safe-anchor recovery.

## Locked Decisions (Post-Goldfish Review)

1. **Runtime & Dependencies:** Pure **Node >= 24.0.0** ESM with native TypeScript type-stripping (`erasableSyntaxOnly`), `node:sqlite`, `node:zlib`, `node:crypto`, `node:module` (`stripTypeScriptTypes`), `node:test`, and `fetch`. Zero external runtime npm dependencies; zero external Python dependencies for governance scripts (`scripts/*.py`).
2. **In-Memory Zero-Execution Quarantine:** `.tgz` archives are fetched via HTTPS, verified against `dist.integrity` SHA-512, gunzipped through a streaming byte-cap transform (`50 MiB` uncompressed / `20 MiB` compressed / `5,000` files / `10 MiB` max text-file parse cap), and parsed strictly in memory. Zip-Slip (`..`), leading `/` or `\`, Windows drive prefixes (`C:`), NTFS Alternate Data Streams (`:`), Windows reserved device names (`CON`, `NUL`, `AUX`, `PRN`, `COM1-9`, `LPT1-9`), symlinks, hardlinks, FIFOs, duplicate tar entries, and case-insensitive NTFS filename collisions are rejected deterministically.
3. **Provenance-Aware Tarball-vs-Source Parity (Epistemically Honest):**
   - **Gold (`PROVENANCE_ATTESTED`):** Reserved strictly for cryptographically verified Sigstore/SLSA provenance (`provenance_status: "sigstore_verified"`, `provenance_attested: true`).
   - **Unanchored / Metadata-Only (`PROVENANCE_UNANCHORED_DSSE` / `PROVENANCE_METADATA_UNVERIFIED`):** Distinguishes advertised `dist.attestations.url` metadata and locally verified leaf-cert DSSE + subject SHA-512 + strict npm PURL package/version checks from full Sigstore Fulcio CA + Rekor TUF root verification (`provenance_attested: false`, explicit trust-boundary unknowns, private-scope off-origin suppression, fails closed under `require_provenance: true` in both `inspect` and `resolve-anchor`; tampered digests, missing/mismatched PURLs, or invalid DSSE signatures emit `CRITICAL` `PROVENANCE_DIGEST_MISMATCH` / `PROVENANCE_DSSE_SIGNATURE_INVALID`).
   - **Silver (`MANIFEST_PARITY_VERIFIED`):** `package.json` `scripts`, `bin`, `dependencies`, and `optionalDependencies` match `gitHead` `package.json`.
   - **Bronze (`COMPILED_DIST_UNATTESTED`):** Compiled `dist/` outputs absent from Git are allowed when build config exists in `gitHead` and no AST taint sinks, obfuscation, or lifecycle-hook drift appear; unexplained script/entrypoint drift triggers `TARBALL_SOURCE_DRIFT`.
4. **Split-Plane SQLite Cache (`WAL` + `busy_timeout = 5000`):**
   - `artifact_facts`: immutable 5-tuple key `sha256(content_sha | ruleset_sha256 | engine_version | options_canonical | schema_version)` storing static byte observations only.
   - `threat_intel_cache`: mutable TTL-bounded OSV/OpenSSF `MAL-*`/KEV state.
   - 4-state `TrustVerdict` is recomputed dynamically on every query from `(Immutable Facts + Current Threat Plane + Active Policy)`.
5. **Canonical 5-Verb CLI & Contract Surface (Aligned Across `src/cli.ts`, `SKILL.md`, `assets/runtime-contract.yaml`):**
   - `discover` (`discover_packages`)
   - `inspect` (`inspect_package_artifact`)
   - `resolve-anchor` (`resolve_safe_anchor`)
   - `verify-confusion` (`verify_confusion`)
   - `audit-verify` (`audit_verify`)
6. **Deterministic Verdict & Exit Codes:**
   - `0`: `VERIFIED_CLEAN_WITHIN_SCOPE` (or verification passed)
   - `2`: `QUARANTINE_SUSPICIOUS` or `UNVERIFIABLE_UNKNOWN`
   - `3`: `MALICIOUS_INDICATORS_FOUND` (or policy/confusion/audit integrity failure)
   - `1`: CLI usage or unexpected runtime error
7. **Honest Pinned Execution & No Self-Bootstrap Paradox:**
   - Stock `npx` cannot enforce `--integrity <sha512>` or lock floating transitive dependencies; the card always outputs `npx --yes --ignore-scripts --package=<pkg>@<ver> -- <bin>` paired with verified `dist.integrity` SHA-512, explicit transitive pinning caveats, and a pre-execution verification note.
   - `ROLLBACK_TO_SAFE_ANCHOR` requires a verified npm release tarball (`tarball_sha512`) passing OSV/KEV gates; commits without a verified tarball emit `FORENSIC_COMMIT_ONLY` and recommend `SWITCH_TO_ALTERNATIVE`.
   - `rea-agents` is strictly an optional pre-registered MCP server or pre-installed `rea` binary—never fetched via `npx -y`.
8. **Prompt-Injection Isolation:** `TrustVerdict`, `Title + Info + Evidence` cards, defanged IOCs, SARIF 2.1.0, and CycloneDX SBOM JSON are generated deterministically by TypeScript code; untrusted metadata strings are sanitized (control chars, hidden/bidi Unicode stripped) and bounded before presentation.

## SQLite Cache Schema (`src/cache/sqlite-store.ts`)

```sql
PRAGMA journal_mode = WAL;
PRAGMA busy_timeout = 5000;
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS artifact_facts (
  cache_key TEXT PRIMARY KEY,
  content_sha TEXT NOT NULL,
  ruleset_sha256 TEXT NOT NULL,
  engine_version TEXT NOT NULL,
  facts_json TEXT NOT NULL,
  created_at_utc TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS threat_intel_cache (
  intel_key TEXT PRIMARY KEY,
  source TEXT NOT NULL,
  payload_json TEXT NOT NULL,
  fetched_at_ms INTEGER NOT NULL,
  expires_at_ms INTEGER NOT NULL
);
```

*Drafted with EGM*
