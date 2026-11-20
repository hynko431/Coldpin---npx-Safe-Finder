---
last_reviewed: 2026-11-20
review_by: 2027-02-20
status: current
owner_lens: evidence-card-spec
sources: SARIF 2.1.0; CycloneDX 1.5; CISA TLP 2.0
---

# Evidence Card, Verdict Matrix & Output Specifications

## 1. Deterministic 4-State Verdict Truth Table

Computed strictly inside `src/verdict/engine-and-formatters.ts` (never overridden by LLM narration):

| Priority | Verdict | Exit Code | Trigger Condition |
|---:|---|---:|---|
| 1 | `MALICIOUS_INDICATORS_FOUND` | `3` | Any OpenSSF `MAL-*` advisory OR any `CRITICAL` observation (`TARBALL_INTEGRITY_MISMATCH`, archive escape/symlink/duplicate-entry/EOF-polyglot, dangerous lifecycle script, credential-to-network/exec taint, bulk `process.env` serialization, suspicious Base64/Hex payload, shady webhook/raw IP, computed/Unicode `eval`, `data:` dynamic `import()`, tarball source drift, tampered SLSA provenance digest/DSSE signature, critical typosquat). |
| 2 | `QUARANTINE_SUSPICIOUS` | `2` | Any `HIGH` observation (hidden/bidi Unicode, prompt-injection signal, high-entropy obfuscation, computed dynamic `import(expr)`, indirect/aliased `eval`/`vm`, credential file access, case collision, decompression cap bomb, young slopsquat with hooks), any benign `LIFECYCLE_HOOK_PRESENT`, release `< cooldown_hours`, or policy block (banned org/license, KEV, Critical/High CVE). |
| 3 | `UNVERIFIABLE_UNKNOWN` | `2` | Unpack failure or cap halt, skipped oversized file or missing/corrupt manifest, uninspected native `.node`/WASM/ELF/PE/Mach-O artifact, strict `require_provenance` policy without Sigstore trust-root verification (`metadata_url_only` and `dsse_leaf_verified_unanchored` fail closed), strict `require_source_link` on `SOURCE_UNLINKED`, or `--offline`/unavailable OSV threat intel. |
| 4 | `VERIFIED_CLEAN_WITHIN_SCOPE` | `0` | None of the above triggers fired within stated static inspection coverage. |

## 2. Standard Output Modes

- **Default (Markdown):** Deterministic `Title + Info + Evidence` card with Observations, Inferences, Unknowns, structured `REA Tier-2 Escalation Plan` (when obfuscation, binaries, or drift appear), Defanged IOCs (`hxxp://`, `[.]` with `TLP:CLEAR` / `TLP:AMBER`), Pinned Execution Command (with honest stock-`npx` transitive caveat), and Local Workspace Containment Card when `package-lock.json`, `pnpm-lock.yaml`, or `yarn.lock` matches a malicious package.
- **`--json`:** Canonical typed JSON matching `assets/runtime-contract.yaml`.
- **`--sarif`:** SARIF 2.1.0 JSON compatible with GitHub Code Scanning.
- **`--sbom`:** CycloneDX 1.5 JSON SBOM + VEX (`serialNumber`, `metadata.component`, `dependencies[]`, `vulnerabilities[]` with `analysis.state`, `purl`, SHA-512 hash, license, verdict, and parity properties).
