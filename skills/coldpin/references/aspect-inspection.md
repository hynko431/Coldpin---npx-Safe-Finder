---
last_reviewed: 2026-11-21
review_by: 2027-02-21
status: current
owner_lens: aspect-inspection
sources: Coldpin runtime-contract.yaml; Threat Taxonomy; Evidence Card Spec
---

# Aspect Playbook: Cold Artifact Malware Triage & Tarball-to-Git Parity

## Scope
Used when inspecting an npm package specifier (`<pkg>[@<ver>]`) or root-confined local `.tgz` tarball cold in memory, with optional local Git parity verification.

## Primary Tools & Resources
- MCP tools: `inspect_package_artifact` (`package_spec` XOR `tarball_path`, optional `git_dir`, `subdir`, `offline`, `detail: "summary" | "card" | "full"`, `format: "json" | "card" | "sarif" | "sbom"`) and `get_artifact_report` (`report_id`, `section`, `offset`, `limit`).
- MCP resource template: `coldpin://reports/{report_id}`.
- CLI equivalent: `coldpin inspect <pkg[@ver]> [--git-dir <repo>] [--json | --sarif | --sbom]`.

## Mandatory Procedure
1. **Zero Execution:** Never run `npm install`, `npm pack`, or `npx` to inspect an artifact. Use `inspect_package_artifact`, which validates SHA-512 integrity, unpacks tarballs strictly in memory, checks Zip-Slip/PAX/NTFS hazards, runs JS/TS lexical taint and lifecycle-hook triage, queries OSV/KEV, and verifies 3-tier tarball-to-Git parity.
2. **Start Compact, Page On Demand:** Default to `detail: "summary"` (`<= 6 KiB`). When `truncated` is true or deeper inspection is needed, slice `observations`, `iocs`, `unknowns`, `card`, `sarif`, or `sbom` via `get_artifact_report` using the returned `report_id`.
3. **Preserve Verdict & Provenance Boundaries:** Never downgrade Coldpin's deterministic 4-state `verdict` (`VERIFIED_CLEAN_WITHIN_SCOPE`, `QUARANTINE_SUSPICIOUS`, `MALICIOUS_INDICATORS_FOUND`, `UNVERIFIABLE_UNKNOWN`) and never rewrite `pinned_execution.command`. Report `PROVENANCE_METADATA_UNVERIFIED` and `PROVENANCE_UNANCHORED_DSSE` accurately (never claim Sigstore trust-root attestation unless verified externally).
4. **Escalate Obfuscated / Native Artifacts:** If `rea_escalation_plan` is emitted (native `.node`, WASM, ELF/PE/Mach-O, high-entropy obfuscation, or tarball-to-source drift), route to `coldpin-forensics` following [rea-integration-playbook.md](rea-integration-playbook.md).

## Output Contract
Emit the `Title + Info + Evidence` card ([evidence-card-spec.md](evidence-card-spec.md)) preserving Observations, Inferences, Unknowns, defanged IOCs, stock-`npx` transitive caveats, and explicit human confirmation requirement before any execution.
