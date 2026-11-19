---
last_reviewed: 2026-11-19
review_by: 2027-02-19
status: current
owner_lens: rea-integration
sources: morluto/rea SKILL.md; references/javascript-applications.md; references/evidence-workflows.md
---

# REA Tier-2 Forensic Escalation Playbook

## 1. When to Escalate from Tier 1 to REA

Escalate to REA (`rea-agents`) only when `coldpin inspect` reports one of:
- `OBFUSCATED_CODE_UNRECOVERED` (`has_obfuscation: true`)
- `REA_DEEP_FORENSICS_REQUIRED` (`has_native_or_wasm: true` — `.node`, `.wasm`, ELF, PE, Mach-O)
- `TARBALL_SOURCE_DRIFT_*` where comparing the compromised release against the prior clean release requires structural/semantic diffing resilient to minification.

## 2. Hard Bootstrap & Safety Boundary

- **NEVER run `npx -y rea-agents@latest`** to bootstrap REA dynamically; doing so reintroduces unpinned `npx` execution during a security investigation.
- Check `host_capabilities.rea_cli_available` in the CLI JSON output or inspect live MCP tools (`tools/list`) in the active agent session.
- If neither REA MCP nor a pre-installed `rea` binary is available, **do not downgrade the verdict to clean**; keep the CLI's `QUARANTINE_SUSPICIOUS` or `UNVERIFIABLE_UNKNOWN` verdict and explicitly report `REA_UNAVAILABLE_ON_HOST` in the unknowns list.

## 3. Summary-First REA Tool Routing (When Available)

| Observed Tier-1 Signal | REA Tool | Epistemic Rules |
|---|---|---|
| Bundled or minified JavaScript tree | `analyze_javascript_application` (`detail: "summary"`) -> `inspect_analysis_view` module pages -> `trace_application_feature` on suspicious seeds | Cite `parent_evidence_id` and exact `node_id`; do not treat static syntax observations as proven runtime reachability. |
| Heavily obfuscated bundle (Linux x64 with Wakaru) | `recover_javascript_sources` -> `analyze_javascript_application` | Inputs and recovered code are never executed; record `OBFUSCATED_UNRECOVERED` on non-Linux hosts without Wakaru. |
| Compromised release vs. candidate clean anchor | `compare_application_versions` | Accept only digest, source-map, structural fingerprint, or non-module semantic matches; report `added`/`removed` only with complete opposite-side coverage. |
| Embedded `.wasm` artifact | `inspect_wasm_artifact` (requires `REA_WABT_BIN_DIRECTORY`) | WAT is not original source; preserve byte digest and glue ambiguity. |
| Bundled Go CLI binary | `inspect_go_binary` (built-in) | Preserve raw module bytes and source ranges. |
| Bundled Rust CLI binary | `inspect_rust_binary` (built-in) | Missing `.dep-v0` is null metadata, not proof of zero dependencies. |
| Native `.node` / PE / ELF / Archive | `open_binary` -> `inspect_artifact` / `inspect_pe_resources` / `inspect_binary_layout` -> `close_binary` | Always call `close_binary` on completion; never leave orphaned sessions. |
