---
last_reviewed: 2026-11-21
review_by: 2027-02-21
status: current
owner_lens: aspect-forensics-rea
sources: Coldpin runtime-contract.yaml; REA Integration Playbook; Enterprise Policy Schema
---

# Aspect Playbook: Compromise Forensics, Safe Anchor Recovery & REA Escalation

## Scope
Used when an artifact or organization is flagged as `MALICIOUS_INDICATORS_FOUND`, `QUARANTINE_SUSPICIOUS` (obfuscated/native/drifted), or `local_workspace_compromised`, requiring patient-zero bisect, pre-compromise rollback selection, or Tier-2 binary/deobfuscation escalation.

## Primary Tools & References
- MCP tools: `resolve_safe_anchor` (`package_name`, `git_dir` or `repo_url`, `subdir`, `window <= 200`, `detail`), `inspect_package_artifact`, and `get_artifact_report`.
- Deep references: [rea-integration-playbook.md](rea-integration-playbook.md) and [enterprise-policy-schema.md](enterprise-policy-schema.md).
- CLI equivalent: `coldpin resolve-anchor <pkg> [--git-dir <repo> | --repo-url <url>] [--window 200] --json`.

## Mandatory Procedure
1. **Bisect Compromise History:** Run `resolve_safe_anchor` to walk `--first-parent` Git history and cached release anchors (`SplitPlaneCache`) to locate the patient-zero commit and last clean ancestor.
2. **Enforce Strict Rollback Rules:** Emit `ROLLBACK_TO_SAFE_ANCHOR` ONLY when a verified npm tarball exists for the clean ancestor and passes CVE/KEV gates. Otherwise emit `FORENSIC_COMMIT_ONLY`, `SWITCH_TO_ALTERNATIVE`, or `BLOCK_NO_SAFE_PATH`. Never fabricate a clean version.
3. **Lockfile Containment & Credential Rotation:** If `local_workspace_compromised` matches any workspace lockfile, immediately surface containment steps: stop installs, preserve hashes, rotate exposed tokens, and review host EDR / `catalog/sigma/` alerts.
4. **REA Tier-2 Escalation Without Self-Bootstrap:** When `rea_escalation_plan` is present for obfuscated JS, native `.node`, WASM, or tarball-to-Git drift, follow [rea-integration-playbook.md](rea-integration-playbook.md). Invoke `rea` / `rea-agents` ONLY if pre-registered as an MCP server or pre-installed on `PATH`; never bootstrap `rea-agents` over `npx`.

## Output Contract
Return `recommended_action`, patient-zero commit/release evidence, verified clean anchor or vetted alternative, defanged IOCs, containment checklist, and regulatory clock reminders (CERT-In 6h, EU NIS2/CRA 24h/72h, GDPR 72h).
