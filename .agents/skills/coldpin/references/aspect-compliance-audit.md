---
last_reviewed: 2026-11-21
review_by: 2027-02-21
status: current
owner_lens: aspect-compliance-audit
sources: Coldpin runtime-contract.yaml; Enterprise Policy Schema; Evidence Card Spec
---

# Aspect Playbook: Policy Posture, Audit-Trail Verification & Regulatory Evidence

## Scope
Used when verifying operator policy posture, auditing hash-chained `audit.jsonl` logs for tampering or sequence gaps, and compiling CycloneDX 1.5 SBOM + VEX, SARIF 2.1.0, or regulatory compliance artifacts.

## Primary Tools & Resources
- MCP tools: `audit_verify` (`audit_log_path` — strictly read-only, root-confined) and `get_artifact_report` (`report_id`, `section: "sarif" | "sbom" | "card" | "observations"`).
- MCP resource: `coldpin://policy/active` (sanitized active policy, `policy_sha256`, authorized root count, host capabilities — zero secrets).
- Deep references: [enterprise-policy-schema.md](enterprise-policy-schema.md) and [evidence-card-spec.md](evidence-card-spec.md).
- CLI equivalent: `coldpin audit-verify <path/to/audit.jsonl> --json`.

## Mandatory Procedure
1. **Inspect Active Policy Posture:** Read `coldpin://policy/active` and confirm `policy_sha256`, `offline_mode`, `private_scopes`, `private_prefixes`, `blocked_licenses`, `block_on_kev`, `block_on_critical_cve`, and `cooldown_hours`. Verify operator-only control plane invariants (`COLDPIN_POLICY_PATH`, `COLDPIN_ALLOWED_ROOTS`, `COLDPIN_AUDIT_LOG` never writable via LLM args).
2. **Verify Local Hash-Chained Audit Trail:** Call `audit_verify` on the root-confined `audit.jsonl` path. Report exact `valid`, `total_events`, and any `broken_at_seq` or `reason`. Note explicitly that local hash chains detect post-hoc edits on disk while enterprise non-repudiation requires shipping logs off-host to WORM storage.
3. **Compile Structured Compliance Outputs:** Page `sarif` (SARIF 2.1.0) or `sbom` (CycloneDX 1.5 + VEX) via `get_artifact_report` for CI/GRC ingestion, ensuring zero secrets or raw PII enter reports (use pseudonymous `actor_id_hash`).
4. **Map Jurisdiction Clocks (Default Routing):** Present India DPDP Act 2023 + CERT-In (`6 h`), EU CRA / NIS2 (`24 h` / `72 h`) & GDPR Art. 33 (`72 h`), and US NIST SSDF / SOC 2 / ISO 27001 controls transparently labeled for counsel confirmation.

## Output Contract
Return policy summary (`policy_sha256`, active guardrails), `audit.jsonl` chain verification verdict, SBOM/SARIF readiness status, and compliance evidence checklist (with engineering-guidance disclaimer).
