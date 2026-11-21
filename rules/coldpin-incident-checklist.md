---
trigger: model_decision
description: Apply immediately when Coldpin flags MALICIOUS_INDICATORS_FOUND, local_workspace_compromised, lockfile exposure, or suspected npm supply-chain compromise.
---

# Coldpin Incident Containment & Recovery Checklist

When Coldpin emits `MALICIOUS_INDICATORS_FOUND`, `local_workspace_compromised`, tampered SLSA provenance, or suspected supply-chain compromise:

1. **Halt Execution Immediately:** Do not run `npm install`, `npx`, or any package binary from the affected package or lockfile. Keep all extracted IOCs strictly defanged (`hxxp://`, `[.]`).
2. **Locate Clean Anchor or Alternative:** Delegate to `coldpin-forensics` (or invoke `/coldpin-incident`) and run `resolve_safe_anchor` against the package's Git history (`--first-parent`) to identify the patient-zero compromise commit and select either a verified `ROLLBACK_TO_SAFE_ANCHOR` release or `SWITCH_TO_ALTERNATIVE`.
3. **Isolate Lockfiles & Capture Forensic Evidence:** Preserve hashes of `package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`, and any local Coldpin `audit.jsonl` logs (verify chain integrity via `coldpin-compliance` / `audit_verify`) before cleaning `node_modules/`.
4. **Rotate Credentials & Check Host Persistence:** Assume any credential readable by the developer shell or CI runner during a prior install was exposed; rotate npm, GitHub, cloud, and API tokens immediately and ask host IR/EDR teams to review shell startup profiles, scheduled tasks, and OS launch entries alongside `catalog/sigma/` detections.
5. **Track Regulatory Notification Clocks (Verify With Counsel):**
   - **India CERT-In Directions (2022-04-28):** `6 hours` for reportable cyber incidents.
   - **EU NIS2 / EU CRA:** `24 hours` early warning, `72 hours` incident notification.
   - **EU GDPR Art. 33:** `72 hours` for personal data breaches.
6. **Escalate Obfuscated / Native Artifacts Safely:** If `rea_escalation_plan` is present, hand off only to a pre-installed or pre-registered `rea` / `rea-agents` tool—never bootstrap `rea-agents` over `npx`.
