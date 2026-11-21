---
last_reviewed: 2026-11-21
review_by: 2027-02-21
status: current
owner_lens: aspect-manifest-confusion
sources: Coldpin runtime-contract.yaml; MITRE ATT&CK v19.1 (T1195.001, T1195.002)
---

# Aspect Playbook: Manifest Batch Screening & Dependency Confusion Audit

## Scope
Used when screening workspace `package.json`, lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`), and `.npmrc` configurations for malicious/squatted dependencies, policy violations, and dependency confusion (`T1195.001`).

## Primary Tools & Resources
- MCP tools: `audit_manifest_batch` (`manifest_path`, `include_dev`, `max_deps <= 50`, `offline`, `detail: "summary" | "full"`), `verify_confusion` (`manifest_path`, `check_public`), and `get_artifact_report`.
- MCP resource: `coldpin://policy/active`.
- CLI equivalents: `coldpin audit-batch [package.json] --json` and `coldpin verify-confusion [package.json] --json`.

## Mandatory Procedure
1. **Batch Screen Direct Dependencies:** Call `audit_manifest_batch` to evaluate up to `50` direct dependencies deterministically (org allow/deny policy, 7-primitive squat screening, private-scope routing, and route-separated batch OSV/OpenSSF `MAL-*`/KEV checks). Note whether `truncated_at_cap` is true.
2. **Page Flagged Findings:** Use `get_artifact_report(report_id, "observations")` to retrieve the full flagged list when `counts.flagged > 0`, and escalate any `MALICIOUS_OR_BLOCKED` or `FLAGGED_SUSPICIOUS` package to `inspect_package_artifact` (`coldpin-inspector`).
3. **Audit `.npmrc` & Private Scopes (`T1195.001`):** Call `verify_confusion` against the root-confined manifest. Flag any private scope lacking an explicit `@scope:registry=` pin, any unscoped internal prefix exposed to public npm shadowing, and any 1-edit typo of a configured private scope. Keep `check_public: false` unless explicitly authorized by operator environment (`COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE=1`).
4. **Strict Zero-Leak Rule:** Never query public `registry.npmjs.org` or `api.osv.dev` for private or policy-denied packages, and never treat workspace `.npmrc` `:_authToken` directives as trusted auth tokens.

## Output Contract
Return manifest counts (`total_declared`, `evaluated_count`, `malicious_or_blocked`, `flagged_suspicious`, `clean_screened`), dependency-confusion findings (`T1195.001`), lockfile exposure notes, and concrete remediation steps (exact `@scope:registry` pins and `--ignore-scripts`).
