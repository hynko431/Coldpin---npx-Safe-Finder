---
trigger: glob
globs: "package.json, **/package.json, package-lock.json, **/package-lock.json, pnpm-lock.yaml, **/pnpm-lock.yaml, yarn.lock, **/yarn.lock, .npmrc, **/.npmrc, mcp_config.json, **/mcp_config.json"
description: Enforce Coldpin dependency screening, private-scope isolation, and pinned script-disabled execution whenever manifests, lockfiles, .npmrc, or MCP configs are inspected or edited.
---

# Coldpin Manifest, Lockfile & Config Guard

Whenever inspecting, adding, upgrading, or editing `package.json`, lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `yarn.lock`), `.npmrc`, or `mcp_config.json`:

1. **Batch Screen Direct Dependencies:** Call `audit_manifest_batch` (or delegate to `coldpin-manifest-auditor`) to screen up to 50 direct dependencies for typosquatting, policy violations, private-scope leaks, and OSV/OpenSSF `MAL-*` or CISA KEV advisories before running any package manager install.
2. **Audit Dependency Confusion (`T1195.001`):** Call `verify_confusion` (or delegate to `coldpin-confusion-auditor`) whenever `.npmrc` or internal package prefixes are present. Never forward private scopes to public `registry.npmjs.org` or `api.osv.dev`, and never read workspace `.npmrc` `:_authToken` directives as trusted credentials.
3. **Require Exact Pins & `--ignore-scripts`:** Reject floating ranges (`latest`, `next`, `*`) for untrusted CLI tools. Require `--ignore-scripts` and exact `X.Y.Z` versions for any newly recommended execution command, and escalate obfuscated or native artifacts to `coldpin-inspector`.
4. **Protect MCP & Plugin Configs:** Never place secret tokens or Antigravity `variables` inside CLI `args` or URL query strings in `mcp_config.json`; pass credentials strictly via `env` or HTTPS `headers`, and require explicit human approval before modifying security configuration files.
