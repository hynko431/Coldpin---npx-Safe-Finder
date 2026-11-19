<!-- SPDX-License-Identifier: Apache-2.0 -->

# Data Handling & Privacy Notice (`coldpin`)

`coldpin` is a local Node.js CLI and agent skill package. It does not operate a hosted backend service, telemetry endpoint, analytics collector, or external database. It requires no separate `coldpin` account or license key.

## Local Inputs and Outputs

- **Inputs read locally:** CLI arguments, workspace `.npmrc` and `.coldpin.policy.json` (or legacy `.npx-guard.policy.json`), local `package.json` / `package-lock.json` (when running `verify-confusion` or workspace compromise checks), local tarballs (`--tarball`), and local Git directories (`--git-dir`).
- **Local persistence:**
  - Split-Plane SQLite cache (`%LOCALAPPDATA%\coldpin\cache.sqlite` on Windows or `~/.cache/coldpin/cache.sqlite` on POSIX, with temp/in-memory fallback) storing structural static observations and TTL-bounded OSV advisory payloads.
  - Optional local append-only `audit.jsonl` (only written when `--audit-log <file>` is explicitly passed), storing a SHA-256 pseudonymous `actor_id_hash` instead of raw usernames or emails.
- **No automatic retention enforcement locally:** Local cache and audit files remain on disk until deleted or shipped to an enterprise WORM log archive by the user or organization.

## Outbound Network Egress & Private-Scope Isolation

- **Offline mode (`--offline`):** Performs zero outbound network requests and fails closed (`UNVERIFIABLE_UNKNOWN`) when live threat intelligence is unavailable.
- **Public package inspection (online):** Contacts the configured npm registry (`https://registry.npmjs.org` by default) to retrieve package metadata and tarballs, `https://api.osv.dev` for OSV/OpenSSF `MAL-*` advisories, and the declared Git remote only when `resolve-anchor` is invoked with a remote URL.
- **Private-scope non-leakage guarantee:** Any package matching `private_scopes`, `private_prefixes`, or private `.npmrc` scoped registries NEVER queries public `registry.npmjs.org` or `api.osv.dev`. Scopes within 1 edit or adjacent transposition of a configured private scope (`@amce` vs `@acme`) are hard-blocked (`blocked_typo`) before any network request is made.
- **Secrets handling:** Registry authentication tokens (`_authToken=${ENV_VAR}` in `.npmrc`) are read strictly from process environment variables, sent only over HTTPS to their matching private registry host, and never written to stdout, stderr, SQLite cache, SARIF, SBOM, audit logs, or LLM prompt context.

## Host Agent Processing

When invoked through an AI agent harness (Antigravity, Claude Code, Codex), the selected host processes prompts and CLI outputs under that host's own account terms and privacy policy. `coldpin` registers no MCP server, installs no automatic permission-approval hook, and runs no untrusted package scripts.

*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
