<!-- SPDX-License-Identifier: Apache-2.0 -->

# Security Policy (`SECURITY.md`)

## Supported Versions

| Version | Supported |
|---|---|
| `1.2.x` | Yes (active maintenance) |
| `1.1.x` | Security fixes via upgrade to `1.2.x` |
| `1.0.x` | Security fixes via upgrade to `1.2.x` |

## Reporting a Vulnerability

If you discover a security bypass in `coldpin` (for example: an archive extraction escape, a static taint evasion, a Git argument injection, a private-scope leak, or a skill prompt-injection bypass):

1. **Do not** open a public issue containing weaponized exploit chains or live malicious package URLs.
2. Submit a confidential report via [GitHub Private Vulnerability Reporting](https://github.com/hynko431/Coldpin---npx-Safe-Finder/security/advisories/new).
3. Provide a minimal, defensive reproduction (synthetic fixture tarball, redacted CLI command, expected verdict vs. observed verdict).
4. Include your Node.js version (`node --version`), OS, and commit SHA.
5. Maintainer triage target: acknowledge within 2 business days `[Typical]`, deliver a regression test + fix before disclosure.

## Hard Security Boundaries of `coldpin`

- **Zero-Execution Inspection:** `coldpin` never runs `npm install`, `npm pack`, package lifecycle hooks, or untrusted package binaries during inspection.
- **No Self-Bootstrap:** `coldpin` never executes `npx -y rea-agents` or installs third-party analyzers silently.
- **Deterministic Verdict Authority:** The 4-state `TrustVerdict` is computed deterministically in TypeScript code outside LLM context; untrusted `README.md` or metadata strings cannot override verdicts.
- **Static Coverage Bounds:** Static analysis cannot observe runtime-only remote C2 payloads; compiled native/WASM artifacts and obfuscated bundles fail closed until inspected with REA or isolated dynamic analysis.

*Engineering guidance, not legal, medical or financial advice; confirm decisions with qualified counsel.*
