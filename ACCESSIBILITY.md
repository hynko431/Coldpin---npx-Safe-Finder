<!-- SPDX-License-Identifier: Apache-2.0 -->

# Accessibility Statement (`ACCESSIBILITY.md`)

`coldpin` aims to keep CLI outputs, Evidence Cards, documentation, and bundled SVG assets accessible across terminals, screen readers, and AI coding harnesses.

## Implemented Practices

- **No Color-Only Signalling:** CLI verdicts (`VERIFIED_CLEAN_WITHIN_SCOPE`, `QUARANTINE_SUSPICIOUS`, `MALICIOUS_INDICATORS_FOUND`, `UNVERIFIABLE_UNKNOWN`) and exit codes (`0`, `1`, `2`, `3`) are conveyed via explicit text labels and machine-readable JSON/SARIF/SBOM fields, never via ANSI color alone.
- **Plain Structured Markdown:** `Title + Info + Evidence` cards use semantic headings (`#`, `##`, `###`), structured tables with escaped pipe characters, and plain bullet lists compatible with screen readers and Braille displays.
- **Icon Alternatives:** Bundled SVG assets (`assets/icon.svg`, `docs/assets/readme-header.svg`) carry explicit `alt` text in `README.md` or decorative empty `alt=""` when paired with adjacent text labels.
- **Deterministic Non-Interactive CLI:** All 5 CLI verbs work non-interactively via flags and stdin/stdout without requiring TUI cursor navigation or mouse input.

## Known Limits

- Output accessibility inside third-party AI agent harnesses (Antigravity, Claude Code, Codex CLI) depends in part on each host's own terminal or IDE UI rendering.
- Report any accessibility barrier by opening an issue describing the assistive technology, harness, and affected command or document.
