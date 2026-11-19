#!/usr/bin/env python3
"""Deep Enterprise Skill Hygiene, Reference, & URL Allow-List Validator
(Enterprise Commons `tools/verify.py` parity).

Checks across skill-src/coldpin/ and docs/:
1. Zero UTF-8 BOM, zero hidden/bidi/Tag Unicode, zero ASCII control chars.
2. Zero embedded prompt-injection or exploit-payload strings inside operational docs.
3. Zero hardcoded secrets / credentialed URIs.
4. Every backticked *.md path resolves cleanly.
5. Reference files carry `last_reviewed:`, `review_by:`, and `status:`.
6. Every referenced URL host appears in docs/fact-ledger.md allow-list.
"""

import datetime
import re
import sys
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
SKILL_DIR = ROOT / "skill-src" / "coldpin"
TODAY = datetime.date.today()

HIDDEN_RE = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\U000e0000-\U000e007f]")
CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
INJECT_RE = re.compile(
    r"ignore (all |any )?(previous|prior|above) (instructions|prompts)"
    r"|disregard (the )?(system|previous) (prompt|instructions)"
    r"|you are now (dan|in developer mode)"
    r"|reveal (your|the) system prompt",
    re.I,
)
SECRET_RE = re.compile(
    r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    r"|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{25,}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|\bAIza[0-9A-Za-z_-]{33,}"
)
PAYLOAD_RE = re.compile(r"msfvenom|(\\x90){6,}|shellcode\s*=\s*b?[\"']\\x", re.I)
MDREF_RE = re.compile(r"`([\w./\-]+\.md)`")
URL_RE = re.compile(r"https?://([\w.\-]+)")


def resolve_md_ref(source_file: Path, ref: str) -> bool:
    if ref in (
        "SKILL.md",
        "README.md",
        "CHANGELOG.md",
        "BENCHMARK.md",
        "TESTING.md",
        "TEST.md",
        "MAINTENANCE.md",
        "SITEMAP.md",
        "SECURITY.md",
        "CONTRIBUTING.md",
        "ACCESSIBILITY.md",
    ):
        return True
    candidates = [
        source_file.parent / ref,
        SKILL_DIR / ref,
        SKILL_DIR / "references" / ref,
        ROOT / ref,
        ROOT / "docs" / ref,
        ROOT / "docs" / "designs" / ref,
    ]
    return any(c.resolve().exists() for c in candidates)


def main() -> int:
    errors: list[str] = []
    warnings: list[str] = []
    hosts: dict[str, set[str]] = {}

    files_to_check: list[tuple[Path, bool]] = [
        (SKILL_DIR / "SKILL.md", False),
        (SKILL_DIR / "skill-card.md", False),
        (SKILL_DIR / "TEST.md", False),
        (ROOT / "README.md", False),
        (ROOT / "TESTING.md", False),
        (ROOT / "SECURITY.md", False),
        (ROOT / "CONTRIBUTING.md", False),
        (ROOT / "ACCESSIBILITY.md", False),
        (ROOT / "MAINTENANCE.md", True),
        (ROOT / "docs" / "fact-ledger.md", True),
        (ROOT / "docs" / "getting_started.md", False),
        (ROOT / "docs" / "harnesses.md", False),
        (ROOT / "docs" / "privacy.md", False),
        (ROOT / "docs" / "faq.md", False),
        (ROOT / "docs" / "designs" / "coldpin.md", False),
    ]
    for ref in sorted((SKILL_DIR / "references").glob("*.md")):
        files_to_check.append((ref, True))

    for fpath, require_ref_meta in files_to_check:
        if not fpath.exists():
            errors.append(f"Missing expected doc: {fpath.relative_to(ROOT).as_posix()}")
            continue
        rel = fpath.relative_to(ROOT).as_posix()
        raw = fpath.read_bytes()
        if raw.startswith(b"\xef\xbb\xbf"):
            errors.append(f"{rel}: UTF-8 BOM present")
        txt = raw.decode("utf-8")
        if HIDDEN_RE.search(txt):
            errors.append(f"{rel}: hidden/bidi/Tag Unicode present")
        if CTRL_RE.search(txt):
            errors.append(f"{rel}: ASCII control characters present")
        if INJECT_RE.search(txt):
            errors.append(f"{rel}: embedded prompt-injection phrase present")
        if SECRET_RE.search(txt):
            errors.append(f"{rel}: secret-like token present")
        if PAYLOAD_RE.search(txt):
            errors.append(f"{rel}: exploit-payload pattern present")

        for m in MDREF_RE.finditer(txt):
            ref_str = m.group(1)
            if not resolve_md_ref(fpath, ref_str):
                errors.append(f"{rel}: unresolved backticked markdown reference `{ref_str}`")

        for m in URL_RE.finditer(txt):
            hosts.setdefault(m.group(1).lower(), set()).add(rel)

        if require_ref_meta:
            head = txt.replace("\r\n", "\n")[:1200]
            for field in ("last_reviewed:", "review_by:", "status:"):
                if field not in head:
                    errors.append(f"{rel}: missing required metadata '{field}'")
            rm = re.search(r"review_by:\s*(\d{4}-\d{2}-\d{2})", head)
            if rm and datetime.date.fromisoformat(rm.group(1)) < TODAY:
                warnings.append(f"{rel}: STALE review_by {rm.group(1)}")

    ledger_txt = (ROOT / "docs" / "fact-ledger.md").read_text(encoding="utf-8").lower()
    unlisted_hosts = sorted(h for h in hosts if h not in ledger_txt and not h.startswith("<"))
    if unlisted_hosts:
        for h in unlisted_hosts:
            errors.append(f"URL host '{h}' not listed in docs/fact-ledger.md allow-list (used in {sorted(hosts[h])[:2]})")

    desc_txt = (SKILL_DIR / "SKILL.md").read_text(encoding="utf-8")
    dm = re.search(r"description:\s*(?:>-?\s*)?(.*?)\n(?:[a-z_-]+:|---)", desc_txt, re.S)
    desc_len = len(" ".join(dm.group(1).split())) if dm else 0

    print(
        f"Hygiene audit: {len(files_to_check)} docs checked | URL hosts: {len(hosts)} "
        f"(unlisted: {len(unlisted_hosts)}) | SKILL.md description: {desc_len} chars"
    )
    if warnings:
        for w in warnings:
            print(f"  WARN: {w}")
    if errors:
        print("VERIFY HYGIENE FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1
    print("VERIFY HYGIENE OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
