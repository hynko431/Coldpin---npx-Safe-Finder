#!/usr/bin/env python3
"""Zero-dependency Enterprise Skill Linter & Hygiene Validator for Coldpin.

Checks:
1. SKILL.md budget (<= 220 lines, <= 24 KB) and valid YAML frontmatter (name, description).
2. Clean UTF-8 and zero hidden/bidirectional/tag Unicode (Trojan Source defense).
3. Shift-left secret & credential-URI scan across all text files in skill-src/ and src/.
4. Relative Markdown link resolution inside skill-src/coldpin/.
5. Reference files carry `last_reviewed:` and `review_by:` metadata.
6. Alignment between CLI verbs in runtime-contract.yaml and SKILL.md.
"""

import json
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
MAX_LINES = 220
MAX_BYTES = 24 * 1024

HIDDEN_UNICODE_RE = re.compile(
    r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\U000e0000-\U000e007f]"
)
SECRET_RE = re.compile(
    r"\b(?:s?ftps?|https?|postgres(?:ql)?|mysql|mongodb(?:\+srv)?|rediss?|amqps?|smtps?|ldaps?|ssh)://"
    r"[^/\s\"'`<>:@$]+:[^/\s\"'`<>@$]+@[^\s\"'`<>]+"
    r"|\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"
    r"|-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"
    r"|\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{25,}"
    r"|\bgithub_pat_[A-Za-z0-9_]{25,}"
    r"|\bxox[baprs]-[A-Za-z0-9-]{10,}"
    r"|\bAIza[0-9A-Za-z_-]{33,}",
    re.I,
)
MD_LINK_RE = re.compile(r"\[[^\]]+\]\(([^)]+)\)")
BINARY_EXTS = frozenset({".png", ".jpg", ".jpeg", ".gif", ".webp", ".ico", ".svg", ".sig", ".zip", ".tgz", ".gz", ".sqlite"})


def extract_skill_md_version(frontmatter: str) -> str | None:
    m = re.search(r'(?m)^\s*version:\s*["\']?([^\s"\']+)["\']?\s*$', frontmatter)
    return m.group(1) if m else None


def extract_skill_card_version(skill_card_text: str) -> str | None:
    normalized = skill_card_text.replace("\r\n", "\n")
    m = re.search(r"##\s+Skill Version\(s\):[^\n]*\n\s*([^\s<]+)", normalized)
    return m.group(1) if m else None


def main() -> int:
    errors: list[str] = []
    skill_md = SKILL_DIR / "SKILL.md"
    if not skill_md.exists():
        print(f"FAIL: missing {skill_md}", file=sys.stderr)
        return 1

    text = skill_md.read_text(encoding="utf-8")
    lines = text.splitlines()
    n_lines = len(lines)
    n_bytes = len(text.encode("utf-8"))

    if n_lines > MAX_LINES:
        errors.append(f"SKILL.md exceeds line budget: {n_lines} > {MAX_LINES}")
    if n_bytes > MAX_BYTES:
        errors.append(f"SKILL.md exceeds byte budget: {n_bytes} > {MAX_BYTES}")

    fm_match = re.match(r"---\n(.*?)\n---", text.replace("\r\n", "\n"), re.S)
    if not fm_match or "name:" not in fm_match.group(1) or "description:" not in fm_match.group(1):
        errors.append("SKILL.md missing valid YAML frontmatter (name, description)")

    # Link validation inside SKILL.md
    for m in MD_LINK_RE.finditer(text):
        target = m.group(1).strip()
        if target.startswith(("http://", "https://", "mailto:", "#")):
            continue
        target_path = (SKILL_DIR / target.split("#")[0]).resolve()
        if not target_path.exists():
            errors.append(f"SKILL.md broken relative link: {target}")

    # Reference metadata checks
    refs_dir = SKILL_DIR / "references"
    for ref in sorted(refs_dir.glob("*.md")):
        rt = ref.read_text(encoding="utf-8")
        if "last_reviewed:" not in rt[:800] or "review_by:" not in rt[:800]:
            errors.append(f"references/{ref.name} missing last_reviewed / review_by frontmatter")

    # Contract verb alignment
    contract_path = SKILL_DIR / "assets" / "runtime-contract.yaml"
    if not contract_path.exists():
        errors.append("Missing assets/runtime-contract.yaml")
    else:
        contract_txt = contract_path.read_text(encoding="utf-8")
        verbs = re.findall(r"cli_verb:\s*([a-z0-9-]+)", contract_txt)
        if not verbs:
            errors.append("No cli_verb entries found in assets/runtime-contract.yaml")
        for verb in verbs:
            if verb not in text:
                errors.append(f"Contract cli_verb '{verb}' not documented in SKILL.md")

    # Cross-harness manifest & version parity check (Google EGM pattern)
    root_manifest_path = ROOT / "plugin.json"
    if not root_manifest_path.exists():
        errors.append("Missing root plugin.json")
    else:
        root_m = json.loads(root_manifest_path.read_text(encoding="utf-8"))
        root_ver = root_m.get("version")
        logo = root_m.get("logo")
        if isinstance(logo, str) and not (ROOT / logo).exists():
            errors.append(f"Root plugin.json logo missing on disk: {logo}")
        for compat in (ROOT / ".claude-plugin" / "plugin.json", ROOT / ".codex-plugin" / "plugin.json"):
            if not compat.exists():
                errors.append(f"Missing multi-harness manifest: {compat.relative_to(ROOT).as_posix()}")
                continue
            cm = json.loads(compat.read_text(encoding="utf-8"))
            for field in ("name", "version", "description", "license"):
                if cm.get(field) != root_m.get(field):
                    errors.append(
                        f"Manifest drift in {compat.relative_to(ROOT).as_posix()}: '{field}' differs from root plugin.json"
                    )
        claude_mkt = ROOT / ".claude-plugin" / "marketplace.json"
        if claude_mkt.exists():
            mkt_data = json.loads(claude_mkt.read_text(encoding="utf-8"))
            for p_entry in mkt_data.get("plugins", []):
                if p_entry.get("version") != root_ver:
                    errors.append(
                        f"Version drift in .claude-plugin/marketplace.json: {p_entry.get('version')} != {root_ver}"
                    )
        codex_mkt = ROOT / ".agents" / "plugins" / "marketplace.json"
        if codex_mkt.exists():
            cmkt = json.loads(codex_mkt.read_text(encoding="utf-8"))
            for p_entry in cmkt.get("plugins", []):
                if p_entry.get("name") != root_m.get("name"):
                    errors.append(
                        f"Name drift in .agents/plugins/marketplace.json: {p_entry.get('name')} != {root_m.get('name')}"
                    )
                m_rel = p_entry.get("manifest")
                if isinstance(m_rel, str) and not (ROOT / m_rel).exists():
                    errors.append(f"Missing manifest referenced in .agents/plugins/marketplace.json: {m_rel}")
        pkg_json = ROOT / "package.json"
        if pkg_json.exists():
            pkg_ver = json.loads(pkg_json.read_text(encoding="utf-8")).get("version")
            if pkg_ver != root_ver:
                errors.append(f"Version drift in package.json: {pkg_ver} != {root_ver}")
        if fm_match:
            sm_ver = extract_skill_md_version(fm_match.group(1))
            if sm_ver != root_ver:
                errors.append(f"Version drift in SKILL.md frontmatter: {sm_ver} != {root_ver}")
        skill_card = SKILL_DIR / "skill-card.md"
        if not skill_card.exists():
            errors.append("Missing skill-src/coldpin/skill-card.md")
        else:
            sc_ver = extract_skill_card_version(skill_card.read_text(encoding="utf-8"))
            if sc_ver != root_ver:
                errors.append(f"Version drift in skill-src/coldpin/skill-card.md: {sc_ver} != {root_ver}")
        types_ts = ROOT / "src" / "types.ts"
        if types_ts.exists():
            eng_m = re.search(r'ENGINE_VERSION\s*=\s*"([^"]+)"', types_ts.read_text(encoding="utf-8"))
            if not eng_m or eng_m.group(1) != root_ver:
                errors.append(f"Version drift in src/types.ts ENGINE_VERSION: {eng_m.group(1) if eng_m else None} != {root_ver}")

    # Validate rules/triage-rules.json catalog
    rules_manifest = ROOT / "rules" / "triage-rules.json"
    if not rules_manifest.exists():
        errors.append("Missing rules/triage-rules.json detection-as-code catalog")
    else:
        try:
            rm = json.loads(rules_manifest.read_text(encoding="utf-8"))
            if not isinstance(rm.get("rules"), list) or len(rm["rules"]) < 10:
                errors.append("rules/triage-rules.json must declare >= 10 structured rules")
            if root_manifest_path.exists():
                root_ver = json.loads(root_manifest_path.read_text(encoding="utf-8")).get("version")
                if rm.get("ruleset_version") != root_ver:
                    errors.append(f"Version drift in rules/triage-rules.json: {rm.get('ruleset_version')} != {root_ver}")
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON in rules/triage-rules.json: {exc}")

    # Hidden/bidi Unicode & shift-left secret scan across skill-src/
    for p in sorted(SKILL_DIR.rglob("*")):
        if not p.is_file() or p.suffix.lower() in BINARY_EXTS:
            continue
        rel = p.relative_to(ROOT).as_posix()
        try:
            content = p.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            errors.append(f"Invalid UTF-8 in {rel}")
            continue
        if HIDDEN_UNICODE_RE.search(content):
            errors.append(f"Hidden/bidirectional Unicode detected in {rel}")
        sm = SECRET_RE.search(content)
        if sm:
            errors.append(f"Potential secret/credential URI in {rel}: {sm.group(0)[:36]!r}")

    print(f"SKILL.md budget: {n_lines}/{MAX_LINES} lines, {n_bytes}/{MAX_BYTES} bytes")
    if errors:
        print("LINT FAILED:", file=sys.stderr)
        for e in errors:
            print(f"  - {e}", file=sys.stderr)
        return 1

    print("LINT OK: skill manifest, links, contract alignment, Unicode hygiene, and secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
