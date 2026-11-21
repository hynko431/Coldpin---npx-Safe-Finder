#!/usr/bin/env python3
"""Zero-dependency Enterprise Skill & MCP Manifest Linter for Coldpin.

Checks:
1. SKILL.md budget (<= 220 lines, <= 24,000 bytes matching agy.exe strict threshold) and valid YAML frontmatter.
2. Clean UTF-8 and zero hidden/bidirectional/tag Unicode (Trojan Source defense).
3. Shift-left secret & credential-URI scan across all text files in skills/coldpin/.
4. Relative Markdown link resolution inside skills/coldpin/.
5. Reference files carry `last_reviewed:` and `review_by:` metadata.
6. Alignment between CLI verbs in runtime-contract.yaml and SKILL.md.
7. Cross-harness 13-manifest version & MCP schema/config parity (`plugin.json`, `package.json`,
   `server.json`, `mcp_config.json`, `.claude-plugin/{plugin,marketplace}.json`, `.codex-plugin/plugin.json`,
   `src/types.ts`, `catalog/triage-rules.json`, `catalog/mcp-schema-pin.json`, `skills/coldpin/{SKILL,skill-card}.md`,
   `skills/coldpin-{audit,incident}/SKILL.md`), plus Antigravity `rules/`, `agents/`, and `hooks.json` schema checks.
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
SKILL_DIR = ROOT / "skills" / "coldpin"
MAX_LINES = 220
MAX_BYTES = 24_000

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

    # Disallow conflicting root .mcp.json or mcp.json (breaks agy plugin validate --strict)
    for forbidden_root in (ROOT / ".mcp.json", ROOT / "mcp.json"):
        if forbidden_root.exists():
            errors.append(f"Forbidden root MCP manifest '{forbidden_root.name}' conflicts with agy plugin validate --strict")

    # Cross-harness manifest & version parity check
    root_manifest_path = ROOT / "plugin.json"
    if not root_manifest_path.exists():
        errors.append("Missing root plugin.json")
    else:
        root_m = json.loads(root_manifest_path.read_text(encoding="utf-8"))
        root_ver = root_m.get("version")
        if "mcpServers" in root_m:
            errors.append("Root plugin.json must NOT inline 'mcpServers' (use root mcp_config.json for agy --strict)")
        if root_m.get("$schema") != "https://antigravity.google/schemas/v1/plugin.json":
            errors.append("Root plugin.json must set '$schema' to 'https://antigravity.google/schemas/v1/plugin.json'")
        allowed_root_props = {
            "$schema", "name", "displayName", "version", "description", "author",
            "homepage", "repository", "license", "keywords", "logo", "suggestedPrompts", "extensions",
        }
        extra_props = sorted(set(root_m.keys()) - allowed_root_props)
        if extra_props:
            errors.append(f"Root plugin.json contains non-schema properties (additionalProperties: false): {extra_props}")
        author_obj = root_m.get("author")
        if isinstance(author_obj, dict) and not str(author_obj.get("url", "")).startswith("https://"):
            errors.append("Root plugin.json author.url must be an https:// URL")
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
            if compat.parent.name == ".claude-plugin":
                c_mcp = cm.get("mcpServers", {}).get("coldpin", {})
                for arg in c_mcp.get("args", []):
                    if isinstance(arg, str) and "${CLAUDE_PLUGIN_ROOT}/" in arg:
                        rel_target = arg.replace("${CLAUDE_PLUGIN_ROOT}/", "")
                        if not (ROOT / rel_target).exists():
                            errors.append(f".claude-plugin/plugin.json MCP target missing on disk: {rel_target}")
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
        pkg_data: dict = {}
        if pkg_json.exists():
            pkg_data = json.loads(pkg_json.read_text(encoding="utf-8"))
            pkg_ver = pkg_data.get("version")
            if pkg_ver != root_ver:
                errors.append(f"Version drift in package.json: {pkg_ver} != {root_ver}")
            for bin_name, bin_rel in (pkg_data.get("bin") or {}).items():
                if isinstance(bin_rel, str):
                    if bin_rel.endswith(".ts"):
                        errors.append(f"package.json bin '{bin_name}' points to .ts file ({bin_rel}); must use compiled lib/*.mjs")
                    if not (ROOT / bin_rel).exists():
                        errors.append(f"package.json bin '{bin_name}' target missing on disk: {bin_rel}")

        # Validate root mcp_config.json
        mcp_cfg_path = ROOT / "mcp_config.json"
        if not mcp_cfg_path.exists():
            errors.append("Missing root mcp_config.json")
        else:
            mcp_cfg = json.loads(mcp_cfg_path.read_text(encoding="utf-8"))
            srv_cfg = mcp_cfg.get("mcpServers", {}).get("coldpin", {})
            if not srv_cfg:
                errors.append("mcp_config.json missing mcpServers.coldpin entry")
            for arg in srv_cfg.get("args", []):
                if isinstance(arg, str) and "${PLUGIN_ROOT}/" in arg:
                    rel_target = arg.replace("${PLUGIN_ROOT}/", "")
                    if not (ROOT / rel_target).exists():
                        errors.append(f"mcp_config.json target missing on disk: {rel_target}")

        # Validate root server.json (Official MCP Registry 2025-12-11 schema)
        srv_json_path = ROOT / "server.json"
        if not srv_json_path.exists():
            errors.append("Missing root server.json")
        else:
            srv_doc = json.loads(srv_json_path.read_text(encoding="utf-8"))
            if srv_doc.get("version") != root_ver:
                errors.append(f"Version drift in server.json: {srv_doc.get('version')} != {root_ver}")
            desc = srv_doc.get("description", "")
            if not isinstance(desc, str) or len(desc) == 0 or len(desc) > 100:
                errors.append(f"server.json description must be 1..100 chars (got {len(desc) if isinstance(desc, str) else 'non-string'})")
            if pkg_data and srv_doc.get("name") != pkg_data.get("mcpName"):
                errors.append(f"server.json name '{srv_doc.get('name')}' != package.json mcpName '{pkg_data.get('mcpName')}'")
            pkgs = srv_doc.get("packages", [])
            if not pkgs or pkgs[0].get("version") != root_ver:
                errors.append("server.json packages[0].version does not match root version")
            if pkg_data and pkgs and pkgs[0].get("identifier") != pkg_data.get("name"):
                errors.append(f"server.json packages[0].identifier '{pkgs[0].get('identifier')}' != package.json name '{pkg_data.get('name')}'")

        if fm_match:
            sm_ver = extract_skill_md_version(fm_match.group(1))
            if sm_ver != root_ver:
                errors.append(f"Version drift in SKILL.md frontmatter: {sm_ver} != {root_ver}")
        skill_card = SKILL_DIR / "skill-card.md"
        if not skill_card.exists():
            errors.append("Missing skills/coldpin/skill-card.md")
        else:
            sc_ver = extract_skill_card_version(skill_card.read_text(encoding="utf-8"))
            if sc_ver != root_ver:
                errors.append(f"Version drift in skills/coldpin/skill-card.md: {sc_ver} != {root_ver}")
        types_ts = ROOT / "src" / "types.ts"
        if types_ts.exists():
            eng_m = re.search(r'ENGINE_VERSION\s*=\s*"([^"]+)"', types_ts.read_text(encoding="utf-8"))
            if not eng_m or eng_m.group(1) != root_ver:
                errors.append(f"Version drift in src/types.ts ENGINE_VERSION: {eng_m.group(1) if eng_m else None} != {root_ver}")

        mcp_pin = ROOT / "catalog" / "mcp-schema-pin.json"
        if not mcp_pin.exists():
            errors.append("Missing catalog/mcp-schema-pin.json")
        else:
            pin_doc = json.loads(mcp_pin.read_text(encoding="utf-8"))
            if pin_doc.get("engine_version") != root_ver:
                errors.append(f"Version drift in catalog/mcp-schema-pin.json: {pin_doc.get('engine_version')} != {root_ver}")

    # Validate catalog/triage-rules.json catalog
    rules_manifest = ROOT / "catalog" / "triage-rules.json"
    if not rules_manifest.exists():
        errors.append("Missing catalog/triage-rules.json detection-as-code catalog")
    else:
        try:
            rm = json.loads(rules_manifest.read_text(encoding="utf-8"))
            if not isinstance(rm.get("rules"), list) or len(rm["rules"]) < 10:
                errors.append("catalog/triage-rules.json must declare >= 10 structured rules")
            if root_manifest_path.exists():
                root_ver = json.loads(root_manifest_path.read_text(encoding="utf-8")).get("version")
                if rm.get("ruleset_version") != root_ver:
                    errors.append(f"Version drift in catalog/triage-rules.json: {rm.get('ruleset_version')} != {root_ver}")
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON in catalog/triage-rules.json: {exc}")

    # Validate Antigravity-only slash skills (`skills/coldpin-audit`, `skills/coldpin-incident`)
    root_ver_for_extra = (
        json.loads(root_manifest_path.read_text(encoding="utf-8")).get("version")
        if root_manifest_path.exists()
        else None
    )
    for extra_skill_name in ("coldpin-audit", "coldpin-incident"):
        extra_skill = ROOT / "skills" / extra_skill_name / "SKILL.md"
        if not extra_skill.exists():
            errors.append(f"Missing Antigravity slash skill: skills/{extra_skill_name}/SKILL.md")
            continue
        es_raw = extra_skill.read_bytes()
        es_txt = es_raw.decode("utf-8")
        if len(es_txt.splitlines()) > MAX_LINES or len(es_raw) > MAX_BYTES:
            errors.append(f"skills/{extra_skill_name}/SKILL.md exceeds Antigravity line/byte budget")
        es_fm = re.match(r"^---\r?\n(.*?)\r?\n---", es_txt, re.S)
        if not es_fm:
            errors.append(f"skills/{extra_skill_name}/SKILL.md missing YAML frontmatter")
        else:
            es_ver = extract_skill_md_version(es_fm.group(1))
            if root_ver_for_extra and es_ver != root_ver_for_extra:
                errors.append(f"Version drift in skills/{extra_skill_name}/SKILL.md: {es_ver} != {root_ver_for_extra}")

    # Validate rules/ (flat pure Markdown rules only)
    rules_dir = ROOT / "rules"
    if not rules_dir.is_dir():
        errors.append("Missing rules/ directory for Antigravity Markdown rules")
    else:
        for entry in sorted(rules_dir.iterdir()):
            if entry.is_dir() or entry.suffix.lower() != ".md":
                errors.append(f"Non-Markdown entry in rules/ (scanner data belongs in catalog/): rules/{entry.name}")
                continue
            r_raw = entry.read_bytes()
            r_txt = r_raw.decode("utf-8")
            if re.search(r"@\[[^\]]+\]\([^)]+\)", r_txt):
                errors.append(f"Disallowed @[label](path) file include in rules/{entry.name}")
            if entry.name in ("AGENTS.md", "GEMINI.md"):
                if r_txt.startswith("---"):
                    errors.append(f"rules/{entry.name} must NOT contain YAML frontmatter")
                if len(r_raw) > 1800:
                    errors.append(f"rules/{entry.name} exceeds 1,800-byte budget ({len(r_raw)} bytes)")
            else:
                rfm = re.match(r"^---\r?\n(.*?)\r?\n---", r_txt, re.S)
                if not rfm:
                    errors.append(f"rules/{entry.name} missing required YAML frontmatter")
                else:
                    fm_body = rfm.group(1)
                    tm = re.search(r"^trigger:\s*(\S+)", fm_body, re.M)
                    if not tm or tm.group(1) not in ("always_on", "model_decision", "glob", "manual"):
                        errors.append(f"rules/{entry.name} missing valid trigger")
                    elif tm.group(1) == "glob":
                        gm = re.search(r'^globs:\s*"([^"]+)"', fm_body, re.M)
                        if not gm:
                            errors.append(f"rules/{entry.name} with trigger: glob must use quoted comma-separated globs string")

    # Validate agents/ (7 read-only aspect agents with canonical tool allowlist)
    agents_dir = ROOT / "agents"
    allowed_agent_tools = {"view_file", "grep_search", "find_by_name", "list_dir", "send_message", "invoke_subagent"}
    if not agents_dir.is_dir():
        errors.append("Missing agents/ directory")
    else:
        agent_files = sorted(agents_dir.glob("*.md"))
        if len(agent_files) != 7:
            errors.append(f"Expected 7 agents in agents/, found {len(agent_files)}")
        for af in agent_files:
            atxt = af.read_text(encoding="utf-8")
            afm = re.match(r"^---\r?\n(.*?)\r?\n---", atxt, re.S)
            if not afm:
                errors.append(f"agents/{af.name} missing YAML frontmatter")
                continue
            fm = afm.group(1)
            if not re.search(r'^commandExecutionPolicy:\s*"?off"?\s*$', fm, re.M):
                errors.append(f"agents/{af.name} must set commandExecutionPolicy: \"off\"")
            is_main = bool(re.search(r"^mainAgent:\s*true\s*$", fm, re.M))
            if not is_main and not re.search(r"^inheritCustomizations:\s*false\s*$", fm, re.M):
                errors.append(f"Background subagent agents/{af.name} must set inheritCustomizations: false")
            if re.search(r"^mcpServers:\s*\n\s*-\s*[\"']?[A-Za-z0-9_-]+[\"']?\s*$", fm, re.M):
                errors.append(f"agents/{af.name} must not use string-array mcpServers")
            # Parse tools block
            tools_m = re.search(r"^tools:\s*\n((?:\s+-\s+\S+\s*\n?)+)", fm, re.M)
            if not tools_m:
                errors.append(f"agents/{af.name} missing explicit read-only tools allowlist")
            else:
                tools_list = [ln.strip().lstrip("-").strip().strip("\"'") for ln in tools_m.group(1).splitlines() if ln.strip()]
                for t in tools_list:
                    if t not in allowed_agent_tools:
                        errors.append(f"agents/{af.name} uses disallowed/non-canonical tool '{t}'")
                    if t == "invoke_subagent" and not is_main:
                        errors.append(f"Background leaf subagent agents/{af.name} must not grant invoke_subagent")
            # Parse skills block
            skills_m = re.search(r"^skills:\s*\n((?:\s+-\s+\S+\s*\n?)+)", fm, re.M)
            if not skills_m:
                errors.append(f"agents/{af.name} missing skills list")
            else:
                for ln in skills_m.group(1).splitlines():
                    sp = ln.strip().lstrip("-").strip().strip("\"'")
                    if sp and not (ROOT / sp / "SKILL.md").exists():
                        errors.append(f"agents/{af.name} references missing skill '{sp}/SKILL.md'")

    # Validate root hooks.json (3 named hook groups, all enabled: true)
    hooks_path = ROOT / "hooks.json"
    if not hooks_path.exists():
        errors.append("Missing root hooks.json")
    else:
        try:
            hdoc = json.loads(hooks_path.read_text(encoding="utf-8"))
            if not isinstance(hdoc, dict) or len(hdoc) != 3:
                errors.append(f"hooks.json must declare 3 named hook groups (found {len(hdoc) if isinstance(hdoc, dict) else 'non-object'})")
            else:
                for gname, gobj in hdoc.items():
                    if not isinstance(gobj, dict) or gobj.get("enabled") is not True:
                        errors.append(f"hooks.json group '{gname}' must have enabled: true")
                    for entry in gobj.get("PreToolUse", []):
                        for h in entry.get("hooks", []):
                            cmd = h.get("command", "")
                            if cmd != "node --no-warnings ./lib/hook.mjs":
                                errors.append(f"hooks.json '{gname}' unexpected command: {cmd!r}")
                            if "${PLUGIN_ROOT}" in cmd:
                                errors.append(f"hooks.json '{gname}' must not interpolate ${{PLUGIN_ROOT}} in command")
                            if not isinstance(h.get("timeout"), int) or h.get("timeout") <= 0:
                                errors.append(f"hooks.json '{gname}' missing positive integer timeout")
        except json.JSONDecodeError as exc:
            errors.append(f"Invalid JSON in hooks.json: {exc}")

    # Hidden/bidi Unicode & shift-left secret scan across skills/, rules/, agents/, hooks.json
    scan_paths: list[Path] = []
    for base_dir in (SKILL_DIR, ROOT / "skills" / "coldpin-audit", ROOT / "skills" / "coldpin-incident", ROOT / "rules", ROOT / "agents"):
        if base_dir.is_dir():
            scan_paths.extend(sorted(base_dir.rglob("*")))
    if hooks_path.exists():
        scan_paths.append(hooks_path)
    for p in scan_paths:
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

    print("LINT OK: skill manifest, MCP configs, 13-manifest parity, rules/agents/hooks schema, links, contract alignment, Unicode hygiene, and secret scan passed.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
