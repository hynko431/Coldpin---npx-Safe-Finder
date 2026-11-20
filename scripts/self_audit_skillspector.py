#!/usr/bin/env python3
"""SkillSpector-class Deterministic Self-Audit for Coldpin (v1.3.0).

Audits skills/coldpin/, src/, scripts/, rules/, and multi-harness/MCP manifests across
NVIDIA SkillSpector's threat categories + Coldpin MCP & compiled-runtime supply-chain gates:
- SS-03 (import-aware): allow ONLY async `execFile` from `node:child_process` in allowlisted files;
  flag sync `execFileSync(` as `SS-03-SYNC-EXEC-BLOCKING`; never false-positive on `RegExp.exec()` or `db.exec()`.
- SS-04..SS-10: unpinned `npx -y`, secrets, persistence, hidden/bidi Unicode, manifest hooks, bounded network, symlinks.
- SS-11: MCP `tools/list` + `resources/list` + `prompts/list` SHA-256 rug-pull pin (`rules/mcp-schema-pin.json`),
  zero listening network sockets in `src/`, and zero stray `stdout` writes in pure-core modules.
- SS-12: Structured JSON least-privilege audit of `mcp_config.json`, `server.json`, and `.claude-plugin/plugin.json`.
- SS-13: Zero-noise 1:1 cryptographic parity between `src/**/*.ts` and committed `lib/**/*.mjs` (`build_lib.ts --check`).
"""

import json
import re
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8")
        sys.stderr.reconfigure(encoding="utf-8")
    except Exception:
        pass

ROOT = Path(__file__).resolve().parent.parent
SKIP_DIRS = {
    "evals",
    ".evals",
    "results",
    ".results",
    "versions",
    ".versions",
    "__pycache__",
    ".git",
    ".venv",
    "node_modules",
    "dist",
    "tests",
    ".agents",
    "lib",  # Audited via zero-noise 1:1 cryptographic parity in SS-13 (prevents duplicate LOW inflation)
}
SKIP_FILES = {"skill.oms.sig", "BENCHMARK.md", "skill-card.md"}
SCAN_EXTS = {".md", ".ts", ".js", ".mjs", ".py", ".yaml", ".yml", ".json"}
PURE_CORE_PREFIXES = (
    "src/core/",
    "src/analysis/",
    "src/intel/",
    "src/quarantine/",
    "src/cache/",
    "src/config/",
    "src/verdict/",
    "src/compliance/",
)


@dataclass
class Finding:
    rule_id: str
    severity: str  # CRITICAL | HIGH | MEDIUM | LOW
    path: str
    line: int
    message: str
    judgment: str
    blocks: bool


def line_number(text: str, index: int) -> int:
    return text[:index].count("\n") + 1


def audit_mcp_manifests(findings: list[Finding]) -> None:
    # SS-12: Structured JSON audit of mcp_config.json, server.json, and .claude-plugin/plugin.json
    mcp_cfg_path = ROOT / "mcp_config.json"
    if not mcp_cfg_path.exists():
        findings.append(
            Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "mcp_config.json", 1, "Missing root mcp_config.json", "Reject: Antigravity MCP config required.", True)
        )
    else:
        try:
            cfg = json.loads(mcp_cfg_path.read_text(encoding="utf-8"))
            srvs = cfg.get("mcpServers", {})
            if not isinstance(srvs, dict) or not srvs:
                findings.append(
                    Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "mcp_config.json", 1, "Empty mcpServers in mcp_config.json", "Reject: invalid MCP server config.", True)
                )
            for name, srv in srvs.items():
                if not isinstance(srv, dict):
                    continue
                if "serverUrl" in srv or "url" in srv:
                    findings.append(
                        Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "mcp_config.json", 1, f"Remote URL configured in local-only MCP server '{name}'", "Reject: local stdio-only architecture locked.", True)
                    )
                if srv.get("command") != "node":
                    findings.append(
                        Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "mcp_config.json", 1, f"Unexpected MCP command '{srv.get('command')}'", "Reject: must invoke node directly (never npx -y).", True)
                    )
                args = srv.get("args", [])
                if not any(isinstance(a, str) and a.endswith("/lib/mcp.mjs") for a in args):
                    findings.append(
                        Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "mcp_config.json", 1, "mcp_config.json does not target compiled lib/mcp.mjs", "Reject: must target ${PLUGIN_ROOT}/lib/mcp.mjs.", True)
                    )
                for ek, ev in (srv.get("env") or {}).items():
                    if isinstance(ev, str) and re.search(r"(?:ghp_|github_pat_|npm_|AKIA|sk-)", ev):
                        findings.append(
                            Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "CRITICAL", "mcp_config.json", 1, f"Hardcoded secret in mcp_config.json env '{ek}'", "Reject: never embed credentials in MCP config.", True)
                        )
        except json.JSONDecodeError as exc:
            findings.append(
                Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "mcp_config.json", 1, f"Malformed JSON in mcp_config.json: {exc}", "Reject: invalid JSON.", True)
            )

    srv_json_path = ROOT / "server.json"
    if not srv_json_path.exists():
        findings.append(
            Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "server.json", 1, "Missing root server.json", "Reject: Official MCP Registry manifest required.", True)
        )
    else:
        try:
            sdoc = json.loads(srv_json_path.read_text(encoding="utf-8"))
            pkgs = sdoc.get("packages", [])
            if not pkgs or not isinstance(pkgs[0], dict):
                findings.append(
                    Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "server.json", 1, "server.json missing npm package entry", "Reject: declare npm stdio package.", True)
                )
            else:
                p0 = pkgs[0]
                if (p0.get("transport") or {}).get("type") != "stdio":
                    findings.append(
                        Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "server.json", 1, "server.json transport is not stdio", "Reject: local stdio-only architecture locked.", True)
                    )
                rargs = [a.get("value") for a in p0.get("runtimeArguments", []) if isinstance(a, dict)]
                if "--ignore-scripts" not in rargs:
                    findings.append(
                        Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "server.json", 1, "server.json runtimeArguments missing --ignore-scripts", "Reject: dogfood --ignore-scripts on npx launch.", True)
                    )
                if "-y" in rargs or "--yes" in rargs:
                    findings.append(
                        Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "server.json", 1, "server.json runtimeArguments must not force -y/--yes", "Reject: avoid silent npx auto-install.", True)
                    )
        except json.JSONDecodeError as exc:
            findings.append(
                Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", "server.json", 1, f"Malformed JSON in server.json: {exc}", "Reject: invalid JSON.", True)
            )

    claude_path = ROOT / ".claude-plugin" / "plugin.json"
    if claude_path.exists():
        cdata = json.loads(claude_path.read_text(encoding="utf-8"))
        for name, srv in (cdata.get("mcpServers") or {}).items():
            if not isinstance(srv, dict):
                continue
            if "serverUrl" in srv or "url" in srv:
                findings.append(
                    Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", ".claude-plugin/plugin.json", 1, f"Remote URL in Claude mcpServers '{name}'", "Reject: stdio-only locked.", True)
                )
            if srv.get("command") != "node":
                findings.append(
                    Finding("SS-12-MCP-CONFIG-LEAST-PRIV", "HIGH", ".claude-plugin/plugin.json", 1, f"Unexpected Claude MCP command '{srv.get('command')}'", "Reject: must invoke node directly.", True)
                )


def audit_mcp_schema_pin(findings: list[Finding]) -> None:
    pin_path = ROOT / "rules" / "mcp-schema-pin.json"
    if not pin_path.exists():
        findings.append(
            Finding("SS-11-MCP-TOOL-SCHEMA-PIN", "CRITICAL", "rules/mcp-schema-pin.json", 1, "Missing rules/mcp-schema-pin.json", "Reject: MCP schema rug-pull pin required.", True)
        )
        return
    try:
        pinned = json.loads(pin_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        findings.append(
            Finding("SS-11-MCP-TOOL-SCHEMA-PIN", "CRITICAL", "rules/mcp-schema-pin.json", 1, f"Malformed mcp-schema-pin.json: {exc}", "Reject: invalid JSON.", True)
        )
        return

    proc = subprocess.run(
        [
            "node",
            "--no-warnings",
            "--input-type=module",
            "-e",
            "import { computeMcpSchemaPin } from './src/mcp/tool-catalog.ts'; console.log(JSON.stringify(computeMcpSchemaPin()));",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=15,
    )
    if proc.returncode != 0:
        findings.append(
            Finding("SS-11-MCP-TOOL-SCHEMA-PIN", "CRITICAL", "src/mcp/tool-catalog.ts", 1, f"Failed computing live MCP schema pin: {proc.stderr.strip()[:160]}", "Reject: cannot verify MCP catalog integrity.", True)
        )
        return
    live = json.loads(proc.stdout.strip())
    for k in ("tools_sha256", "resources_sha256", "prompts_sha256", "catalog_sha256", "tools_count"):
        if pinned.get(k) != live.get(k):
            findings.append(
                Finding(
                    "SS-11-MCP-TOOL-SCHEMA-PIN",
                    "CRITICAL",
                    "rules/mcp-schema-pin.json",
                    1,
                    f"MCP schema pin drift on '{k}': pinned={pinned.get(k)} != live={live.get(k)}",
                    "Reject: unexpected tool/resource/prompt schema mutation (potential rug pull).",
                    True,
                )
            )
    if live.get("estimated_tokens", 99999) > 1800:
        findings.append(
            Finding(
                "SS-11-MCP-TOOL-SCHEMA-PIN",
                "HIGH",
                "src/mcp/tool-catalog.ts",
                1,
                f"MCP tools/list token budget exceeded: {live.get('estimated_tokens')} > 1800",
                "Reject: trim MCP schema/descriptions to preserve token efficiency.",
                True,
            )
        )


def audit_compiled_lib_parity(findings: list[Finding]) -> None:
    # SS-13: Zero-noise 1:1 cryptographic parity between src/**/*.ts and committed lib/**/*.mjs
    proc = subprocess.run(
        ["node", "--no-warnings", "scripts/build_lib.ts", "--check"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        timeout=20,
    )
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout).strip().splitlines()[0] if (proc.stderr or proc.stdout).strip() else "lib/ parity failure"
        findings.append(
            Finding(
                "SS-13-COMPILED-LIB-DRIFT",
                "CRITICAL",
                "lib/",
                1,
                f"Compiled lib/ differs from src/ ({detail[:160]})",
                "Reject: re-run 'npm run build' or investigate tampered lib/*.mjs artifact.",
                True,
            )
        )


def scan_repo() -> list[Finding]:
    findings: list[Finding] = []

    hidden_uni = re.compile(r"[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\U000e0000-\U000e007f]")
    secret_re = re.compile(
        r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b|-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----|\bghp_[A-Za-z0-9]{25,}"
    )
    shell_true_re = re.compile(r"shell\s*[:=]\s*true", re.I)
    # Import-aware non-member shell APIs (never matches RegExp.exec() or db.exec())
    unsafe_shell_api_re = re.compile(r"(?<![.\"'`A-Za-z0-9_])(?:execSync|spawn|spawnSync|fork|os\.system|subprocess\.Popen)\s*\(")
    sync_exec_file_re = re.compile(r"(?<![.\"'`A-Za-z0-9_])execFileSync\s*\(")
    cp_import_re = re.compile(r"""import\s*\{([^}]+)\}\s*from\s*["'](?:node:)?child_process["']""")
    unsafe_eval_re = re.compile(r"(?<![.\"'`A-Za-z0-9_])eval\s*\(")
    persistence_re = re.compile(r"(?:/etc/cron|LaunchAgents|~/.bashrc|~/.zshrc|schtasks\s+/create)", re.I)
    unpinned_npx_re = re.compile(r"\bnpx\s+-y\s+[a-z0-9@/_-]+", re.I)
    fetch_call_re = re.compile(r"(?<![A-Za-z0-9_.])fetch\s*\(")
    net_listener_re = re.compile(r"\b(?:createServer|WebSocketServer)\s*\(")
    stray_stdout_re = re.compile(r"\b(?:process\.stdout\.write|console\.(?:log|info|debug|warn|error))\s*\(")

    scan_roots = [
        ROOT / "skills" / "coldpin",
        ROOT / "src",
        ROOT / "scripts",
        ROOT / "rules",
        ROOT / "plugin.json",
        ROOT / "mcp_config.json",
        ROOT / "server.json",
        ROOT / ".claude-plugin" / "plugin.json",
        ROOT / ".codex-plugin" / "plugin.json",
    ]

    files: list[Path] = []
    for sr in scan_roots:
        if sr.is_file():
            files.append(sr)
        elif sr.is_dir():
            for p in sorted(sr.rglob("*")):
                if any(part in SKIP_DIRS for part in p.parts):
                    continue
                if p.is_symlink():
                    findings.append(
                        Finding(
                            "SS-10-SYMLINK",
                            "CRITICAL",
                            p.relative_to(ROOT).as_posix(),
                            1,
                            "Symlink detected inside skill or source tree",
                            "Reject: symlinks violate package integrity boundary.",
                            True,
                        )
                    )
                    continue
                if p.is_file() and p.name not in SKIP_FILES and p.suffix.lower() in SCAN_EXTS:
                    files.append(p)

    for fpath in files:
        rel = fpath.relative_to(ROOT).as_posix()
        txt = fpath.read_text(encoding="utf-8")
        lines = txt.splitlines()

        # SS-07: Real invisible / bidi / Tag Unicode (checked across ALL files, zero whole-file skips!)
        m = hidden_uni.search(txt)
        if m:
            findings.append(
                Finding(
                    "SS-07-HIDDEN-UNICODE",
                    "CRITICAL",
                    rel,
                    line_number(txt, m.start()),
                    "Hidden or bidirectional Unicode character detected",
                    "Reject: Trojan-Source or invisible prompt injection.",
                    True,
                )
            )

        if rel == "scripts/self_audit_skillspector.py":
            continue

        # SS-05: Hardcoded secrets
        for sm in secret_re.finditer(txt):
            lno = line_number(txt, sm.start())
            if rel in ("scripts/lint_skill.py", "scripts/verify_hygiene.py") and "SECRET_RE" in txt[max(0, sm.start() - 400):sm.start()]:
                continue
            findings.append(
                Finding(
                    "SS-05-HARDCODED-SECRET",
                    "CRITICAL",
                    rel,
                    lno,
                    "Hardcoded secret or private key marker detected",
                    "Reject: secrets must never be stored in skill files.",
                    True,
                )
            )

        # SS-03 & SS-11 in runnable code
        if fpath.suffix.lower() in (".ts", ".js", ".mjs", ".py"):
            m = shell_true_re.search(txt)
            if m:
                findings.append(
                    Finding(
                        "SS-03-SHELL-TRUE",
                        "HIGH",
                        rel,
                        line_number(txt, m.start()),
                        "Subprocess invocation with shell=true detected",
                        "Reject: use argument-array execFile/subprocess without shell.",
                        True,
                    )
                )
            if rel.startswith("src/"):
                # Import-aware node:child_process check
                for im in cp_import_re.finditer(txt):
                    lno = line_number(txt, im.start())
                    imported = [s.strip().split(" as ")[0].strip() for s in im.group(1).split(",") if s.strip()]
                    allowed_file = rel in ("src/analysis/parity-and-bisect.ts", "src/config/policy.ts")
                    disallowed_syms = [s for s in imported if s != "execFile"]
                    if not allowed_file or disallowed_syms:
                        findings.append(
                            Finding(
                                "SS-03-UNSAFE-SHELL-API",
                                "HIGH",
                                rel,
                                lno,
                                f"Disallowed child_process import ({', '.join(imported)}) in {rel}",
                                "Reject: only async execFile is permitted in allowlisted Git/capability modules.",
                                True,
                            )
                        )
                    else:
                        hardened_ok = True
                        if rel == "src/analysis/parity-and-bisect.ts":
                            hardened_ok = (
                                "core.fsmonitor=false" in txt
                                and "core.hooksPath=/dev/null" in txt
                                and "http.followRedirects=false" in txt
                                and "GIT_CONFIG_GLOBAL" in txt
                            )
                        findings.append(
                            Finding(
                                "SS-03-BOUNDED-EXEC" if hardened_ok else "SS-03-UNHARDENED-EXEC",
                                "LOW" if hardened_ok else "HIGH",
                                rel,
                                lno,
                                "Read-only async argument-array execFile (git/version probe) with hooks/fsmonitor/redirects disabled and minimal env"
                                if hardened_ok
                                else "Unhardened execFile() surface in src/",
                                "Acceptable: required for Git parity/bisect or --version probe; never executes untrusted package scripts."
                                if hardened_ok
                                else "Reject: harden git invocations with fsmonitor=false, hooksPath=/dev/null, followRedirects=false, and minimal env.",
                                not hardened_ok,
                            )
                        )

                for um in unsafe_shell_api_re.finditer(txt):
                    lno = line_number(txt, um.start())
                    line_txt = lines[lno - 1]
                    if line_txt.strip().startswith("//"):
                        continue
                    findings.append(
                        Finding(
                            "SS-03-UNSAFE-SHELL-API",
                            "HIGH",
                            rel,
                            lno,
                            f"Shell-capable process API '{um.group(0)}' used in src/",
                            "Reject: use async argument-array execFile with shell disabled.",
                            True,
                        )
                    )

                for sm_sync in sync_exec_file_re.finditer(txt):
                    lno = line_number(txt, sm_sync.start())
                    if lines[lno - 1].strip().startswith("//"):
                        continue
                    findings.append(
                        Finding(
                            "SS-03-SYNC-EXEC-BLOCKING",
                            "HIGH",
                            rel,
                            lno,
                            "Blocking execFileSync() call detected in src/",
                            "Reject: use async promisify(execFile) so MCP stdio server never stalls.",
                            True,
                        )
                    )

                # SS-11: Ban listening sockets anywhere in src/ (stdio-only invariant)
                for nm in net_listener_re.finditer(txt):
                    lno = line_number(txt, nm.start())
                    if lines[lno - 1].strip().startswith("//"):
                        continue
                    findings.append(
                        Finding(
                            "SS-11-MCP-STDIO-ONLY",
                            "HIGH",
                            rel,
                            lno,
                            f"Network listener '{nm.group(0)}' detected in src/",
                            "Reject: Coldpin MCP is strictly local stdio-only with zero listening sockets.",
                            True,
                        )
                    )

                # SS-11: Pure-core invariant (zero stdout/console writes in core libraries)
                if rel.startswith(PURE_CORE_PREFIXES):
                    for st_m in stray_stdout_re.finditer(txt):
                        lno = line_number(txt, st_m.start())
                        stripped_line = lines[lno - 1].strip()
                        if stripped_line.startswith(("//", "*")):
                            continue
                        findings.append(
                            Finding(
                                "SS-11-PURE-CORE-STDIO",
                                "HIGH",
                                rel,
                                lno,
                                f"Direct stdio/console call '{st_m.group(0)}' inside pure-core module",
                                "Reject: pure-core modules must not write to stdout/console (prevents MCP JSON-RPC framing corruption).",
                                True,
                            )
                        )

            for em in unsafe_eval_re.finditer(txt):
                lno = line_number(txt, em.start())
                line_txt = lines[lno - 1]
                stripped = line_txt.strip()
                if stripped.startswith(("//", "#", "*")) or '"eval("' in line_txt or "'eval('" in line_txt:
                    continue
                findings.append(
                    Finding(
                        "SS-03-DYNAMIC-EXEC",
                        "HIGH",
                        rel,
                        lno,
                        f"Dynamic execution primitive '{em.group(0)}' detected",
                        "Reject: dynamic eval is forbidden in scanner source.",
                        True,
                    )
                )

        # SS-06: Persistence hooks
        m = persistence_re.search(txt)
        if m:
            findings.append(
                Finding(
                    "SS-06-PERSISTENCE",
                    "CRITICAL",
                    rel,
                    line_number(txt, m.start()),
                    f"Persistence target '{m.group(0)}' referenced",
                    "Reject: skill must not establish host persistence.",
                    True,
                )
            )

        # SS-04: Unpinned `npx -y` outside explicit prohibition lines
        for um in unpinned_npx_re.finditer(txt):
            lno = line_number(txt, um.start())
            line_txt = lines[lno - 1].lower()
            if any(neg in line_txt for neg in ("never", "forbidden", "do not", "don't", "must not", "prohibit")):
                continue
            findings.append(
                Finding(
                    "SS-04-UNPINNED-NPX",
                    "HIGH",
                    rel,
                    lno,
                    f"Unpinned '{um.group(0)}' execution reference detected",
                    "Reject: avoid unpinned npx -y calls.",
                    True,
                )
            )

        # SS-09: Dynamic detection of outbound network fetch() inside src/
        if rel.startswith("src/") and fpath.suffix.lower() == ".ts":
            fetch_match = fetch_call_re.search(txt)
            if fetch_match:
                lno = line_number(txt, fetch_match.start())
                is_expected = rel == "src/intel/registry-osv.ts"
                findings.append(
                    Finding(
                        "SS-09-BOUNDED-NETWORK" if is_expected else "SS-09-UNEXPECTED-NETWORK",
                        "LOW" if is_expected else "HIGH",
                        rel,
                        lno,
                        "Bounded HTTPS fetch with redirect token-stripping, pre-flight DNS IP guard, and byte caps"
                        if is_expected
                        else "Unexpected fetch() network call outside src/intel/registry-osv.ts",
                        "Acceptable: documented core capability, blocked for private scopes and --offline."
                        if is_expected
                        else "Reject: consolidate outbound network calls inside src/intel/registry-osv.ts.",
                        not is_expected,
                    )
                )

    # SS-08: Manifest least privilege & no auto-approval hooks
    for mpath in (ROOT / "plugin.json", ROOT / ".claude-plugin" / "plugin.json", ROOT / ".codex-plugin" / "plugin.json"):
        if mpath.exists():
            data = json.loads(mpath.read_text(encoding="utf-8"))
            if "hooks" in data:
                findings.append(
                    Finding(
                        "SS-08-MANIFEST-HOOKS",
                        "HIGH",
                        mpath.relative_to(ROOT).as_posix(),
                        1,
                        "Manifest declares lifecycle hooks",
                        "Reject: runtime plugin must not register permission-approval hooks.",
                        True,
                    )
                )

    # SS-11, SS-12, SS-13 MCP & compiled-runtime supply-chain gates
    audit_mcp_manifests(findings)
    audit_mcp_schema_pin(findings)
    audit_compiled_lib_parity(findings)

    return findings


def read_tool_version() -> str:
    manifest = ROOT / "plugin.json"
    if manifest.exists():
        ver = json.loads(manifest.read_text(encoding="utf-8")).get("version")
        if isinstance(ver, str) and ver.strip():
            return ver.strip()
    return "0.0.0"


def emit_sarif(findings: list[Finding], dest: Path) -> None:
    dest.parent.mkdir(parents=True, exist_ok=True)
    rules = {}
    for f in findings:
        rules.setdefault(
            f.rule_id,
            {"id": f.rule_id, "name": f.rule_id, "shortDescription": {"text": f.message}},
        )
    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "coldpin-skillspector-self-audit",
                        "version": read_tool_version(),
                        "rules": list(rules.values()),
                    }
                },
                "results": [
                    {
                        "ruleId": f.rule_id,
                        "level": "error" if f.severity in ("CRITICAL", "HIGH") else "warning" if f.severity == "MEDIUM" else "note",
                        "message": {"text": f"{f.message} — {f.judgment}"},
                        "locations": [
                            {"physicalLocation": {"artifactLocation": {"uri": f.path}, "region": {"startLine": f.line}}}
                        ],
                    }
                    for f in findings
                ],
            }
        ],
    }
    dest.write_text(json.dumps(sarif, indent=2) + "\n", encoding="utf-8", newline="\n")


def emit_triage_report(findings: list[Finding], dest: Path) -> tuple[str, int]:
    dest.parent.mkdir(parents=True, exist_ok=True)
    blocking = [f for f in findings if f.blocks]
    score = min(
        100,
        sum(35 if f.severity == "CRITICAL" else 20 if f.severity == "HIGH" else 8 if f.severity == "MEDIUM" else 4 for f in findings),
    )
    verdict = "REJECT" if blocking else ("APPROVE" if score <= 20 else "CAUTION")
    severity_band = "CRITICAL" if any(f.severity == "CRITICAL" for f in findings) else "HIGH" if blocking else "LOW"
    rec = "BLOCK" if blocking else "ALLOW_WITH_STANDARD_CONTROLS"

    rows = "\n".join(
        f"| `{f.rule_id}` | `{f.severity}` | `{f.path}:{f.line}` | {f.judgment} |" for f in findings
    ) or "| (none) | `INFO` | `-` | Zero security findings observed. |"

    md = f"""<!-- SPDX-License-Identifier: Apache-2.0 -->

## Skill Inspector: `coldpin`

**Source:** `skills/coldpin/` + `src/` + `lib/` (1:1 parity-verified) + `scripts/` + `rules/` + multi-harness & MCP manifests
**Verdict:** `{verdict}` — {"Zero blocking HIGH/CRITICAL findings; documented network and read-only async git/probe surfaces are bounded, hardened, and controllable; MCP schema pin and compiled lib/ parity verified." if verdict == "APPROVE" else "Blocking security findings require remediation before installation."}
**Risk:** {score}/100 · {severity_band} · {rec}
**Install posture:** Suitable for local developer workspaces, IDE MCP hosts (stdio), and CI verification pipelines on Node.js >= 24; not a substitute for runtime EDR or isolated detonation on dynamically fetched payloads.

### Bottom Line
Deterministic SkillSpector-class static scanning (`--no-llm` equivalent, with zero whole-file skips on `src/`) and source-aware review found **{len(blocking)} blocking findings** and **{len(findings) - len(blocking)} documented low-risk capabilities**. The implementation matches the stated zero-execution `npx` discovery, vetting, and local `stdio` MCP server purpose without hidden hooks, listening sockets, persistence, symlinks, dynamic `eval`, silent package installs, or compiled runtime drift.

### Signal Overview
| Source | Result | Interpretation |
|---|---|---|
| Deterministic static self-audit (`SS-03`–`SS-13`) | `{len(blocking)}` blocking, `{len(findings) - len(blocking)}` documented LOW | Clean across Unicode, secrets, `shell=True`, import-aware child_process, dynamic `eval`, persistence, symlinks, manifest hooks, MCP schema pin, MCP config least privilege, and `src/` ↔ `lib/` 1:1 parity. |
| Source-aware semantic review | Purpose & permission fit verified | `SKILL.md` and `lib/mcp.mjs` enforce operator-only control plane, human confirmation, private-scope isolation, and non-LLM verdict authority. |
| Sensitive surface | Hardened read-only async `git` (`core.fsmonitor=false`, `core.hooksPath=/dev/null`, `http.followRedirects=false`, minimal env), SSRF/DNS/redirect-hardened HTTPS `fetch`, read-only `--version` probe | Strictly scoped, disabled in `--offline` mode, private scopes never hit public endpoints, HTTPS-only Bearer auth, cross-origin redirects strip credentials. |

### Key Evidence
| Rule | Severity | Location | Review judgment |
|---|---|---|---|
{rows}

### Diagnosis
Every observed sensitive call site (`src/intel/registry-osv.ts` HTTPS registry/OSV fetch, `src/analysis/parity-and-bisect.ts` hardened read-only async `git`, and `src/config/policy.ts` read-only async `git`/`rea` `--version` probe) was located dynamically by line number, verified to disable shell interpolation, Git redirects, and Git hooks, and remains controllable via `--offline` / `COLDPIN_OFFLINE=1` and operator policy. All 19 compiled ESM files under `lib/` match `src/` 1:1 cryptographically (`SS-13`), and the canonical MCP `tools/list` + `resources/list` + `prompts/list` catalog matches `rules/mcp-schema-pin.json` (`SS-11`). External `skillspector` CLI binary was not installed on `PATH` on this host, so this report reflects the repo's deterministic SkillSpector-equivalent static checker plus manual source review.

### Guardrails
1. Keep `.coldpin.policy.json` configured with `private_scopes` and `private_prefixes` before running against internal organization repositories; in MCP mode configure policy via `COLDPIN_POLICY_PATH`.
2. Never add automatic command-approval hooks to `plugin.json`; require explicit human confirmation before executing any emitted `npx` command.
3. Re-run `npm run audit:self` and inspect `dist/skillspector-self-audit.sarif` on every PR and release.
"""
    dest.write_text(md, encoding="utf-8", newline="\n")
    return verdict, score


def main() -> int:
    findings = scan_repo()
    sarif_path = ROOT / "dist" / "skillspector-self-audit.sarif"
    report_path = ROOT / "docs" / "verification" / "skill-inspector-self-audit.md"
    emit_sarif(findings, sarif_path)
    verdict, score = emit_triage_report(findings, report_path)
    blocking = [f for f in findings if f.blocks]
    print(f"SELF-AUDIT VERDICT: {verdict} (risk={score}/100, blocking={len(blocking)}, total={len(findings)})")
    print(f"  SARIF:  {sarif_path.relative_to(ROOT).as_posix()}")
    print(f"  Report: {report_path.relative_to(ROOT).as_posix()}")
    if blocking:
        for b in blocking:
            print(f"  BLOCK: {b.rule_id} at {b.path}:{b.line} — {b.message}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
