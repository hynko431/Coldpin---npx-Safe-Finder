#!/usr/bin/env python3
"""Reproducible multi-harness allowlist packager for Coldpin (Google EGM pattern).

Builds host-targeted runtime bundles (`antigravity`, `claude`, `openai`, or `all`) from one
canonical source tree (`skill-src/coldpin/` + `src/` + `rules/` + `examples/` + docs):
- Explicit allowlist only (excludes .git, node_modules, tests, caches, audit logs).
- Rejects symlinks, hooks, and paths escaping the repository root.
- Maps `skill-src/coldpin/*` -> `skills/coldpin/*` inside ALL runtime bundles
  (matching Google EGM plugin layout across Antigravity, Claude Code, and Codex CLI).
- Validates manifest asset references and EVERY relative Markdown / image link inside each
  generated archive so no shipped runtime bundle can contain broken references.
- Supports `--no-overwrite` (EGM overwrite-refusal guard) for safe CI/release staging.
- Sorts archive entries and uses fixed timestamps (2026-01-01 00:00:00 UTC) and modes (0644)
  for byte-for-byte reproducibility under the same toolchain.
- Syncs `.agents/skills/coldpin/` when `--sync-workspace` is passed.
"""

import argparse
import hashlib
import json
import posixpath
import re
import shutil
import sys
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIXED_ZIP_TIME = (2026, 1, 1, 0, 0, 0)

SHARED_GLOBS = [
    "README.md",
    "LICENSE",
    "CHANGELOG.md",
    "MAINTENANCE.md",
    "TESTING.md",
    "SECURITY.md",
    "CONTRIBUTING.md",
    "ACCESSIBILITY.md",
    "plugin.json",
    "package.json",
    "tsconfig.json",
    "assets/icon.svg",
    "docs/*.md",
    "docs/assets/*.svg",
    "docs/designs/*.md",
    "docs/verification/*.md",
    "examples/*",
    "examples/.*",
    "rules/triage-rules.json",
    "rules/sigma/*.yml",
    "src/**/*.ts",
    "skill-src/coldpin/SKILL.md",
    "skill-src/coldpin/skill-card.md",
    "skill-src/coldpin/BENCHMARK.md",
    "skill-src/coldpin/TEST.md",
    "skill-src/coldpin/test_scenarios.yaml",
    "skill-src/coldpin/skill.oms.sig",
    "skill-src/coldpin/assets/*",
    "skill-src/coldpin/agents/*",
    "skill-src/coldpin/references/*.md",
    "skill-src/coldpin/evals/*.json",
]

HOST_GLOBS = {
    "antigravity": [],
    "claude": [".claude-plugin/plugin.json", ".claude-plugin/marketplace.json"],
    "openai": [".codex-plugin/plugin.json", ".agents/plugins/marketplace.json"],
}

REQUIRED_ARCHIVE_PATHS = {
    "plugin.json",
    "package.json",
    "README.md",
    "LICENSE",
    "assets/icon.svg",
    "src/cli.ts",
    "rules/triage-rules.json",
    "skills/coldpin/SKILL.md",
    "skills/coldpin/assets/runtime-contract.yaml",
    "skills/coldpin/skill.oms.sig",
}

MD_LINK_RE = re.compile(r"\[[^\]]*\]\(([^)]+)\)")
HTML_REF_RE = re.compile(r"""(?:href|src)=["']([^"']+)["']""")


def collect_target_files(target: str) -> list[tuple[str, Path]]:
    found: dict[str, Path] = {}
    root_resolved = ROOT.resolve()
    patterns = SHARED_GLOBS + HOST_GLOBS[target]
    for pattern in patterns:
        for p in ROOT.glob(pattern):
            if p.is_symlink():
                raise ValueError(f"Symlink rejected in package allowlist: {p}")
            if not p.is_file():
                continue
            resolved = p.resolve()
            try:
                rel = resolved.relative_to(root_resolved).as_posix()
            except ValueError as exc:
                raise ValueError(f"Path escapes repo root: {p}") from exc
            # Map authored skill-src/ -> portable runtime skills/ across ALL runtime targets
            arc_name = rel
            if rel.startswith("skill-src/"):
                arc_name = "skills/" + rel[len("skill-src/"):]
            found[arc_name] = resolved
    return [(k, found[k]) for k in sorted(found.keys())]


def render_archive_bytes(arc_name: str, fpath: Path) -> bytes:
    raw = fpath.read_bytes()
    # Rewrite authored `skill-src/coldpin/` links to packaged `skills/coldpin/` in outer docs
    # without touching signed bytes inside `skills/coldpin/` (preserves skill.oms.sig integrity).
    if arc_name.endswith(".md") and not arc_name.startswith("skills/"):
        text = raw.decode("utf-8").replace("skill-src/coldpin/", "skills/coldpin/")
        return text.encode("utf-8")
    return raw


def validate_archive_contents(target: str, file_bytes: dict[str, bytes]) -> list[str]:
    errors: list[str] = []
    arc_names = set(file_bytes.keys())

    # 1. Verify required core paths exist
    for req in sorted(REQUIRED_ARCHIVE_PATHS):
        if req not in arc_names:
            errors.append(f"[{target}] missing required archive path: {req}")

    # 2. Verify manifest paths & zero hooks
    for manifest_name in ("plugin.json", ".claude-plugin/plugin.json", ".codex-plugin/plugin.json"):
        if manifest_name not in file_bytes:
            continue
        m = json.loads(file_bytes[manifest_name].decode("utf-8"))
        if "hooks" in m:
            errors.append(f"[{target}] manifest {manifest_name} must not declare lifecycle hooks")
        logo = m.get("logo")
        if isinstance(logo, str):
            norm_logo = posixpath.normpath(logo)
            if norm_logo not in arc_names:
                errors.append(f"[{target}] {manifest_name} logo '{logo}' missing from archive")
        skills_dir = m.get("skills")
        if isinstance(skills_dir, str):
            prefix = skills_dir.strip("./") + "/"
            if not any(n.startswith(prefix) and n.endswith("/SKILL.md") for n in arc_names):
                errors.append(f"[{target}] {manifest_name} skills dir '{skills_dir}' has no packaged SKILL.md")
        ext_iface = m.get("extensions", {}).get("com.openai", {}).get("interface", {})
        for icon_key in ("composerIcon", "logo"):
            icon_val = ext_iface.get(icon_key)
            if isinstance(icon_val, str):
                norm_icon = posixpath.normpath(icon_val)
                if norm_icon not in arc_names:
                    errors.append(f"[{target}] {manifest_name} interface.{icon_key} '{icon_val}' missing from archive")

    # 3. Validate relative Markdown & HTML links inside packaged Markdown docs
    for arc_name, raw in sorted(file_bytes.items()):
        if not arc_name.endswith(".md"):
            continue
        text = raw.decode("utf-8")
        # Strip fenced code blocks before checking links
        stripped = re.sub(r"```[\s\S]*?```", "", text)
        base_dir = posixpath.dirname(arc_name)
        refs = [m.group(1).strip() for m in MD_LINK_RE.finditer(stripped)]
        refs.extend(m.group(1).strip() for m in HTML_REF_RE.finditer(stripped))
        for ref in refs:
            if not ref or ref.startswith(("http://", "https://", "mailto:", "#", "<")):
                continue
            target_part = ref.split("#", 1)[0].split("?", 1)[0].strip()
            if not target_part:
                continue
            resolved = posixpath.normpath(posixpath.join(base_dir, target_part)) if base_dir else posixpath.normpath(target_part)
            if resolved.startswith(".."):
                errors.append(f"[{target}] {arc_name}: relative link escapes archive root: {ref}")
                continue
            if resolved not in arc_names and not any(n.startswith(resolved + "/") for n in arc_names):
                errors.append(f"[{target}] {arc_name}: broken packaged relative link '{ref}' (resolved '{resolved}')")

    return errors


def build_reproducible_zip(dest_zip: Path, items: list[tuple[str, Path]], target: str) -> str:
    file_bytes: dict[str, bytes] = {arc_name: render_archive_bytes(arc_name, fpath) for arc_name, fpath in items}
    errors = validate_archive_contents(target, file_bytes)
    if errors:
        raise ValueError("Packaged archive validation failed:\n  - " + "\n  - ".join(errors))

    dest_zip.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest_zip, "w", compression=zipfile.ZIP_DEFLATED, compresslevel=9) as zf:
        for arc_name in sorted(file_bytes.keys()):
            info = zipfile.ZipInfo(filename=arc_name, date_time=FIXED_ZIP_TIME)
            info.compress_type = zipfile.ZIP_DEFLATED
            info.external_attr = 0o644 << 16
            zf.writestr(info, file_bytes[arc_name])
    return hashlib.sha256(dest_zip.read_bytes()).hexdigest()


def sync_workspace_skill_mirror() -> Path:
    src_skill = ROOT / "skill-src" / "coldpin"
    dest_skill = ROOT / ".agents" / "skills" / "coldpin"
    legacy_skill = ROOT / ".agents" / "skills" / "npx-safe-finder"
    if legacy_skill.exists():
        shutil.rmtree(legacy_skill)
    if dest_skill.exists():
        shutil.rmtree(dest_skill)
    dest_skill.parent.mkdir(parents=True, exist_ok=True)
    for fpath in sorted(src_skill.rglob("*")):
        if fpath.is_symlink():
            raise ValueError(f"Symlink rejected in skill-src: {fpath}")
        if not fpath.is_file():
            continue
        rel = fpath.relative_to(src_skill)
        out = dest_skill / rel
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_bytes(fpath.read_bytes())
    return dest_skill


def main() -> int:
    parser = argparse.ArgumentParser(description="Build reproducible multi-harness Coldpin bundles.")
    parser.add_argument("--target", choices=["antigravity", "claude", "openai", "all"], default="all")
    parser.add_argument("--out-dir", default=str(ROOT / "dist"))
    parser.add_argument("--verify", action="store_true", help="Build twice and assert identical SHA-256 bytes.")
    parser.add_argument("--no-overwrite", action="store_true", help="Refuse to overwrite existing target zip archives (EGM pattern).")
    parser.add_argument("--sync-workspace", action="store_true", help="Mirror skill-src into .agents/skills/coldpin.")
    args = parser.parse_args()

    targets = ["antigravity", "claude", "openai"] if args.target == "all" else [args.target]
    out_dir = Path(args.out_dir)

    for target in targets:
        out_zip = out_dir / f"coldpin-{target}.zip"
        if args.no_overwrite and out_zip.exists():
            print(f"FAIL: refusing to overwrite existing archive (--no-overwrite): {out_zip}", file=sys.stderr)
            return 1
        items = collect_target_files(target)
        sha1 = build_reproducible_zip(out_zip, items, target)
        if args.verify:
            verify_zip = out_zip.with_suffix(".verify.zip")
            try:
                sha2 = build_reproducible_zip(verify_zip, items, target)
            finally:
                verify_zip.unlink(missing_ok=True)
            if sha1 != sha2:
                print(f"FAIL: non-reproducible archive for {target} ({sha1} != {sha2})", file=sys.stderr)
                return 1
            print(f"PACK REPRODUCIBLE OK [{target}]: {len(items)} files -> {out_zip.name} (sha256={sha1[:16]}...)")
        else:
            print(f"PACK OK [{target}]: {len(items)} files -> {out_zip} (sha256={sha1[:16]}...)")

    # Remove legacy stale bundle zips if present in default dist dir
    if out_dir.resolve() == (ROOT / "dist").resolve():
        for stale in out_dir.glob("npx-safe-finder-*.zip"):
            stale.unlink(missing_ok=True)

    if args.sync_workspace:
        mirror = sync_workspace_skill_mirror()
        print(f"WORKSPACE SKILL MIRROR SYNCED: {mirror}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
