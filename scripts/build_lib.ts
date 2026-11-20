#!/usr/bin/env node
import { execFileSync } from "node:child_process";
import { createHash } from "node:crypto";
import {
  chmodSync,
  existsSync,
  lstatSync,
  mkdirSync,
  readdirSync,
  readFileSync,
  rmSync,
  writeFileSync,
} from "node:fs";
import { stripTypeScriptTypes } from "node:module";
import { dirname, join, relative, resolve } from "node:path";

const REPO_ROOT = resolve(import.meta.dirname, "..");
const SRC_DIR = join(REPO_ROOT, "src");
const LIB_DIR = join(REPO_ROOT, "lib");
const PIN_PATH = join(REPO_ROOT, "rules", "mcp-schema-pin.json");

function walkFiles(dir: string, suffix: string, out: string[] = []): string[] {
  if (!existsSync(dir)) return out;
  const entries = readdirSync(dir, { withFileTypes: true }).sort((a, b) => a.name.localeCompare(b.name));
  for (const entry of entries) {
    const full = join(dir, entry.name);
    const lst = lstatSync(full);
    if (lst.isSymbolicLink()) {
      throw new Error(`Refusing symlink in build tree: ${full}`);
    }
    if (entry.isDirectory()) {
      walkFiles(full, suffix, out);
    } else if (entry.isFile() && entry.name.endsWith(suffix)) {
      out.push(full);
    }
  }
  return out;
}

/**
 * Anchored ESM relative specifier rewriter:
 * Rewrites ONLY relative import/export/dynamic-import `.ts` specifiers to `.mjs`
 * while preserving literal `.ts` strings (such as CLI usage text and static-triage regexes).
 */
export function rewriteRelativeTsImports(code: string): string {
  return code
    .replace(/(\b(?:from|import)\s*["'])(\.{1,2}\/[^"'\r\n]+)\.ts(["'])/g, "$1$2.mjs$3")
    .replace(/(\bimport\s*\(\s*["'])(\.{1,2}\/[^"'\r\n]+)\.ts(["']\s*\))/g, "$1$2.mjs$3");
}

export function compileTsSourceToMjs(tsSource: string, sourceUrl: string): string {
  const normalizedInput = tsSource.replace(/\r\n/g, "\n");
  const hasShebang = normalizedInput.startsWith("#!/usr/bin/env node\n");
  const body = hasShebang ? normalizedInput.slice("#!/usr/bin/env node\n".length) : normalizedInput;
  const stripped = stripTypeScriptTypes(body, { mode: "strip", sourceUrl });
  const rewritten = rewriteRelativeTsImports(stripped).replace(/\r\n/g, "\n");
  const finalCode = `${hasShebang ? "#!/usr/bin/env node\n" : ""}${rewritten}`;
  return finalCode.endsWith("\n") ? finalCode : `${finalCode}\n`;
}

function sha256Hex(buf: Buffer | string): string {
  return createHash("sha256").update(buf).digest("hex");
}

function removeEmptyDirs(dir: string): void {
  if (!existsSync(dir)) return;
  for (const entry of readdirSync(dir, { withFileTypes: true })) {
    if (entry.isDirectory()) {
      const sub = join(dir, entry.name);
      removeEmptyDirs(sub);
      if (readdirSync(sub).length === 0) {
        rmSync(sub, { recursive: true, force: true });
      }
    }
  }
}

async function main(): Promise<void> {
  const args = new Set(process.argv.slice(2));
  const checkOnly = args.has("--check");
  const updatePin = args.has("--update-pin");

  const srcFiles = walkFiles(SRC_DIR, ".ts");
  if (srcFiles.length === 0) {
    throw new Error("No TypeScript files found under src/.");
  }

  const expectedOutputs = new Map<string, { content: string; hasShebang: boolean }>();
  for (const srcPath of srcFiles) {
    const rel = relative(SRC_DIR, srcPath).replace(/\\/g, "/");
    const relMjs = rel.replace(/\.ts$/, ".mjs");
    const outPath = join(LIB_DIR, relMjs);
    const tsSource = readFileSync(srcPath, "utf8");
    const compiled = compileTsSourceToMjs(tsSource, rel);
    expectedOutputs.set(outPath, {
      content: compiled,
      hasShebang: compiled.startsWith("#!/usr/bin/env node\n"),
    });
  }

  if (checkOnly) {
    const actualFiles = new Set(walkFiles(LIB_DIR, ".mjs"));
    const errors: string[] = [];
    for (const [outPath, expected] of expectedOutputs) {
      if (!actualFiles.has(outPath)) {
        errors.push(`MISSING: ${relative(REPO_ROOT, outPath)}`);
        continue;
      }
      actualFiles.delete(outPath);
      const actualBuf = readFileSync(outPath);
      if (sha256Hex(actualBuf) !== sha256Hex(Buffer.from(expected.content, "utf8"))) {
        errors.push(`DRIFT: ${relative(REPO_ROOT, outPath)}`);
      }
    }
    for (const orphan of actualFiles) {
      errors.push(`ORPHAN: ${relative(REPO_ROOT, orphan)}`);
    }
    if (errors.length > 0) {
      process.stderr.write(`Compiled lib/ parity check FAILED:\n${errors.join("\n")}\n`);
      process.exit(1);
    }
    process.stdout.write(`LIB_PARITY_OK (${expectedOutputs.size} files verified)\n`);
    return;
  }

  mkdirSync(LIB_DIR, { recursive: true });
  const existingLibFiles = new Set(walkFiles(LIB_DIR, ".mjs"));
  let written = 0;

  for (const [outPath, { content, hasShebang }] of expectedOutputs) {
    existingLibFiles.delete(outPath);
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, Buffer.from(content, "utf8"));
    if (hasShebang && process.platform !== "win32") {
      try {
        chmodSync(outPath, 0o755);
      } catch {
        // Best-effort chmod
      }
    }
    // Syntax-check every emitted ESM file
    execFileSync(process.execPath, ["--check", outPath], { stdio: "pipe" });
    written++;
  }

  // Prune any orphaned .mjs files under lib/
  for (const orphan of existingLibFiles) {
    rmSync(orphan, { force: true });
  }
  removeEmptyDirs(LIB_DIR);

  if (updatePin) {
    const { computeMcpSchemaPin } = await import("../src/mcp/tool-catalog.ts");
    const pin = computeMcpSchemaPin();
    writeFileSync(PIN_PATH, `${JSON.stringify(pin, null, 2)}\n`, "utf8");
    process.stdout.write(
      `Updated rules/mcp-schema-pin.json (tools=${pin.tools_count}, chars=${pin.tools_list_chars}, est_tokens=${pin.estimated_tokens}, catalog_sha256=${pin.catalog_sha256.slice(0, 16)}...)\n`,
    );
  }

  process.stdout.write(`BUILD_LIB_OK: emitted and syntax-checked ${written} ESM files under lib/\n`);
}

await main();
