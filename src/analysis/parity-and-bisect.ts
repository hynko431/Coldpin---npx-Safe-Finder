import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { promisify } from "node:util";
import { buildFactCacheKey, type SplitPlaneCache } from "../cache/sqlite-store.ts";
import { isPrivateOrReservedIp, type ProvenanceInspectionResult } from "../intel/registry-osv.ts";
import type {
  AdvisoryRecord,
  CommitAuditSummary,
  EvidenceRecord,
  Observation,
  PackageManifest,
  ParityResult,
  PolicyConfig,
  ProvenanceStatus,
  SafeAnchorDecision,
  TarEntry,
  TrustVerdict,
} from "../types.ts";
import {
  analyzeSourceBlob,
  DANGEROUS_LIFECYCLE_CMD_RE,
  hasModuleTaintData,
  isSafeNpmBinName,
  isSafeNpmPackageName,
  isSafeNpmVersion,
  LIFECYCLE_HOOKS,
  resolveCrossFileTaint,
  RULESET_SHA256,
  sanitizeUntrustedText,
  type ModuleTaintSummary,
} from "./static-triage.ts";

const execFileAsync = promisify(execFile);

const SAFE_GIT_CONFIG_ARGS = [
  "-c",
  "core.fsmonitor=false",
  "-c",
  "core.hooksPath=/dev/null",
  "-c",
  "protocol.allow=never",
  "-c",
  "protocol.https.allow=always",
  "-c",
  "http.followRedirects=false",
  "-c",
  "credential.helper=",
  "-c",
  "diff.external=",
];

const ALLOWLISTED_GIT_ENV_KEYS = [
  "PATH",
  "Path",
  "PATHEXT",
  "SYSTEMROOT",
  "SystemRoot",
  "COMSPEC",
  "ComSpec",
  "WINDIR",
  "TEMP",
  "TMP",
  "TMPDIR",
  "HOME",
  "USERPROFILE",
  "LANG",
  "LC_ALL",
  "SSL_CERT_FILE",
  "SSL_CERT_DIR",
  "NODE_EXTRA_CA_CERTS",
] as const;

function buildSafeGitEnv(): NodeJS.ProcessEnv {
  // Security [MCP-09]: never spread full process.env (prevents leaking GITHUB_TOKEN, AWS_*, NPM_TOKEN to git subprocesses)
  const env: NodeJS.ProcessEnv = {
    GIT_TERMINAL_PROMPT: "0",
    GIT_CONFIG_NOSYSTEM: "1",
    GIT_CONFIG_GLOBAL: process.platform === "win32" ? "NUL" : "/dev/null",
  };
  for (const key of ALLOWLISTED_GIT_ENV_KEYS) {
    const val = process.env[key];
    if (val !== undefined) env[key] = val;
  }
  return env;
}

const ACTIVE_GIT_TEMP_DIRS = new Set<string>();

export function cleanupActiveGitTempDirs(): void {
  for (const dir of Array.from(ACTIVE_GIT_TEMP_DIRS)) {
    try {
      rmSync(dir, { recursive: true, force: true });
    } catch {
      // Best-effort shutdown cleanup
    }
    ACTIVE_GIT_TEMP_DIRS.delete(dir);
  }
}

function isBlockedRemoteGitHost(rawHost: string): boolean {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (isPrivateOrReservedIp(host)) return true;
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "metadata.google.internal" ||
    host === "metadata.goog" ||
    host === "100.100.100.200" ||
    host === "::1" ||
    host === "::" ||
    host === "0:0:0:0:0:0:0:1" ||
    host === "0:0:0:0:0:0:0:0" ||
    host === "fd00:ec2::254"
  ) {
    return true;
  }
  // IPv4 loopback, link-local/metadata, unspecified, RFC1918, CGNAT 100.64.0.0/10
  if (
    host.startsWith("127.") ||
    host.startsWith("0.") ||
    host.startsWith("169.254.") ||
    host.startsWith("10.") ||
    host.startsWith("192.168.") ||
    /^100\.(?:6[4-9]|[7-9]\d|1[01]\d|12[0-7])\./.test(host) ||
    /^172\.(?:1[6-9]|2\d|3[01])\./.test(host)
  ) {
    return true;
  }
  // IPv6 link-local (fe80::/10) and ULA (fc00::/7)
  if (/^fe[89ab][0-9a-f]:/.test(host) || /^f[cd][0-9a-f]{2}:/.test(host)) {
    return true;
  }
  if (host.startsWith("::ffff:")) {
    const mapped = host.slice("::ffff:".length);
    if (mapped.includes(".")) return isBlockedRemoteGitHost(mapped);
    const hexParts = mapped.split(":");
    if (hexParts.length === 2) {
      const hi = Number.parseInt(hexParts[0]!, 16);
      const lo = Number.parseInt(hexParts[1]!, 16);
      if (Number.isFinite(hi) && Number.isFinite(lo)) {
        const ipv4 = `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
        return isBlockedRemoteGitHost(ipv4);
      }
    }
    return true;
  }
  return false;
}

export function validateRemoteGitUrl(rawUrl: string): { valid: boolean; reason?: string } {
  const trimmed = rawUrl.trim();
  if (!trimmed || trimmed.length > 256 || trimmed.startsWith("-") || /[\x00-\x1f\s]/.test(trimmed)) {
    return { valid: false, reason: "Invalid, oversized (>256 chars), or option-like Git URL rejected (CWE-88 defense)." };
  }
  if (/^ext::/i.test(trimmed)) {
    return { valid: false, reason: "Git ext:: remote helper protocol is forbidden." };
  }
  let parsed: URL;
  try {
    parsed = new URL(trimmed);
  } catch {
    return { valid: false, reason: "Malformed remote Git URL." };
  }
  if (parsed.protocol !== "https:") {
    return { valid: false, reason: `Remote Git protocol '${parsed.protocol}' rejected; only https:// is permitted.` };
  }
  // Security [MCP-04]: reject query strings, fragments, and embedded userinfo to prevent exfil beacons
  if (parsed.username || parsed.password) {
    return { valid: false, reason: "Remote Git URL with embedded userinfo/credentials is forbidden." };
  }
  if (parsed.search || trimmed.includes("?") || parsed.hash || trimmed.includes("#")) {
    return { valid: false, reason: "Remote Git URL query parameters and fragments are forbidden." };
  }
  const host = parsed.hostname.toLowerCase();
  if (isBlockedRemoteGitHost(host)) {
    return { valid: false, reason: `Remote Git host '${host}' blocked by SSRF guard.` };
  }
  return { valid: true };
}

export function validateGitRef(ref: string): boolean {
  return ref === "HEAD" || /^[0-9a-f]{40}$/i.test(ref);
}

export function validateGitSubdir(subdir: string): boolean {
  if (!subdir) return true;
  if (subdir.startsWith("-") || subdir.startsWith("/") || subdir.includes("\\") || /[\x00-\x1f]/.test(subdir)) {
    return false;
  }
  return !subdir.split("/").some((seg) => seg === ".." || seg === ".");
}

async function runGit(
  args: string[],
  cwd: string,
  timeoutMs = 15000,
  signal?: AbortSignal,
): Promise<{ ok: boolean; stdout: string; stderr: string }> {
  try {
    const { stdout, stderr } = await execFileAsync("git", [...SAFE_GIT_CONFIG_ARGS, ...args], {
      cwd,
      encoding: "utf8",
      env: buildSafeGitEnv(),
      timeout: timeoutMs,
      maxBuffer: 24 * 1024 * 1024,
      windowsHide: true,
      ...(signal ? { signal } : {}),
    });
    return { ok: true, stdout, stderr: stderr ?? "" };
  } catch (err) {
    const e = err as { stderr?: string | Buffer; message?: string };
    return {
      ok: false,
      stdout: "",
      stderr: typeof e.stderr === "string" ? e.stderr : e.stderr?.toString("utf8") ?? e.message ?? "git error",
    };
  }
}

async function runGitBuffer(
  args: string[],
  cwd: string,
  timeoutMs = 15000,
  signal?: AbortSignal,
): Promise<Buffer | null> {
  try {
    // CRITICAL: explicit `encoding: "buffer"` is mandatory under promisify(execFile)
    // because default encoding is "utf8" (unlike execFileSync), which corrupts binary .wasm/.node blobs!
    const { stdout } = await execFileAsync("git", [...SAFE_GIT_CONFIG_ARGS, ...args], {
      cwd,
      encoding: "buffer",
      env: buildSafeGitEnv(),
      timeout: timeoutMs,
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
      ...(signal ? { signal } : {}),
    });
    return Buffer.isBuffer(stdout) ? stdout : Buffer.from(stdout);
  } catch {
    return null;
  }
}

export async function extractCommitDirectDependencies(
  localGitDir: string,
  commitSha: string,
  subdir?: string,
  signal?: AbortSignal,
): Promise<{ deps: Array<{ name: string; version?: string; isFloating: boolean }>; binName?: string }> {
  if (!validateGitRef(commitSha) || (subdir && !validateGitSubdir(subdir))) {
    return { deps: [] };
  }
  const prefix = subdir ? `${subdir.replace(/^\/+|\/+$/g, "")}/` : "";
  const buf = await runGitBuffer(["show", `${commitSha}:${prefix}package.json`], localGitDir, 15000, signal);
  if (!buf) return { deps: [] };
  try {
    const pkg = JSON.parse(buf.toString("utf8")) as PackageManifest;
    const combined = { ...(pkg.dependencies ?? {}), ...(pkg.optionalDependencies ?? {}) };
    const deps = Object.entries(combined)
      .slice(0, 50)
      .map(([name, range]) => {
        const clean = typeof range === "string" ? range.trim() : "";
        const exact = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(clean);
        return { name, version: exact ? clean : undefined, isFloating: !exact };
      });
    let binName: string | undefined;
    if (typeof pkg.bin === "string" && pkg.name) {
      binName = pkg.name.includes("/") ? pkg.name.slice(pkg.name.indexOf("/") + 1) : pkg.name;
    } else if (pkg.bin && typeof pkg.bin === "object") {
      binName = Object.keys(pkg.bin)[0];
    }
    return { deps, binName };
  } catch {
    return { deps: [] };
  }
}

function normalizedRecord(rec?: Record<string, string>): string {
  if (!rec) return "{}";
  return JSON.stringify(
    Object.keys(rec)
      .sort()
      .reduce<Record<string, string>>((acc, k) => {
        acc[k] = rec[k]!;
        return acc;
      }, {}),
  );
}

/**
 * 3-Tier Provenance-Aware Tarball-vs-Git Parity Verification:
 * - Gold: PROVENANCE_ATTESTED (ONLY when full Sigstore/SLSA cryptographic verification succeeded)
 * - Unanchored / Metadata-Only: PROVENANCE_UNANCHORED_DSSE or PROVENANCE_METADATA_UNVERIFIED
 *   (explicitly sets provenance_attested=false and discloses Fulcio/Rekor trust boundaries)
 * - Silver: MANIFEST_PARITY_VERIFIED (package.json scripts/bin/dependencies match gitHead)
 * - Bronze: COMPILED_DIST_UNATTESTED vs TARBALL_SOURCE_DRIFT (handles TypeScript dist/ cleanly!)
 */
export async function verifyTarballVsGitParity(params: {
  tarballManifest: PackageManifest | null;
  tarballEntries: TarEntry[];
  provenanceAttested: boolean;
  provenanceStatus?: ProvenanceStatus;
  provenanceUrl?: string;
  provenanceInspection?: ProvenanceInspectionResult;
  gitHead?: string;
  repositoryUrl?: string;
  localGitDir?: string;
  subdir?: string;
  signal?: AbortSignal;
}): Promise<ParityResult> {
  const observations: Observation[] = [];
  const unknowns: string[] = [];

  const effectiveStatus: ProvenanceStatus =
    params.provenanceInspection?.status ??
    params.provenanceStatus ??
    (params.provenanceAttested ? "sigstore_verified" : params.provenanceUrl ? "metadata_url_only" : "none");
  const cryptoVerified = effectiveStatus === "sigstore_verified" && params.provenanceAttested;
  const provUrl = params.provenanceInspection?.provenance_url ?? params.provenanceUrl;

  if (params.provenanceInspection) {
    observations.push(...params.provenanceInspection.observations);
    unknowns.push(...params.provenanceInspection.unknowns);
  } else if (effectiveStatus === "metadata_url_only") {
    unknowns.push(
      "PROVENANCE_CRYPTO_UNVERIFIED: registry metadata advertises dist.attestations.url, but Sigstore/SLSA cryptographic verification (Fulcio CA chain + Rekor transparency log) was not performed.",
    );
  } else if (effectiveStatus === "dsse_leaf_verified_unanchored") {
    unknowns.push(
      "PROVENANCE_TRUST_ROOT_UNVERIFIED: SLSA DSSE signature verified against bundled leaf certificate, but Sigstore Fulcio CA chain and Rekor transparency-log proofs were NOT verified locally.",
    );
  }

  if (!params.localGitDir) {
    if (effectiveStatus === "verification_failed") {
      return {
        tier: "TARBALL_SOURCE_DRIFT",
        git_head: params.gitHead,
        repository_url: params.repositoryUrl,
        provenance_attested: false,
        provenance_status: "verification_failed",
        provenance_url: provUrl,
        observations,
        unknowns,
      };
    }
    if (cryptoVerified) {
      return {
        tier: "PROVENANCE_ATTESTED",
        git_head: params.gitHead,
        repository_url: params.repositoryUrl,
        provenance_attested: true,
        provenance_status: "sigstore_verified",
        provenance_url: provUrl,
        observations,
        unknowns,
      };
    }
    if (effectiveStatus === "dsse_leaf_verified_unanchored") {
      return {
        tier: "PROVENANCE_UNANCHORED_DSSE",
        git_head: params.gitHead,
        repository_url: params.repositoryUrl,
        provenance_attested: false,
        provenance_status: "dsse_leaf_verified_unanchored",
        provenance_url: provUrl,
        observations,
        unknowns,
      };
    }
    if (effectiveStatus === "metadata_url_only") {
      return {
        tier: "PROVENANCE_METADATA_UNVERIFIED",
        git_head: params.gitHead,
        repository_url: params.repositoryUrl,
        provenance_attested: false,
        provenance_status: "metadata_url_only",
        provenance_url: provUrl,
        observations,
        unknowns,
      };
    }
    if (!params.gitHead) {
      unknowns.push("SOURCE_UNLINKED: no npm provenance attestation and no gitHead/repository linked.");
      return {
        tier: "SOURCE_UNLINKED",
        repository_url: params.repositoryUrl,
        provenance_attested: false,
        provenance_status: effectiveStatus,
        provenance_url: provUrl,
        observations,
        unknowns,
      };
    }
    unknowns.push(
      `PARITY_GIT_NOT_FETCHED: gitHead '${params.gitHead}' recorded, but local Git checkout was not supplied for manifest diff.`,
    );
    return {
      tier: "COMPILED_DIST_UNATTESTED",
      git_head: params.gitHead,
      repository_url: params.repositoryUrl,
      provenance_attested: false,
      provenance_status: effectiveStatus,
      provenance_url: provUrl,
      observations,
      unknowns,
    };
  }

  const ref = params.gitHead ?? "HEAD";
  if (!validateGitRef(ref)) {
    observations.push({
      code: "TARBALL_SOURCE_DRIFT_INVALID_GIT_HEAD",
      severity: "CRITICAL",
      path: "package.json",
      attack_id: "T1195.002",
      detail: `Rejected malformed or option-like gitHead value '${sanitizeUntrustedText(ref, 64)}' (must be 40-char hex SHA).`,
    });
    return {
      tier: "TARBALL_SOURCE_DRIFT",
      git_head: undefined,
      repository_url: params.repositoryUrl,
      provenance_attested: false,
      provenance_status: effectiveStatus,
      provenance_url: provUrl,
      observations,
      unknowns,
    };
  }
  if (params.subdir && !validateGitSubdir(params.subdir)) {
    unknowns.push(`INVALID_GIT_SUBDIR: rejected unsafe subdir '${sanitizeUntrustedText(params.subdir, 64)}'.`);
    return {
      tier: effectiveStatus === "verification_failed" ? "TARBALL_SOURCE_DRIFT" : "SOURCE_UNLINKED",
      git_head: params.gitHead,
      repository_url: params.repositoryUrl,
      provenance_attested: false,
      provenance_status: effectiveStatus,
      provenance_url: provUrl,
      observations,
      unknowns,
    };
  }
  const prefix = params.subdir ? `${params.subdir.replace(/^\/+|\/+$/g, "")}/` : "";
  const gitPkgBuf = await runGitBuffer(["show", `${ref}:${prefix}package.json`], params.localGitDir, 15000, params.signal);
  if (!gitPkgBuf || !params.tarballManifest) {
    unknowns.push(`GIT_MANIFEST_UNREADABLE: could not read '${ref}:${prefix}package.json' from local Git repo.`);
    return {
      tier: effectiveStatus === "verification_failed" ? "TARBALL_SOURCE_DRIFT" : "SOURCE_UNLINKED",
      git_head: params.gitHead,
      repository_url: params.repositoryUrl,
      provenance_attested: false,
      provenance_status: effectiveStatus,
      provenance_url: provUrl,
      observations,
      unknowns,
    };
  }

  let gitManifest: PackageManifest;
  try {
    gitManifest = JSON.parse(gitPkgBuf.toString("utf8")) as PackageManifest;
  } catch {
    unknowns.push("GIT_MANIFEST_INVALID_JSON");
    return {
      tier: effectiveStatus === "verification_failed" ? "TARBALL_SOURCE_DRIFT" : "SOURCE_UNLINKED",
      git_head: params.gitHead,
      repository_url: params.repositoryUrl,
      provenance_attested: false,
      provenance_status: effectiveStatus,
      provenance_url: provUrl,
      observations,
      unknowns,
    };
  }

  // Silver check: compare security-critical manifest fields (scripts, bin, dependencies, optionalDependencies)
  let driftDetected = false;

  if (normalizedRecord(params.tarballManifest.scripts) !== normalizedRecord(gitManifest.scripts)) {
    driftDetected = true;
    observations.push({
      code: "TARBALL_SOURCE_DRIFT_SCRIPTS",
      severity: "CRITICAL",
      path: "package.json",
      attack_id: "T1195.002",
      detail: "Tarball package.json 'scripts' diverge from Git source commit (potential tarball-only lifecycle hook injection).",
    });
  }

  if (JSON.stringify(params.tarballManifest.bin ?? null) !== JSON.stringify(gitManifest.bin ?? null)) {
    driftDetected = true;
    observations.push({
      code: "TARBALL_SOURCE_DRIFT_BIN",
      severity: "HIGH",
      path: "package.json",
      attack_id: "T1195.002",
      detail: "Tarball package.json 'bin' entrypoints diverge from Git source commit.",
    });
  }

  if (
    normalizedRecord(params.tarballManifest.dependencies) !== normalizedRecord(gitManifest.dependencies) ||
    normalizedRecord(params.tarballManifest.optionalDependencies) !== normalizedRecord(gitManifest.optionalDependencies)
  ) {
    driftDetected = true;
    observations.push({
      code: "TARBALL_SOURCE_DRIFT_DEPS",
      severity: "HIGH",
      path: "package.json",
      attack_id: "T1195.002",
      detail: "Tarball package.json dependencies or optionalDependencies diverge from Git source commit.",
    });
  }

  // Check if non-build JS files in tarball exist in Git and match SHA-256
  const treeList = await runGit(
    ["ls-tree", "-r", ref, ...(prefix ? [prefix.slice(0, -1)] : [])],
    params.localGitDir,
    15000,
    params.signal,
  );
  const gitFilePaths = new Set<string>();
  let hasBuildConfig = false;
  if (treeList.ok) {
    for (const line of treeList.stdout.split(/\r?\n/)) {
      const tabIdx = line.indexOf("\t");
      if (tabIdx === -1) continue;
      let p = line.slice(tabIdx + 1).trim();
      if (prefix && p.startsWith(prefix)) p = p.slice(prefix.length);
      gitFilePaths.add(p);
      if (
        p === "tsconfig.json" ||
        p.startsWith("tsup.config") ||
        p.startsWith("esbuild") ||
        p.startsWith("rollup.config") ||
        p.startsWith("webpack.config") ||
        p.startsWith("vite.config")
      ) {
        hasBuildConfig = true;
      }
    }
  }

  let hasCompiledDistOnly = false;
  for (const entry of params.tarballEntries) {
    if (entry.path === "package.json") continue;
    if (gitFilePaths.has(entry.path)) {
      const gitBlob = await runGitBuffer(["show", `${ref}:${prefix}${entry.path}`], params.localGitDir, 15000, params.signal);
      if (gitBlob) {
        const gitSha = createHash("sha256").update(gitBlob).digest("hex");
        if (gitSha !== entry.sha256) {
          driftDetected = true;
          observations.push({
            code: "TARBALL_SOURCE_DRIFT_FILE_MODIFIED",
            severity: "CRITICAL",
            path: entry.path,
            digest_sha256: entry.sha256,
            attack_id: "T1195.002",
            detail: `Published tarball file '${entry.path}' differs byte-for-byte from Git commit '${ref}'.`,
          });
        }
      }
    } else if (/^(dist|build|lib|out)\//.test(entry.path) && hasBuildConfig) {
      hasCompiledDistOnly = true;
    } else if (/\.(js|mjs|cjs|sh|ps1|bat|cmd|node|wasm)$/i.test(entry.path)) {
      driftDetected = true;
      observations.push({
        code: "TARBALL_SOURCE_DRIFT_EXTRA_EXEC",
        severity: "CRITICAL",
        path: entry.path,
        digest_sha256: entry.sha256,
        attack_id: "T1195.002",
        detail: `Unexplained executable/script file '${entry.path}' in tarball is absent from Git source commit '${ref}'.`,
      });
    }
  }

  if (driftDetected || effectiveStatus === "verification_failed") {
    return {
      tier: "TARBALL_SOURCE_DRIFT",
      git_head: params.gitHead,
      repository_url: params.repositoryUrl,
      provenance_attested: false,
      provenance_status: effectiveStatus === "verification_failed" ? "verification_failed" : effectiveStatus,
      provenance_url: provUrl,
      observations,
      unknowns,
    };
  }

  if (hasCompiledDistOnly) {
    if (cryptoVerified) {
      return {
        tier: "PROVENANCE_ATTESTED",
        git_head: params.gitHead,
        repository_url: params.repositoryUrl,
        provenance_attested: true,
        provenance_status: "sigstore_verified",
        provenance_url: provUrl,
        observations,
        unknowns,
      };
    }
    unknowns.push("COMPILED_DIST_UNATTESTED: compiled build output present in tarball without cryptographically verified SLSA provenance; manifest & source files match gitHead.");
    return {
      tier: "COMPILED_DIST_UNATTESTED",
      git_head: params.gitHead,
      repository_url: params.repositoryUrl,
      provenance_attested: false,
      provenance_status: effectiveStatus,
      provenance_url: provUrl,
      observations,
      unknowns,
    };
  }

  return {
    tier: cryptoVerified ? "PROVENANCE_ATTESTED" : "MANIFEST_PARITY_VERIFIED",
    git_head: params.gitHead,
    repository_url: params.repositoryUrl,
    provenance_attested: cryptoVerified,
    provenance_status: effectiveStatus,
    provenance_url: provUrl,
    observations,
    unknowns,
  };
}

interface CachedBlobFacts {
  observations: Observation[];
  inferences: string[];
  unknowns: string[];
  has_obfuscation: boolean;
  has_native_or_wasm: boolean;
  module_taint?: ModuleTaintSummary;
}

function isAdvisoryPolicyBlocking(advisories: AdvisoryRecord[], policy: PolicyConfig): boolean {
  return advisories.some(
    (a) =>
      a.is_malicious ||
      (policy.block_on_kev && a.kev) ||
      (policy.block_on_critical_cve && a.severity === "CRITICAL") ||
      (policy.block_on_high_cve && a.severity === "HIGH"),
  );
}

function isReleaseProvenanceVerified(
  rel: { provenance_attested: boolean; provenance_status?: ProvenanceStatus } | undefined,
): boolean {
  if (!rel?.provenance_attested) return false;
  const status: ProvenanceStatus = rel.provenance_status ?? "sigstore_verified";
  return status === "sigstore_verified";
}

function safePinnedNpxCommand(pkgName: string, version: string | undefined, binName: string): string | null {
  if (!version) return null;
  if (!isSafeNpmPackageName(pkgName) || !isSafeNpmVersion(version) || !isSafeNpmBinName(binName)) {
    return null;
  }
  return `npx --yes --ignore-scripts --package=${pkgName}@${version} -- ${binName}`;
}

function classifyCommitObservations(obs: Observation[], unknowns: string[]): TrustVerdict {
  if (
    obs.some(
      (o) =>
        o.severity === "CRITICAL" ||
        o.code === "TAINT_CRED_TO_NETWORK_OR_EXEC" ||
        o.code === "ENV_SERIALIZATION_EXFIL" ||
        o.code === "BASE64_PAYLOAD_SUSPICIOUS" ||
        o.code === "LIFECYCLE_HOOK_DANGEROUS_CMD" ||
        o.code === "SHADY_WEBHOOK_OR_RAW_IP",
    )
  ) {
    return "MALICIOUS_INDICATORS_FOUND";
  }
  if (obs.some((o) => o.severity === "HIGH" || o.code === "HIDDEN_UNICODE_TROJAN_SOURCE" || o.code === "HIGH_ENTROPY_OBFUSCATION")) {
    return "QUARANTINE_SUSPICIOUS";
  }
  if (unknowns.some((u) => u.startsWith("REA_DEEP_FORENSICS_REQUIRED") || u.startsWith("OBFUSCATED_CODE_UNRECOVERED"))) {
    return "UNVERIFIABLE_UNKNOWN";
  }
  return "VERIFIED_CLEAN_WITHIN_SCOPE";
}

/**
 * Safe Clean-Commit & Patient-Zero Resolver.
 * Uses `git rev-list --first-parent`, `git ls-tree -r`, and content-addressed blob-SHA caching
 * in SplitPlaneCache so unchanged files across commits are scanned at most once.
 * Aggregates findings across the FULL tree of each commit (catching multi-file split payloads).
 */
export async function walkGitHistoryForCleanAnchor(params: {
  package_name: string;
  repoUrlOrLocalPath: string;
  isLocalDir: boolean;
  subdir?: string;
  binName?: string;
  policy: PolicyConfig;
  cache?: SplitPlaneCache;
  releaseTarballByCommit?: Map<
    string,
    { version: string; tarball_sha512?: string; provenance_attested: boolean; provenance_status?: ProvenanceStatus }
  >;
  residualAdvisoriesByCommit?: Map<string, AdvisoryRecord[]>;
  compromisedVersions?: Set<string>;
  compromisedCommits?: Set<string>;
  compromisedReason?: string;
  alternatives?: SafeAnchorDecision["alternatives"];
  signal?: AbortSignal;
}): Promise<SafeAnchorDecision> {
  const unknowns: string[] = [];
  const inspected_commits: CommitAuditSummary[] = [];
  const evidence: EvidenceRecord[] = [];
  let workDir = params.repoUrlOrLocalPath;
  let tempCloneDir: string | null = null;
  const resolvedBin =
    params.binName ??
    (params.package_name.includes("/")
      ? params.package_name.slice(params.package_name.indexOf("/") + 1)
      : params.package_name);

  if (params.subdir && !validateGitSubdir(params.subdir)) {
    unknowns.push(`INVALID_GIT_SUBDIR: rejected unsafe subdir '${sanitizeUntrustedText(params.subdir, 64)}'.`);
    return {
      schema_version: "1",
      package_name: params.package_name,
      compromised_latest: { reason: "Rejected unsafe Git subdirectory argument." },
      recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
      alternatives: params.alternatives ?? [],
      inspected_commits,
      evidence,
      unknowns,
    };
  }

  try {
    if (!params.isLocalDir) {
      // Security [MCP-03]: fail closed on remote git clone whenever offline_mode is enabled
      if (params.policy.offline_mode) {
        unknowns.push("OFFLINE_MODE_GIT_CLONE_BLOCKED: remote git clone is disabled while offline_mode is enabled.");
        return {
          schema_version: "1",
          package_name: params.package_name,
          compromised_latest: { reason: "Remote git clone blocked in offline mode; supply a local git_dir instead." },
          recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
          alternatives: params.alternatives ?? [],
          inspected_commits,
          evidence,
          unknowns,
        };
      }
      const urlCheck = validateRemoteGitUrl(params.repoUrlOrLocalPath);
      if (!urlCheck.valid) {
        unknowns.push(`GIT_REMOTE_URL_REJECTED: ${urlCheck.reason ?? "invalid URL"}`);
        return {
          schema_version: "1",
          package_name: params.package_name,
          compromised_latest: { reason: urlCheck.reason ?? "Rejected untrusted remote Git URL." },
          recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
          alternatives: params.alternatives ?? [],
          inspected_commits,
          evidence,
          unknowns,
        };
      }
      tempCloneDir = mkdtempSync(join(tmpdir(), "coldpin-git-"));
      ACTIVE_GIT_TEMP_DIRS.add(tempCloneDir);
      const cloneArgs = [
        "clone",
        "--filter=blob:none",
        "--no-checkout",
        "--single-branch",
        "--",
        params.repoUrlOrLocalPath,
        tempCloneDir,
      ];
      const cloneRes = await runGit(cloneArgs, tmpdir(), 30000, params.signal);
      if (!cloneRes.ok) {
        unknowns.push(`GIT_CLONE_FAILED: ${cloneRes.stderr.trim()}`);
        return {
          schema_version: "1",
          package_name: params.package_name,
          compromised_latest: { reason: "Could not clone repository for commit history inspection." },
          recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
          alternatives: params.alternatives ?? [],
          inspected_commits,
          evidence,
          unknowns,
        };
      }
      workDir = tempCloneDir;
    }

    const maxCommits = Math.max(1, params.policy.bisect_max_commits);
    const sinceArg = `--since=${params.policy.bisect_max_days}.days`;
    const logArgs = [
      "rev-list",
      "--first-parent",
      `-n`,
      String(maxCommits),
      sinceArg,
      "--format=%H%x1f%cI%x1f%s",
      "HEAD",
    ];
    if (params.subdir) logArgs.push("--", params.subdir);

    const logRes = await runGit(logArgs, workDir, 15000, params.signal);
    if (!logRes.ok) {
      unknowns.push(`GIT_REV_LIST_FAILED: ${logRes.stderr.trim()}`);
      return {
        schema_version: "1",
        package_name: params.package_name,
        compromised_latest: { reason: "Failed to read Git commit history." },
        recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
        alternatives: params.alternatives ?? [],
        inspected_commits,
        evidence,
        unknowns,
      };
    }

    const commits: Array<{ sha: string; date: string; subject: string }> = [];
    for (const line of logRes.stdout.split(/\r?\n/)) {
      if (!line.includes("\x1f")) continue;
      const parts = line.split("\x1f");
      if (parts[0] && parts[0].length === 40) {
        commits.push({
          sha: parts[0],
          date: parts[1] ?? "",
          subject: sanitizeUntrustedText(parts[2] ?? "", 100),
        });
      }
    }

    if (commits.length === 0) {
      unknowns.push("GIT_NO_COMMITS_IN_WINDOW: no commits matched the bounded bisect window.");
    }

    let latestVerdict: TrustVerdict = "UNVERIFIABLE_UNKNOWN";
    let patientZeroSha: string | undefined;
    let cleanCandidate: { sha: string; obsCount: number; evidenceId: string; hasVerifiedTarball: boolean } | undefined;
    let lookbehindRemaining = -1;
    const NON_MONOTONIC_LOOKBEHIND = 3;

    const blobMemoryCache = new Map<string, CachedBlobFacts>();

    for (let idx = 0; idx < commits.length; idx++) {
      if (params.signal?.aborted) {
        throw new Error("Operation aborted");
      }
      const c = commits[idx]!;
      // Use diff-tree --root --first-parent to count changed blobs safely (even on root commits)
      const diffRes = await runGit(
        ["diff-tree", "--root", "--first-parent", "-r", "--no-commit-id", "--name-only", c.sha],
        workDir,
        15000,
        params.signal,
      );
      const changedCount = diffRes.ok
        ? diffRes.stdout.split(/\r?\n/).filter((l) => l.trim().length > 0).length
        : 0;

      // Full-tree listing so multi-file split payloads across blobs in commit C are evaluated together
      const treeArgs = ["ls-tree", "-r", c.sha, ...(params.subdir ? [params.subdir] : [])];
      const treeRes = await runGit(treeArgs, workDir, 15000, params.signal);
      if (!treeRes.ok) {
        unknowns.push(`GIT_LS_TREE_FAILED:${c.sha}`);
        continue;
      }

      const commitObs: Observation[] = [];
      const commitInferences: string[] = [];
      const commitUnknowns: string[] = [];
      const commitModuleTaint = new Map<string, { sha256: string; taint: ModuleTaintSummary }>();
      let cacheHits = 0;
      let filesInspected = 0;

      for (const line of treeRes.stdout.split(/\r?\n/)) {
        const tabIdx = line.indexOf("\t");
        if (tabIdx === -1) continue;
        const metaParts = line.slice(0, tabIdx).trim().split(/\s+/);
        const objType = metaParts[1];
        const blobSha = metaParts[2];
        const filePath = line.slice(tabIdx + 1).trim();
        if (objType !== "blob" || !blobSha) continue;

        const cacheKey = buildFactCacheKey({
          content_sha: `${blobSha}:${filePath}`,
          ruleset_sha256: RULESET_SHA256,
          options: { max_single_file_bytes: params.policy.max_single_file_bytes },
        });

        let blobFacts = blobMemoryCache.get(cacheKey) ?? params.cache?.getArtifactFacts<CachedBlobFacts>(cacheKey) ?? null;
        if (blobFacts) {
          cacheHits++;
        } else {
          const blobBuf = await runGitBuffer(["cat-file", "blob", blobSha], workDir, 15000, params.signal);
          if (!blobBuf) {
            commitUnknowns.push(`GIT_BLOB_READ_FAILED:${blobSha}:${filePath}`);
            continue;
          }
          const analyzed = analyzeSourceBlob(filePath, blobBuf, blobSha, params.policy);

          // Also inspect package.json lifecycle hooks & shell-safe metadata inside the commit
          if (filePath === "package.json" || filePath.endsWith("/package.json")) {
            try {
              const pkg = JSON.parse(blobBuf.toString("utf8")) as PackageManifest;
              if (typeof pkg.name === "string" && !isSafeNpmPackageName(pkg.name)) {
                analyzed.observations.push({
                  code: "MANIFEST_SHELL_INJECTION_META",
                  severity: "CRITICAL",
                  path: filePath,
                  digest_sha256: blobSha,
                  attack_id: "T1059",
                  detail: `Unsafe package.json 'name' in commit ${c.sha.slice(0, 8)}.`,
                });
              }
              if (pkg.bin && typeof pkg.bin === "object") {
                for (const binKey of Object.keys(pkg.bin)) {
                  if (!isSafeNpmBinName(binKey)) {
                    analyzed.observations.push({
                      code: "MANIFEST_SHELL_INJECTION_META",
                      severity: "CRITICAL",
                      path: filePath,
                      digest_sha256: blobSha,
                      attack_id: "T1059",
                      detail: `Unsafe package.json 'bin' key in commit ${c.sha.slice(0, 8)}.`,
                    });
                  }
                }
              }
              for (const [hook, cmd] of Object.entries(pkg.scripts ?? {})) {
                if (LIFECYCLE_HOOKS.has(hook.toLowerCase()) && typeof cmd === "string") {
                  const dangerous = DANGEROUS_LIFECYCLE_CMD_RE.test(cmd);
                  analyzed.observations.push({
                    code: dangerous ? "LIFECYCLE_HOOK_DANGEROUS_CMD" : "LIFECYCLE_HOOK_PRESENT",
                    severity: dangerous ? "CRITICAL" : "MEDIUM",
                    path: filePath,
                    digest_sha256: blobSha,
                    attack_id: "T1195.002",
                    detail: `Lifecycle script '${hook}' in commit ${c.sha.slice(0, 8)}: "${sanitizeUntrustedText(cmd, 120)}".`,
                  });
                }
              }
            } catch {
              analyzed.unknowns.push(`COMMIT_MANIFEST_PARSE_ERROR:${c.sha}`);
            }
          }

          blobFacts = {
            observations: analyzed.observations,
            inferences: analyzed.inferences,
            unknowns: analyzed.unknowns,
            has_obfuscation: analyzed.has_obfuscation,
            has_native_or_wasm: analyzed.has_native_or_wasm,
            module_taint: analyzed.module_taint,
          };
          blobMemoryCache.set(cacheKey, blobFacts);
          params.cache?.putArtifactFacts({
            cache_key: cacheKey,
            content_sha: `${blobSha}:${filePath}`,
            ruleset_sha256: RULESET_SHA256,
            facts: blobFacts,
          });
        }

        filesInspected++;
        commitObs.push(...blobFacts.observations);
        commitInferences.push(...blobFacts.inferences);
        commitUnknowns.push(...blobFacts.unknowns);
        if (hasModuleTaintData(blobFacts.module_taint)) {
          commitModuleTaint.set(filePath, { sha256: blobSha, taint: blobFacts.module_taint! });
        }
      }

      if (commitModuleTaint.size > 1) {
        commitObs.push(...resolveCrossFileTaint(commitModuleTaint));
      }

      const relForCommit = params.releaseTarballByCommit?.get(c.sha);
      const isReleaseCompromised = Boolean(
        params.compromisedCommits?.has(c.sha) ||
          (relForCommit?.version && params.compromisedVersions?.has(relForCommit.version)),
      );
      let verdict = classifyCommitObservations(commitObs, commitUnknowns);
      if (isReleaseCompromised && verdict === "VERIFIED_CLEAN_WITHIN_SCOPE") {
        verdict = "MALICIOUS_INDICATORS_FOUND";
        commitObs.push({
          code: "TARBALL_ONLY_RELEASE_COMPROMISE",
          severity: "CRITICAL",
          path: "<npm-release>",
          attack_id: "T1195.002",
          detail:
            params.compromisedReason ??
            `Published npm release ${relForCommit?.version ?? c.sha.slice(0, 10)} is flagged compromised despite clean Git source tree.`,
        });
      }
      const evId = `ev_bisect_${c.sha.slice(0, 12)}`;
      if (idx === 0) latestVerdict = verdict;

      inspected_commits.push({
        commit_sha: c.sha,
        committed_at_utc: c.date,
        subject: c.subject,
        verdict,
        changed_blobs: changedCount,
        cache_hits: cacheHits,
        observations_count: commitObs.length,
      });

      if (verdict !== "VERIFIED_CLEAN_WITHIN_SCOPE") {
        if (!cleanCandidate) {
          // Track oldest contiguous infected commit as patient-zero candidate
          patientZeroSha = c.sha;
        } else {
          // Non-monotonic history: earlier commit before our clean candidate was also infected
          unknowns.push(
            `HISTORICAL_NON_MONOTONIC_COMPROMISE: earlier commit ${c.sha.slice(0, 10)} before clean candidate ${cleanCandidate.sha.slice(0, 10)} also exhibited ${verdict}.`,
          );
          break;
        }
        if (idx === 0 || idx === commits.length - 1) {
          evidence.push({
            evidence_id: evId,
            source: "tier3_bisect",
            commit_sha: c.sha,
            observations: commitObs,
            inferences: commitInferences,
            unknowns: commitUnknowns,
            coverage: {
              files_inspected: filesInspected,
              files_skipped: 0,
              rea_invoked: false,
              transitive_checked: false,
            },
          });
        }
      } else {
        const hasVerifiedTarball = Boolean(relForCommit?.tarball_sha512);
        const hasReleaseMap = Boolean(params.releaseTarballByCommit && params.releaseTarballByCommit.size > 0);
        if (!cleanCandidate) {
          cleanCandidate = { sha: c.sha, obsCount: commitObs.length, evidenceId: evId, hasVerifiedTarball };
          if (idx > 0) {
            patientZeroSha = commits[idx - 1]?.sha;
          }
          evidence.push({
            evidence_id: evId,
            source: "tier3_bisect",
            commit_sha: c.sha,
            observations: commitObs,
            inferences: commitInferences,
            unknowns: commitUnknowns,
            coverage: {
              files_inspected: filesInspected,
              files_skipped: 0,
              rea_invoked: false,
              transitive_checked: Boolean(params.residualAdvisoriesByCommit?.has(c.sha)),
            },
          });
        } else if (hasVerifiedTarball && !cleanCandidate.hasVerifiedTarball) {
          // Promote to the latest clean commit that also has a verified npm release tarball
          cleanCandidate = { sha: c.sha, obsCount: commitObs.length, evidenceId: evId, hasVerifiedTarball: true };
          evidence.push({
            evidence_id: evId,
            source: "tier3_bisect",
            commit_sha: c.sha,
            observations: commitObs,
            inferences: commitInferences,
            unknowns: commitUnknowns,
            coverage: {
              files_inspected: filesInspected,
              files_skipped: 0,
              rea_invoked: false,
              transitive_checked: Boolean(params.residualAdvisoriesByCommit?.has(c.sha)),
            },
          });
        }

        if (idx === 0) {
          break;
        }
        // Once we have a finalized clean candidate, scan a bounded lookbehind to detect non-monotonic history
        const candidateFinalized = !hasReleaseMap || cleanCandidate.hasVerifiedTarball;
        if (candidateFinalized) {
          if (lookbehindRemaining === -1) {
            lookbehindRemaining = NON_MONOTONIC_LOOKBEHIND;
          } else {
            lookbehindRemaining--;
          }
          if (lookbehindRemaining <= 0) {
            break;
          }
        }
      }
    }

    const headSha = commits[0]?.sha;
    if (latestVerdict === "VERIFIED_CLEAN_WITHIN_SCOPE" && headSha) {
      const rel = params.releaseTarballByCommit?.get(headSha);
      const headAdvisories = params.residualAdvisoriesByCommit?.get(headSha) ?? [];
      if (isAdvisoryPolicyBlocking(headAdvisories, params.policy)) {
        return {
          schema_version: "1",
          package_name: params.package_name,
          compromised_latest: {
            version: rel?.version,
            commit_sha: headSha,
            reason: `HEAD commit (${headSha.slice(0, 10)}) has clean static source but failed enterprise CVE/KEV/MAL advisory policy gate.`,
          },
          recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
          safe_anchor: {
            version: rel?.version,
            commit_sha: headSha,
            tarball_sha512: rel?.tarball_sha512,
            provenance_attested: rel?.provenance_attested ?? false,
            provenance_status: rel?.provenance_status ?? (rel?.provenance_attested ? "sigstore_verified" : "none"),
            pinned_execution: {
              command: null,
              exact_version: rel?.version,
              tarball_sha512: rel?.tarball_sha512,
              caveat: "Latest release blocked by enterprise CVE/KEV/MAL advisory policy; switch to a vetted alternative.",
            },
            residual_advisories: headAdvisories,
          },
          alternatives: params.alternatives ?? [],
          inspected_commits,
          evidence,
          unknowns,
        };
      }
      const headProvStatus: ProvenanceStatus =
        rel?.provenance_status ?? (rel?.provenance_attested ? "sigstore_verified" : "none");
      if (params.policy.require_provenance && !isReleaseProvenanceVerified(rel)) {
        unknowns.push(
          `PROVENANCE_REQUIRED_NOT_VERIFIED: enterprise policy requires cryptographically verified Sigstore/SLSA provenance (observed '${headProvStatus}', sigstore_verified=${isReleaseProvenanceVerified(rel)}).`,
        );
        return {
          schema_version: "1",
          package_name: params.package_name,
          compromised_latest: {
            version: rel?.version,
            commit_sha: headSha,
            reason: `HEAD commit (${headSha.slice(0, 10)}) lacks cryptographically verified Sigstore/SLSA provenance required by policy.`,
          },
          recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
          safe_anchor: {
            version: rel?.version,
            commit_sha: headSha,
            tarball_sha512: rel?.tarball_sha512,
            provenance_attested: false,
            provenance_status: headProvStatus,
            pinned_execution: {
              command: null,
              exact_version: rel?.version,
              tarball_sha512: rel?.tarball_sha512,
              caveat: "Execution command suppressed: require_provenance=true requires full Sigstore Fulcio/Rekor verification.",
            },
            residual_advisories: headAdvisories,
          },
          alternatives: params.alternatives ?? [],
          inspected_commits,
          evidence,
          unknowns,
        };
      }
      const latestCmd = safePinnedNpxCommand(params.package_name, rel?.version, resolvedBin);
      return {
        schema_version: "1",
        package_name: params.package_name,
        compromised_latest: {
          commit_sha: headSha,
          reason: "HEAD commit shows no static malicious indicators within inspected scope.",
        },
        recommended_action: "USE_PINNED_LATEST",
        safe_anchor: {
          version: rel?.version,
          commit_sha: headSha,
          tarball_sha512: rel?.tarball_sha512,
          provenance_attested: isReleaseProvenanceVerified(rel),
          provenance_status: headProvStatus,
          pinned_execution: {
            command: latestCmd,
            exact_version: rel?.version,
            tarball_sha512: rel?.tarball_sha512,
            caveat: latestCmd
              ? "Stock npx pins top-level version only; verify tarball SHA-512 and lock transitive dependencies before execution."
              : "No safe executable command emitted (missing verified npm release version or unsafe package/bin identifier).",
          },
          residual_advisories: headAdvisories,
        },
        alternatives: params.alternatives ?? [],
        inspected_commits,
        evidence,
        unknowns,
      };
    }

    if (!cleanCandidate) {
      unknowns.push(
        `NO_CLEAN_COMMIT_IN_WINDOW: scanned ${inspected_commits.length} commits (limit ${params.policy.bisect_max_commits}) without finding a clean ancestor.`,
      );
      return {
        schema_version: "1",
        package_name: params.package_name,
        compromised_latest: {
          commit_sha: headSha,
          patient_zero_sha: patientZeroSha,
          reason: `Latest commit (${headSha?.slice(0, 10) ?? "unknown"}) flagged ${latestVerdict}; no clean ancestor found in window.`,
        },
        recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
        alternatives: params.alternatives ?? [],
        inspected_commits,
        evidence,
        unknowns,
      };
    }

    // Dual-Gate CVE & Tarball Parity Check on cleanCandidate
    const residualAdvisories = params.residualAdvisoriesByCommit?.get(cleanCandidate.sha) ?? [];
    const blockedByCve = isAdvisoryPolicyBlocking(residualAdvisories, params.policy);

    const matchingRelease = params.releaseTarballByCommit?.get(cleanCandidate.sha);

    if (blockedByCve) {
      return {
        schema_version: "1",
        package_name: params.package_name,
        compromised_latest: {
          commit_sha: headSha,
          patient_zero_sha: patientZeroSha,
          reason: `Latest commit compromised; clean ancestor ${cleanCandidate.sha.slice(0, 10)} failed CVE/KEV policy gate.`,
        },
        recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
        safe_anchor: {
          version: matchingRelease?.version,
          commit_sha: cleanCandidate.sha,
          tarball_sha512: matchingRelease?.tarball_sha512,
          provenance_attested: isReleaseProvenanceVerified(matchingRelease),
          provenance_status:
            matchingRelease?.provenance_status ?? (matchingRelease?.provenance_attested ? "sigstore_verified" : "none"),
          pinned_execution: {
            command: null,
            exact_version: matchingRelease?.version,
            tarball_sha512: matchingRelease?.tarball_sha512,
            caveat: "Rollback blocked by enterprise CVE/KEV policy; switch to a vetted alternative.",
          },
          residual_advisories: residualAdvisories,
        },
        alternatives: params.alternatives ?? [],
        inspected_commits,
        evidence,
        unknowns,
      };
    }

    if (!matchingRelease?.tarball_sha512) {
      unknowns.push(
        `NO_VERIFIED_NPM_TARBALL_FOR_COMMIT: clean commit ${cleanCandidate.sha} has no verified npm tarball; direct 'npx github:...' execution is blocked to avoid unverified build scripts and floating transitives.`,
      );
      return {
        schema_version: "1",
        package_name: params.package_name,
        compromised_latest: {
          commit_sha: headSha,
          patient_zero_sha: patientZeroSha,
          reason: `Malicious indicators introduced at ${patientZeroSha?.slice(0, 10) ?? "unknown"}; last clean source commit is ${cleanCandidate.sha.slice(0, 10)} (no published verified tarball).`,
        },
        recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "FORENSIC_COMMIT_ONLY",
        safe_anchor: {
          commit_sha: cleanCandidate.sha,
          provenance_attested: false,
          provenance_status: "none",
          pinned_execution: {
            command: null,
            caveat:
              "Forensic anchor only: no matching verified npm tarball exists. Build in an isolated sandbox or switch to a vetted alternative.",
          },
          residual_advisories: residualAdvisories,
        },
        alternatives: params.alternatives ?? [],
        inspected_commits,
        evidence,
        unknowns,
      };
    }

    const rollbackProvStatus: ProvenanceStatus =
      matchingRelease.provenance_status ?? (matchingRelease.provenance_attested ? "sigstore_verified" : "none");
    if (params.policy.require_provenance && !isReleaseProvenanceVerified(matchingRelease)) {
      unknowns.push(
        `PROVENANCE_REQUIRED_NOT_VERIFIED: enterprise policy requires cryptographically verified Sigstore/SLSA provenance for rollback release ${matchingRelease.version} (observed '${rollbackProvStatus}', sigstore_verified=false).`,
      );
      return {
        schema_version: "1",
        package_name: params.package_name,
        compromised_latest: {
          commit_sha: headSha,
          patient_zero_sha: patientZeroSha,
          reason: `Latest commit compromised; clean release ${matchingRelease.version} lacks cryptographically verified Sigstore/SLSA provenance required by policy.`,
        },
        recommended_action: params.alternatives?.length ? "SWITCH_TO_ALTERNATIVE" : "BLOCK_NO_SAFE_PATH",
        safe_anchor: {
          version: matchingRelease.version,
          commit_sha: cleanCandidate.sha,
          tarball_sha512: matchingRelease.tarball_sha512,
          provenance_attested: false,
          provenance_status: rollbackProvStatus,
          pinned_execution: {
            command: null,
            exact_version: matchingRelease.version,
            tarball_sha512: matchingRelease.tarball_sha512,
            caveat: "Rollback command suppressed: require_provenance=true requires full Sigstore Fulcio/Rekor verification.",
          },
          residual_advisories: residualAdvisories,
        },
        alternatives: params.alternatives ?? [],
        inspected_commits,
        evidence,
        unknowns,
      };
    }

    const rollbackCmd = safePinnedNpxCommand(params.package_name, matchingRelease.version, resolvedBin);
    return {
      schema_version: "1",
      package_name: params.package_name,
      compromised_latest: {
        commit_sha: headSha,
        patient_zero_sha: patientZeroSha,
        reason: `Malicious indicators introduced at ${patientZeroSha?.slice(0, 10) ?? "unknown"}; safe verified release ${matchingRelease.version} mapped to clean commit ${cleanCandidate.sha.slice(0, 10)}.`,
      },
      recommended_action: rollbackCmd ? "ROLLBACK_TO_SAFE_ANCHOR" : "BLOCK_NO_SAFE_PATH",
      safe_anchor: {
        version: matchingRelease.version,
        commit_sha: cleanCandidate.sha,
        tarball_sha512: matchingRelease.tarball_sha512,
        provenance_attested: isReleaseProvenanceVerified(matchingRelease),
        provenance_status: rollbackProvStatus,
        pinned_execution: {
          command: rollbackCmd,
          exact_version: matchingRelease.version,
          tarball_sha512: matchingRelease.tarball_sha512,
          caveat: rollbackCmd
            ? "Stock npx pins top-level version only; verify dist.integrity SHA-512 and lock transitive dependencies before execution."
            : "Execution command suppressed due to unsafe package/version/bin identifier.",
        },
        residual_advisories: residualAdvisories,
      },
      alternatives: params.alternatives ?? [],
      inspected_commits,
      evidence,
      unknowns,
    };
  } finally {
    if (tempCloneDir) {
      ACTIVE_GIT_TEMP_DIRS.delete(tempCloneDir);
      try {
        rmSync(tempCloneDir, { recursive: true, force: true });
      } catch {
        // Best-effort temp cleanup
      }
    }
  }
}
