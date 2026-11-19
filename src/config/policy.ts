import { createHash } from "node:crypto";
import { execFileSync } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import type { HostCapabilities, PolicyConfig } from "../types.ts";

export const DEFAULT_POLICY: PolicyConfig = {
  private_scopes: [],
  private_prefixes: [],
  private_registries: {},
  default_registry: "https://registry.npmjs.org",
  osv_api_url: "https://api.osv.dev",
  allow_public_fallback: false,
  allowed_orgs: [],
  denied_orgs: [],
  blocked_licenses: ["AGPL-3.0", "AGPL-3.0-only", "SSPL-1.0"],
  cooldown_hours: 72,
  max_compressed_bytes: 20 * 1024 * 1024,
  max_uncompressed_bytes: 50 * 1024 * 1024,
  max_files: 5000,
  max_single_file_bytes: 10 * 1024 * 1024,
  block_on_kev: true,
  block_on_critical_cve: true,
  block_on_high_cve: false,
  require_provenance: false,
  require_source_link: false,
  bisect_max_commits: 200,
  bisect_max_days: 180,
  intel_ttl_seconds: 21600,
  offline_mode: false,
};

export interface NpmrcConfig {
  paths_loaded: string[];
  default_registry?: string;
  scoped_registries: Record<string, string>;
  auth_token_env_by_host: Record<string, string>;
}

export interface RegistryRouteResult {
  route: "private" | "public" | "blocked_typo" | "blocked_unconfigured";
  registry_url: string;
  auth_token?: string;
  matched_scope_or_prefix?: string;
  reason: string;
}

const PUBLIC_NPM_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

export function isPublicNpmRegistryUrl(rawUrl: string): boolean {
  try {
    const host = new URL(rawUrl).hostname.toLowerCase();
    return PUBLIC_NPM_HOSTS.has(host);
  } catch {
    return rawUrl.toLowerCase().includes("registry.npmjs.org");
  }
}

export function levenshtein(a: string, b: string): number {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array<number>(n + 1);
  let curr = new Array<number>(n + 1);
  for (let j = 0; j <= n; j++) prev[j] = j;
  for (let i = 1; i <= m; i++) {
    curr[0] = i;
    const ca = a.charCodeAt(i - 1);
    for (let j = 1; j <= n; j++) {
      const cost = ca === b.charCodeAt(j - 1) ? 0 : 1;
      const del = (prev[j] ?? 0) + 1;
      const ins = (curr[j - 1] ?? 0) + 1;
      const sub = (prev[j - 1] ?? 0) + cost;
      curr[j] = Math.min(del, ins, sub);
    }
    const tmp = prev;
    prev = curr;
    curr = tmp;
  }
  return prev[n] ?? 0;
}

function findGitRoot(startDir: string): string | null {
  let dir = resolve(startDir);
  for (let i = 0; i < 32; i++) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function asStringArray(val: unknown, fallback: string[]): string[] {
  if (!Array.isArray(val)) return fallback;
  return val.filter((v): v is string => typeof v === "string");
}

function asStringRecord(val: unknown, fallback: Record<string, string>): Record<string, string> {
  if (val === null || typeof val !== "object" || Array.isArray(val)) return fallback;
  const out: Record<string, string> = {};
  for (const [k, v] of Object.entries(val as Record<string, unknown>)) {
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

function asPositiveNumber(val: unknown, fallback: number): number {
  return typeof val === "number" && Number.isFinite(val) && val >= 0 ? val : fallback;
}

function asBoolean(val: unknown, fallback: boolean): boolean {
  return typeof val === "boolean" ? val : fallback;
}

export function loadPolicy(cwd: string, explicitPath?: string): {
  policy: PolicyConfig;
  policy_path: string | null;
  policy_sha256: string;
} {
  const candidates: string[] = [];
  if (explicitPath) {
    candidates.push(resolve(explicitPath));
  } else {
    const policyFiles = [".coldpin.policy.json", ".npx-guard.policy.json"];
    const resolvedCwd = resolve(cwd);
    const gitRoot = findGitRoot(cwd);
    for (const fileName of policyFiles) {
      candidates.push(join(resolvedCwd, fileName));
      if (gitRoot && gitRoot !== resolvedCwd) {
        candidates.push(join(gitRoot, fileName));
      }
      candidates.push(join(homedir(), fileName));
    }
  }

  let loadedPath: string | null = null;
  let raw: Record<string, unknown> = {};
  for (const p of candidates) {
    if (existsSync(p)) {
      const content = readFileSync(p, "utf8");
      const parsed: unknown = JSON.parse(content);
      if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
        throw new Error(`Invalid policy JSON object in ${p}`);
      }
      raw = parsed as Record<string, unknown>;
      loadedPath = p;
      break;
    }
  }

  const normalizedPrivateRegistries: Record<string, string> = {};
  for (const [k, v] of Object.entries(asStringRecord(raw["private_registries"], DEFAULT_POLICY.private_registries))) {
    const scopeKey = k.startsWith("@") ? k.toLowerCase() : `@${k.toLowerCase()}`;
    normalizedPrivateRegistries[scopeKey] = v.replace(/\/+$/, "");
  }

  const policy: PolicyConfig = {
    private_scopes: asStringArray(raw["private_scopes"], DEFAULT_POLICY.private_scopes).map((s) =>
      s.startsWith("@") ? s.toLowerCase() : `@${s.toLowerCase()}`,
    ),
    private_prefixes: asStringArray(raw["private_prefixes"], DEFAULT_POLICY.private_prefixes).map((s) =>
      s.toLowerCase(),
    ),
    private_registries: normalizedPrivateRegistries,
    default_registry:
      typeof raw["default_registry"] === "string" ? raw["default_registry"] : DEFAULT_POLICY.default_registry,
    osv_api_url:
      typeof raw["osv_api_url"] === "string" && raw["osv_api_url"].trim().length > 0
        ? raw["osv_api_url"].trim().replace(/\/+$/, "")
        : DEFAULT_POLICY.osv_api_url,
    allow_public_fallback: asBoolean(raw["allow_public_fallback"], DEFAULT_POLICY.allow_public_fallback),
    allowed_orgs: asStringArray(raw["allowed_orgs"], DEFAULT_POLICY.allowed_orgs).map((s) => s.toLowerCase()),
    denied_orgs: asStringArray(raw["denied_orgs"], DEFAULT_POLICY.denied_orgs).map((s) => s.toLowerCase()),
    blocked_licenses: asStringArray(raw["blocked_licenses"], DEFAULT_POLICY.blocked_licenses),
    cooldown_hours: asPositiveNumber(raw["cooldown_hours"], DEFAULT_POLICY.cooldown_hours),
    max_compressed_bytes: asPositiveNumber(raw["max_compressed_bytes"], DEFAULT_POLICY.max_compressed_bytes),
    max_uncompressed_bytes: asPositiveNumber(raw["max_uncompressed_bytes"], DEFAULT_POLICY.max_uncompressed_bytes),
    max_files: asPositiveNumber(raw["max_files"], DEFAULT_POLICY.max_files),
    max_single_file_bytes: asPositiveNumber(raw["max_single_file_bytes"], DEFAULT_POLICY.max_single_file_bytes),
    block_on_kev: asBoolean(raw["block_on_kev"], DEFAULT_POLICY.block_on_kev),
    block_on_critical_cve: asBoolean(raw["block_on_critical_cve"], DEFAULT_POLICY.block_on_critical_cve),
    block_on_high_cve: asBoolean(raw["block_on_high_cve"], DEFAULT_POLICY.block_on_high_cve),
    require_provenance: asBoolean(raw["require_provenance"], DEFAULT_POLICY.require_provenance),
    require_source_link: asBoolean(raw["require_source_link"], DEFAULT_POLICY.require_source_link),
    bisect_max_commits: asPositiveNumber(raw["bisect_max_commits"], DEFAULT_POLICY.bisect_max_commits),
    bisect_max_days: asPositiveNumber(raw["bisect_max_days"], DEFAULT_POLICY.bisect_max_days),
    intel_ttl_seconds: asPositiveNumber(raw["intel_ttl_seconds"], DEFAULT_POLICY.intel_ttl_seconds),
    offline_mode: asBoolean(raw["offline_mode"], DEFAULT_POLICY.offline_mode),
  };

  const policy_sha256 = createHash("sha256").update(JSON.stringify(policy)).digest("hex");
  return { policy, policy_path: loadedPath, policy_sha256 };
}

export function loadNpmrc(cwd: string): NpmrcConfig {
  const result: NpmrcConfig = {
    paths_loaded: [],
    scoped_registries: {},
    auth_token_env_by_host: {},
  };

  const candidatePaths: string[] = [];
  const homeRc = join(homedir(), ".npmrc");
  if (existsSync(homeRc)) candidatePaths.push(homeRc);
  const gitRoot = findGitRoot(cwd);
  if (gitRoot && gitRoot !== resolve(cwd)) {
    const rootRc = join(gitRoot, ".npmrc");
    if (existsSync(rootRc)) candidatePaths.push(rootRc);
  }
  const cwdRc = join(resolve(cwd), ".npmrc");
  if (existsSync(cwdRc)) candidatePaths.push(cwdRc);

  for (const rcPath of candidatePaths) {
    result.paths_loaded.push(rcPath);
    const lines = readFileSync(rcPath, "utf8").split(/\r?\n/);
    for (const rawLine of lines) {
      const line = rawLine.trim();
      if (!line || line.startsWith("#") || line.startsWith(";")) continue;
      const eqIdx = line.indexOf("=");
      if (eqIdx <= 0) continue;
      const key = line.slice(0, eqIdx).trim();
      const val = line.slice(eqIdx + 1).trim();

      if (key === "registry") {
        result.default_registry = val.replace(/\/+$/, "");
      } else if (key.startsWith("@") && key.endsWith(":registry")) {
        const scope = key.slice(0, -":registry".length).toLowerCase();
        result.scoped_registries[scope] = val.replace(/\/+$/, "");
      } else if (key.startsWith("//") && key.endsWith(":_authToken")) {
        const hostPath = key.slice(2, -":_authToken".length).replace(/\/+$/, "");
        const envMatch = /^\$\{([A-Z0-9_]+)\}$/.exec(val);
        if (envMatch?.[1]) {
          result.auth_token_env_by_host[hostPath] = envMatch[1];
        }
      }
    }
  }

  if (process.env["npm_config_registry"]) {
    result.default_registry = process.env["npm_config_registry"].replace(/\/+$/, "");
  }

  return result;
}

function resolveAuthTokenForUrl(registryUrl: string, npmrc: NpmrcConfig): string | undefined {
  try {
    const parsed = new URL(registryUrl);
    const hostAndPath = `${parsed.host}${parsed.pathname}`.replace(/\/+$/, "");
    for (const [k, envVar] of Object.entries(npmrc.auth_token_env_by_host)) {
      if (hostAndPath.startsWith(k) || parsed.host === k) {
        return process.env[envVar];
      }
    }
  } catch {
    return undefined;
  }
  return undefined;
}

/**
 * Private-scope-first router with fuzzy Levenshtein typo guard.
 * Guarantees private scopes and private prefixes NEVER leak to public registry.npmjs.org.
 */
export function routeRegistry(
  packageOrScope: string,
  policy: PolicyConfig,
  npmrc: NpmrcConfig,
): RegistryRouteResult {
  const normalized = packageOrScope.trim().toLowerCase();
  const scopeMatch = /^(@[^/\s]+)/.exec(normalized);
  const scope = scopeMatch?.[1];

  const allPrivateScopes = new Set<string>([
    ...policy.private_scopes,
    ...Object.keys(policy.private_registries).map((s) => s.toLowerCase()),
    ...Object.keys(npmrc.scoped_registries).filter(
      (s) => !isPublicNpmRegistryUrl(npmrc.scoped_registries[s] ?? ""),
    ),
  ]);

  if (scope) {
    const policyReg = policy.private_registries[scope];
    const npmrcReg = npmrc.scoped_registries[scope];
    const resolvedPrivate = policyReg ?? npmrcReg;
    if (resolvedPrivate && !isPublicNpmRegistryUrl(resolvedPrivate)) {
      return {
        route: "private",
        registry_url: resolvedPrivate.replace(/\/+$/, ""),
        auth_token: resolveAuthTokenForUrl(resolvedPrivate, npmrc),
        matched_scope_or_prefix: scope,
        reason: `Scoped package ${scope} routed to private registry.`,
      };
    }

    if (allPrivateScopes.has(scope)) {
      return {
        route: "blocked_unconfigured",
        registry_url: "",
        matched_scope_or_prefix: scope,
        reason: `Private scope ${scope} declared in policy without a configured private registry URL; public npm lookup blocked.`,
      };
    }

    // Fuzzy typo guard: block near-misses & single transpositions of configured private scopes (e.g., @amce vs @acme)
    for (const priv of allPrivateScopes) {
      const a = scope.slice(1);
      const b = priv.slice(1);
      const isTransposition =
        a.length === b.length &&
        a.length >= 4 &&
        (() => {
          const diffs: number[] = [];
          for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) diffs.push(i);
            if (diffs.length > 2) return false;
          }
          return diffs.length === 2 && diffs[1] === diffs[0]! + 1 && a[diffs[0]!] === b[diffs[1]!] && a[diffs[1]!] === b[diffs[0]!];
        })();
      if (a.length >= 4 && b.length >= 4 && (levenshtein(a, b) <= 1 || isTransposition)) {
        return {
          route: "blocked_typo",
          registry_url: "",
          matched_scope_or_prefix: priv,
          reason: `Scope ${scope} is 1 edit/transposition away from private scope ${priv}; blocked to prevent internal namespace leak.`,
        };
      }
    }
  }

  // Unscoped private prefix check
  const bareName = scope ? normalized.slice(scope.length + 1) : normalized;
  for (const prefix of policy.private_prefixes) {
    if (bareName.startsWith(prefix)) {
      const defaultPriv =
        npmrc.default_registry && !isPublicNpmRegistryUrl(npmrc.default_registry)
          ? npmrc.default_registry
          : !isPublicNpmRegistryUrl(policy.default_registry)
            ? policy.default_registry
            : "";
      if (defaultPriv) {
        return {
          route: "private",
          registry_url: defaultPriv,
          auth_token: resolveAuthTokenForUrl(defaultPriv, npmrc),
          matched_scope_or_prefix: prefix,
          reason: `Unscoped package matching private prefix '${prefix}' routed to private registry.`,
        };
      }
      return {
        route: "blocked_unconfigured",
        registry_url: "",
        matched_scope_or_prefix: prefix,
        reason: `Package matches private prefix '${prefix}' but no private registry is configured; public npm lookup blocked.`,
      };
    }
  }

  const targetRegistry = (npmrc.default_registry ?? policy.default_registry).replace(/\/+$/, "");
  const isPrivate = !isPublicNpmRegistryUrl(targetRegistry);
  return {
    route: isPrivate ? "private" : "public",
    registry_url: targetRegistry,
    auth_token: isPrivate ? resolveAuthTokenForUrl(targetRegistry, npmrc) : undefined,
    reason: isPrivate ? "Routed via configured default private registry." : "Routed to public npm registry.",
  };
}

/**
 * Inspects every whitespace-separated token in a multi-word discovery query so an
 * internal scope or prefix embedded after other search words (e.g. "find @acme/cli")
 * cannot accidentally leak to public registry.npmjs.org.
 */
export function routeDiscoveryQuery(
  query: string,
  org: string | undefined,
  policy: PolicyConfig,
  npmrc: NpmrcConfig,
): RegistryRouteResult {
  const tokens: string[] = [];
  if (org?.trim()) tokens.push(org.trim().startsWith("@") ? org.trim() : `@${org.trim()}`);
  for (const tok of query.split(/\s+/).filter(Boolean)) {
    tokens.push(tok.replace(/^["'`(,]+|["'`),.;:]+$/g, ""));
  }
  let privateMatch: RegistryRouteResult | null = null;
  for (const tok of tokens) {
    if (!tok) continue;
    const r = routeRegistry(tok, policy, npmrc);
    if (r.route === "blocked_typo" || r.route === "blocked_unconfigured") {
      return r;
    }
    if (r.route === "private" && !privateMatch) {
      privateMatch = r;
    }
  }
  return privateMatch ?? routeRegistry(tokens[0] ?? "", policy, npmrc);
}

export function probeHostCapabilities(): HostCapabilities {
  let gitAvailable = false;
  let gitPartialCloneSupported = false;
  let reaCliAvailable = false;
  let reaCliCommand: string | undefined;

  try {
    const out = execFileSync("git", ["--version"], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "ignore"],
      timeout: 3000,
    });
    gitAvailable = out.toLowerCase().includes("git version");
    const verMatch = /(\d+)\.(\d+)/.exec(out);
    if (verMatch?.[1] && verMatch[2]) {
      const maj = Number(verMatch[1]);
      const min = Number(verMatch[2]);
      gitPartialCloneSupported = maj > 2 || (maj === 2 && min >= 25);
    }
  } catch {
    gitAvailable = false;
  }

  for (const candidate of ["rea", "rea-agents"]) {
    try {
      execFileSync(candidate, ["--version"], {
        encoding: "utf8",
        stdio: ["ignore", "pipe", "ignore"],
        timeout: 2000,
      });
      reaCliAvailable = true;
      reaCliCommand = candidate;
      break;
    } catch {
      // Not installed on PATH; never auto-bootstrap via npx -y
    }
  }

  return {
    node_version: process.version,
    git_available: gitAvailable,
    git_partial_clone_supported: gitPartialCloneSupported,
    rea_cli_available: reaCliAvailable,
    ...(reaCliCommand ? { rea_cli_command: reaCliCommand } : {}),
    sqlite_available: true,
  };
}
