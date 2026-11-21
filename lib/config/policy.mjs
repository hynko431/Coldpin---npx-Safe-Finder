import { execFile } from "node:child_process";
import { createHash } from "node:crypto";
import { existsSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join, resolve } from "node:path";
import { promisify } from "node:util";
import { readCappedRegularFileSync } from "../core/path-confinement.mjs";
                                                                  

const execFileAsync = promisify(execFile);
const MAX_POLICY_BYTES = 1024 * 1024;
const MAX_NPMRC_BYTES = 512 * 1024;

export const DEFAULT_POLICY               = {
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

                              
                         
                            
                                            
                                                 
 

                                      
                                                                                           
                       
                      
                                   
                 
 

const PUBLIC_NPM_HOSTS = new Set(["registry.npmjs.org", "registry.yarnpkg.com"]);

/**
 * Unanchored Antigravity placeholder detector (`[PLG-09]`):
 * Rejects literal unexpanded placeholders such as `${COLDPIN_REGISTRY_TOKEN}`,
 * `${PLUGIN_DATA}/cache`, or `Bearer ${TOKEN}` if a host enables a plugin before filling variables.
 */
export const UNEXPANDED_PLACEHOLDER_RE = /\$\{[A-Za-z0-9_]+\}/;

export function hasUnexpandedPlaceholder(raw                    )          {
  return typeof raw === "string" && UNEXPANDED_PLACEHOLDER_RE.test(raw);
}

export function sanitizeOperatorEnvValue(raw                    )                     {
  if (typeof raw !== "string") return undefined;
  const trimmed = raw.trim();
  if (!trimmed || hasUnexpandedPlaceholder(trimmed)) return undefined;
  return trimmed;
}

export function isValidPrivateRegistryEnvUrl(rawUrl        )          {
  if (hasUnexpandedPlaceholder(rawUrl)) return false;
  let parsed     ;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return false;
  }
  if (parsed.protocol !== "https:") return false;
  if (parsed.username || parsed.password) return false;
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (!host || PUBLIC_NPM_HOSTS.has(host)) return false;
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host === "metadata.google.internal" ||
    host === "metadata.goog" ||
    host === "169.254.169.254" ||
    host === "100.100.100.200" ||
    host === "fd00:ec2::254" ||
    host === "::1" ||
    host === "::" ||
    host.startsWith("127.") ||
    host.startsWith("0.") ||
    host.startsWith("169.254.") ||
    /^fe[89ab][0-9a-f]:/.test(host) ||
    host.startsWith("::ffff:127.") ||
    host.startsWith("::ffff:169.254.") ||
    host.startsWith("::ffff:0.")
  ) {
    return false;
  }
  return true;
}

function applyPrivateRegistryEnvOverlay(
  policy              ,
  hasExplicitPolicyFile         ,
  env                    = process.env,
)               {
  const rawScopes = sanitizeOperatorEnvValue(env["COLDPIN_PRIVATE_SCOPES"]);
  const rawRegUrl = sanitizeOperatorEnvValue(env["COLDPIN_PRIVATE_REGISTRY_URL"]);
  if (!rawScopes && !rawRegUrl) return policy;

  const envScopes = rawScopes
    ? rawScopes
        .split(",")
        .map((s) => s.trim().toLowerCase())
        .filter(Boolean)
        .map((s) => (s.startsWith("@") ? s : `@${s}`))
    : [];
  const validRegUrl = rawRegUrl && isValidPrivateRegistryEnvUrl(rawRegUrl) ? rawRegUrl.replace(/\/+$/, "") : undefined;

  const privateScopes = Array.from(new Set([...policy.private_scopes, ...envScopes]));
  const privateRegistries                         = { ...policy.private_registries };
  if (validRegUrl) {
    for (const scope of envScopes) {
      if (!hasExplicitPolicyFile || !privateRegistries[scope]) {
        privateRegistries[scope] = validRegUrl;
      }
    }
  }
  return {
    ...policy,
    private_scopes: privateScopes,
    private_registries: privateRegistries,
  };
}

const SECRET_LIKE_PATTERNS                    = [
  /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{16,}\b/,
  /\bgithub_pat_[A-Za-z0-9_]{20,}\b/,
  /\bnpm_[A-Za-z0-9]{20,}\b/,
  /\b(?:AKIA|ASIA|ABIA|ACCA)[0-9A-Z]{16}\b/,
  /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/,
  /\bsk-(?:proj-|live-|test-)?[A-Za-z0-9_-]{20,}\b/,
  /\bAIza[0-9A-Za-z_-]{25,}\b/,
  /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/,
  /-----BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+)?PRIVATE\s+KEY-----/i,
  /\b(?:api[_-]?key|secret|password|passwd|bearer|auth[_-]?token)\s*[:=]\s*[^\s]{6,}/i,
];

export function hasSecretLikeDiscoveryToken(raw        )          {
  if (!raw) return false;
  for (const re of SECRET_LIKE_PATTERNS) {
    if (re.test(raw)) return true;
  }
  return false;
}

export function isPublicNpmRegistryUrl(rawUrl        )          {
  try {
    const host = new URL(rawUrl).hostname.toLowerCase();
    return PUBLIC_NPM_HOSTS.has(host);
  } catch {
    return rawUrl.toLowerCase().includes("registry.npmjs.org");
  }
}

export function levenshtein(a        , b        )         {
  const m = a.length;
  const n = b.length;
  if (m === 0) return n;
  if (n === 0) return m;
  let prev = new Array        (n + 1);
  let curr = new Array        (n + 1);
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

function findGitRoot(startDir        )                {
  let dir = resolve(startDir);
  for (let i = 0; i < 32; i++) {
    if (existsSync(join(dir, ".git"))) return dir;
    const parent = dirname(dir);
    if (parent === dir) break;
    dir = parent;
  }
  return null;
}

function asStringArray(val         , fallback          )           {
  if (!Array.isArray(val)) return fallback;
  return val.filter((v)              => typeof v === "string");
}

function asStringRecord(val         , fallback                        )                         {
  if (val === null || typeof val !== "object" || Array.isArray(val)) return fallback;
  const out                         = {};
  for (const [k, v] of Object.entries(val                           )) {
    if (typeof v === "string") out[k] = v;
  }
  return out;
}

function asPositiveNumber(val         , fallback        )         {
  return typeof val === "number" && Number.isFinite(val) && val >= 0 ? val : fallback;
}

function asBoolean(val         , fallback         )          {
  return typeof val === "boolean" ? val : fallback;
}

function parseRawPolicyObject(raw                         , base               = DEFAULT_POLICY)               {
  const normalizedPrivateRegistries                         = {};
  for (const [k, v] of Object.entries(asStringRecord(raw["private_registries"], base.private_registries))) {
    const scopeKey = k.startsWith("@") ? k.toLowerCase() : `@${k.toLowerCase()}`;
    normalizedPrivateRegistries[scopeKey] = v.replace(/\/+$/, "");
  }

  return {
    private_scopes: asStringArray(raw["private_scopes"], base.private_scopes).map((s) =>
      s.startsWith("@") ? s.toLowerCase() : `@${s.toLowerCase()}`,
    ),
    private_prefixes: asStringArray(raw["private_prefixes"], base.private_prefixes).map((s) => s.toLowerCase()),
    private_registries: normalizedPrivateRegistries,
    default_registry: typeof raw["default_registry"] === "string" ? raw["default_registry"] : base.default_registry,
    osv_api_url:
      typeof raw["osv_api_url"] === "string" && raw["osv_api_url"].trim().length > 0
        ? raw["osv_api_url"].trim().replace(/\/+$/, "")
        : base.osv_api_url,
    allow_public_fallback: asBoolean(raw["allow_public_fallback"], base.allow_public_fallback),
    allowed_orgs: asStringArray(raw["allowed_orgs"], base.allowed_orgs).map((s) => s.toLowerCase()),
    denied_orgs: asStringArray(raw["denied_orgs"], base.denied_orgs).map((s) => s.toLowerCase()),
    blocked_licenses: asStringArray(raw["blocked_licenses"], base.blocked_licenses),
    cooldown_hours: asPositiveNumber(raw["cooldown_hours"], base.cooldown_hours),
    max_compressed_bytes: asPositiveNumber(raw["max_compressed_bytes"], base.max_compressed_bytes),
    max_uncompressed_bytes: asPositiveNumber(raw["max_uncompressed_bytes"], base.max_uncompressed_bytes),
    max_files: asPositiveNumber(raw["max_files"], base.max_files),
    max_single_file_bytes: asPositiveNumber(raw["max_single_file_bytes"], base.max_single_file_bytes),
    block_on_kev: asBoolean(raw["block_on_kev"], base.block_on_kev),
    block_on_critical_cve: asBoolean(raw["block_on_critical_cve"], base.block_on_critical_cve),
    block_on_high_cve: asBoolean(raw["block_on_high_cve"], base.block_on_high_cve),
    require_provenance: asBoolean(raw["require_provenance"], base.require_provenance),
    require_source_link: asBoolean(raw["require_source_link"], base.require_source_link),
    bisect_max_commits: asPositiveNumber(raw["bisect_max_commits"], base.bisect_max_commits),
    bisect_max_days: asPositiveNumber(raw["bisect_max_days"], base.bisect_max_days),
    intel_ttl_seconds: asPositiveNumber(raw["intel_ttl_seconds"], base.intel_ttl_seconds),
    offline_mode: asBoolean(raw["offline_mode"], base.offline_mode),
  };
}

function readPolicyJsonFile(filePath        )                          {
  const content = readCappedRegularFileSync(filePath, MAX_POLICY_BYTES).toString("utf8");
  const parsed          = JSON.parse(content);
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new Error(`Invalid policy JSON object in ${filePath}`);
  }
  return parsed                           ;
}

function mergePolicyAdditiveTighteningOnly(base              , ws              )               {
  const unionLower = (a          , b          )           =>
    Array.from(new Set([...a.map((x) => x.toLowerCase()), ...b.map((x) => x.toLowerCase())]));
  const unionExact = (a          , b          )           => Array.from(new Set([...a, ...b]));
  return {
    // Workspace policy may ADD private scopes/prefixes, denied orgs, and blocked licenses
    private_scopes: unionLower(base.private_scopes, ws.private_scopes),
    private_prefixes: unionLower(base.private_prefixes, ws.private_prefixes),
    // Never allow untrusted workspace policy to redirect registries, OSV endpoints, or public fallback
    private_registries: { ...base.private_registries },
    default_registry: base.default_registry,
    osv_api_url: base.osv_api_url,
    allow_public_fallback: base.allow_public_fallback && ws.allow_public_fallback,
    // Allowed orgs may only narrow (never widen)
    allowed_orgs:
      base.allowed_orgs.length > 0 && ws.allowed_orgs.length > 0
        ? base.allowed_orgs.filter((o) => ws.allowed_orgs.includes(o))
        : base.allowed_orgs.length > 0
          ? [...base.allowed_orgs]
          : [...ws.allowed_orgs],
    denied_orgs: unionLower(base.denied_orgs, ws.denied_orgs),
    blocked_licenses: unionExact(base.blocked_licenses, ws.blocked_licenses),
    // Thresholds & resource caps may only tighten
    cooldown_hours: Math.max(base.cooldown_hours, ws.cooldown_hours),
    max_compressed_bytes: Math.min(base.max_compressed_bytes, ws.max_compressed_bytes),
    max_uncompressed_bytes: Math.min(base.max_uncompressed_bytes, ws.max_uncompressed_bytes),
    max_files: Math.min(base.max_files, ws.max_files),
    max_single_file_bytes: Math.min(base.max_single_file_bytes, ws.max_single_file_bytes),
    // Security gates may only tighten (false -> true)
    block_on_kev: base.block_on_kev || ws.block_on_kev,
    block_on_critical_cve: base.block_on_critical_cve || ws.block_on_critical_cve,
    block_on_high_cve: base.block_on_high_cve || ws.block_on_high_cve,
    require_provenance: base.require_provenance || ws.require_provenance,
    require_source_link: base.require_source_link || ws.require_source_link,
    bisect_max_commits: Math.min(base.bisect_max_commits, ws.bisect_max_commits),
    bisect_max_days: Math.min(base.bisect_max_days, ws.bisect_max_days),
    intel_ttl_seconds: Math.min(base.intel_ttl_seconds, ws.intel_ttl_seconds),
    offline_mode: base.offline_mode || ws.offline_mode,
  };
}

export function loadPolicy(cwd        , explicitPath         )   
                       
                             
                        
  {
  const candidates           = [];
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

  let loadedPath                = null;
  let raw                          = {};
  for (const p of candidates) {
    if (existsSync(p)) {
      raw = readPolicyJsonFile(p);
      loadedPath = p;
      break;
    }
  }

  const parsedPolicy = parseRawPolicyObject(raw, DEFAULT_POLICY);
  const policy = applyPrivateRegistryEnvOverlay(parsedPolicy, Boolean(explicitPath && loadedPath));
  const policy_sha256 = createHash("sha256").update(JSON.stringify(policy)).digest("hex");
  return { policy, policy_path: loadedPath, policy_sha256 };
}

/**
 * Operator-controlled MCP policy loader (`[MCP-01]`):
 * Loads base policy strictly from `COLDPIN_POLICY_PATH` -> `~/.coldpin.policy.json` -> `DEFAULT_POLICY`.
 * Untrusted workspace `.coldpin.policy.json` files can ONLY apply additive tightening unless the
 * operator explicitly sets `COLDPIN_TRUST_WORKSPACE_POLICY=1`.
 */
export function loadMcpPolicy(options   
                              
                         
                                 
                         
 )   
                       
                             
                        
  {
  const baseCandidates           = [];
  if (options.explicitPolicyPath) {
    baseCandidates.push(resolve(options.explicitPolicyPath));
  } else {
    baseCandidates.push(join(homedir(), ".coldpin.policy.json"));
    baseCandidates.push(join(homedir(), ".npx-guard.policy.json"));
  }

  let loadedPath                = null;
  let basePolicy               = { ...DEFAULT_POLICY };
  for (const p of baseCandidates) {
    if (existsSync(p)) {
      const raw = readPolicyJsonFile(p);
      basePolicy = parseRawPolicyObject(raw, DEFAULT_POLICY);
      loadedPath = p;
      break;
    }
  }

  let effectivePolicy = applyPrivateRegistryEnvOverlay(
    basePolicy,
    Boolean(options.explicitPolicyPath && loadedPath),
  );
  if (options.workspaceRoot) {
    const wsCandidates = [
      join(resolve(options.workspaceRoot), ".coldpin.policy.json"),
      join(resolve(options.workspaceRoot), ".npx-guard.policy.json"),
    ];
    for (const wp of wsCandidates) {
      if (existsSync(wp)) {
        try {
          const wsRaw = readPolicyJsonFile(wp);
          const wsParsed = parseRawPolicyObject(wsRaw, effectivePolicy);
          effectivePolicy = options.trustWorkspacePolicy
            ? wsParsed
            : mergePolicyAdditiveTighteningOnly(effectivePolicy, wsParsed);
          if (!loadedPath && options.trustWorkspacePolicy) loadedPath = wp;
        } catch {
          // Malformed workspace policy cannot crash or downgrade the operator policy
        }
        break;
      }
    }
  }

  if (options.forceOffline) {
    effectivePolicy = { ...effectivePolicy, offline_mode: true };
  }

  const policy_sha256 = createHash("sha256").update(JSON.stringify(effectivePolicy)).digest("hex");
  return { policy: effectivePolicy, policy_path: loadedPath, policy_sha256 };
}

                                   
                                                                               
                           
                                                                                                                                                                
                                       
 

export function loadNpmrc(cwd        , options                   = {})              {
  const result              = {
    paths_loaded: [],
    scoped_registries: {},
    auth_token_env_by_host: {},
  };

  const entries                                                    = [];
  const homeRc = join(homedir(), ".npmrc");
  if (existsSync(homeRc)) entries.push({ path: homeRc, allowAuthTokens: true });

  if (options.pinnedNpmrcPath) {
    const pinned = resolve(options.pinnedNpmrcPath);
    if (existsSync(pinned) && pinned !== homeRc) {
      entries.push({ path: pinned, allowAuthTokens: true });
    }
  }

  const includeWs = options.includeWorkspaceRegistries ?? true;
  if (includeWs) {
    const gitRoot = findGitRoot(cwd);
    if (gitRoot && gitRoot !== resolve(cwd)) {
      const rootRc = join(gitRoot, ".npmrc");
      if (existsSync(rootRc) && rootRc !== homeRc) {
        entries.push({ path: rootRc, allowAuthTokens: false });
      }
    }
    const cwdRc = join(resolve(cwd), ".npmrc");
    if (existsSync(cwdRc) && cwdRc !== homeRc) {
      entries.push({ path: cwdRc, allowAuthTokens: false });
    }
  }

  for (const { path: rcPath, allowAuthTokens } of entries) {
    let content        ;
    try {
      content = readCappedRegularFileSync(rcPath, MAX_NPMRC_BYTES).toString("utf8");
    } catch {
      continue;
    }
    result.paths_loaded.push(rcPath);
    const lines = content.split(/\r?\n/);
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
      } else if (allowAuthTokens && key.startsWith("//") && key.endsWith(":_authToken")) {
        // Security [MCP-09]: parse `:_authToken` ONLY from $HOME/.npmrc or operator-pinned config
        const hostPath = key.slice(2, -":_authToken".length).replace(/^\/+|\/+$/g, "");
        const envMatch = /^\$\{([A-Z0-9_]+)\}$/.exec(val);
        if (hostPath && envMatch?.[1]) {
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

function normalizeHostPathKey(rawKey        )         {
  const trimmed = rawKey.replace(/^\/+|\/+$/g, "");
  const slashIdx = trimmed.indexOf("/");
  if (slashIdx === -1) return trimmed.toLowerCase();
  return `${trimmed.slice(0, slashIdx).toLowerCase()}${trimmed.slice(slashIdx)}`;
}

export function resolveAuthTokenForUrl(
  registryUrl        ,
  npmrc             ,
  env                    = process.env,
)                     {
  try {
    const parsed = new URL(registryUrl);
    // Security [MCP-09]: never resolve Bearer credentials for non-HTTPS URLs or public npm registries
    if (parsed.protocol !== "https:") return undefined;
    if (PUBLIC_NPM_HOSTS.has(parsed.hostname.toLowerCase())) return undefined;
    const hostLower = parsed.host.toLowerCase();
    const pathClean = parsed.pathname.replace(/\/+$/, "");
    const hostAndPath = pathClean ? `${hostLower}${pathClean}` : hostLower;
    for (const [k, envVar] of Object.entries(npmrc.auth_token_env_by_host)) {
      const kNorm = normalizeHostPathKey(k);
      if (!kNorm) continue;
      // Security [MCP-09]: exact host or '/'-segment boundary match (prevents corp.local.evil.com matching corp.local)
      if (hostAndPath === kNorm || hostAndPath.startsWith(`${kNorm}/`)) {
        return sanitizeOperatorEnvValue(env[envVar]);
      }
    }
    // Optional enterprise Antigravity variables overlay (`[PLG-09]`): exact HTTPS host+path match only
    const envRegUrl = sanitizeOperatorEnvValue(env["COLDPIN_PRIVATE_REGISTRY_URL"]);
    const envToken = sanitizeOperatorEnvValue(env["COLDPIN_REGISTRY_TOKEN"]);
    if (envRegUrl && envToken && isValidPrivateRegistryEnvUrl(envRegUrl)) {
      const envParsed = new URL(envRegUrl);
      const envHostPath = `${envParsed.host.toLowerCase()}${envParsed.pathname.replace(/\/+$/, "")}`;
      if (hostAndPath === envHostPath || hostAndPath.startsWith(`${envHostPath}/`)) {
        return envToken;
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
  packageOrScope        ,
  policy              ,
  npmrc             ,
)                      {
  const normalized = packageOrScope.trim().toLowerCase();
  const scopeMatch = /^(@[^/\s]+)/.exec(normalized);
  const scope = scopeMatch?.[1];

  const allPrivateScopes = new Set        ([
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
          const diffs           = [];
          for (let i = 0; i < a.length; i++) {
            if (a[i] !== b[i]) diffs.push(i);
            if (diffs.length > 2) return false;
          }
          return diffs.length === 2 && diffs[1] === diffs[0]  + 1 && a[diffs[0] ] === b[diffs[1] ] && a[diffs[1] ] === b[diffs[0] ];
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

function extractDiscoveryTokens(rawValue        )           {
  const out           = [];
  for (const rawTok of rawValue.split(/\s+/).filter(Boolean)) {
    const cleaned = rawTok.replace(/^["'`(,]+|["'`),.;:]+$/g, "");
    if (!cleaned) continue;
    out.push(cleaned);
    // Unwrap npm search qualifiers such as `scope:acme`, `maintainer:acme-internal-bot`, `keywords:@acme/foo`
    const qualMatch = /^(?:scope|maintainer|author|keywords|not):(.+)$/i.exec(cleaned);
    if (qualMatch?.[1]) {
      const inner = qualMatch[1].trim();
      out.push(inner);
      if (cleaned.toLowerCase().startsWith("scope:") && !inner.startsWith("@")) {
        out.push(`@${inner}`);
      }
    }
  }
  return out;
}

/**
 * Inspects every whitespace-separated token across `query`, `org`, `creator`, and `category`
 * so internal scopes, private prefixes, `scope:` qualifiers, or secret-shaped strings cannot
 * leak to public `registry.npmjs.org` (`[MCP-04]`).
 */
export function routeDiscoveryQuery(
  query        ,
  org                    ,
  policy              ,
  npmrc             ,
  extra                                          ,
)                      {
  const allRawFields = [query, org ?? "", extra?.creator ?? "", extra?.category ?? ""];
  for (const field of allRawFields) {
    if (hasSecretLikeDiscoveryToken(field)) {
      return {
        route: "blocked_secret",
        registry_url: "",
        reason: "Blocked discovery query containing credential-shaped or secret-like material.",
      };
    }
  }

  const tokens           = [];
  if (org?.trim()) {
    const trimmedOrg = org.trim();
    tokens.push(trimmedOrg.startsWith("@") ? trimmedOrg : `@${trimmedOrg}`);
    tokens.push(...extractDiscoveryTokens(trimmedOrg));
  }
  tokens.push(...extractDiscoveryTokens(query));
  if (extra?.creator?.trim()) {
    const c = extra.creator.trim();
    tokens.push(...extractDiscoveryTokens(c));
    if (!c.startsWith("@")) tokens.push(`@${c}`);
  }
  if (extra?.category?.trim()) {
    tokens.push(...extractDiscoveryTokens(extra.category.trim()));
  }

  let privateMatch                             = null;
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

export async function probeHostCapabilitiesAsync()                            {
  let gitAvailable = false;
  let gitPartialCloneSupported = false;
  let reaCliAvailable = false;
  let reaCliCommand                    ;

  try {
    const { stdout } = await execFileAsync("git", ["--version"], {
      encoding: "utf8",
      timeout: 3000,
      windowsHide: true,
    });
    gitAvailable = stdout.toLowerCase().includes("git version");
    const verMatch = /(\d+)\.(\d+)/.exec(stdout);
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
      await execFileAsync(candidate, ["--version"], {
        encoding: "utf8",
        timeout: 2000,
        windowsHide: true,
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


//# sourceURL=config/policy.ts
