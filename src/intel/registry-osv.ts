import { existsSync, readFileSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { SingleFlight, type SplitPlaneCache } from "../cache/sqlite-store.ts";
import {
  isPublicNpmRegistryUrl,
  loadNpmrc,
  routeDiscoveryQuery,
  type NpmrcConfig,
} from "../config/policy.ts";
import {
  ENGINE_VERSION,
  type AdvisoryRecord,
  type ConfusionFinding,
  type ConfusionReport,
  type DiscoveryCandidate,
  type DiscoveryCardList,
  type PackageManifest,
  type PolicyConfig,
  type Severity,
} from "../types.ts";
import { sanitizeUntrustedText } from "../analysis/static-triage.ts";
import { evaluateSlopsquatAndCooldown } from "../discovery/slopsquat-guard.ts";

const USER_AGENT = `coldpin/${ENGINE_VERSION}`;
const osvDetailFlight = new SingleFlight<Record<string, unknown> | undefined>();
const BLOCKED_METADATA_HOSTS = new Set([
  "169.254.169.254",
  "100.100.100.200",
  "metadata.google.internal",
  "metadata.goog",
  "fd00:ec2::254",
]);
const MAX_REDIRECT_HOPS = 5;

function decodeMappedIpv4(host: string): string | null {
  if (!host.startsWith("::ffff:")) return null;
  const mapped = host.slice("::ffff:".length);
  if (mapped.includes(".")) return mapped;
  const parts = mapped.split(":");
  if (parts.length !== 2) return null;
  const hi = Number.parseInt(parts[0]!, 16);
  const lo = Number.parseInt(parts[1]!, 16);
  if (!Number.isFinite(hi) || !Number.isFinite(lo)) return null;
  return `${(hi >> 8) & 0xff}.${hi & 0xff}.${(lo >> 8) & 0xff}.${lo & 0xff}`;
}

function isMetadataOrLinkLocalHost(rawHost: string): boolean {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (BLOCKED_METADATA_HOSTS.has(host) || host.startsWith("169.254.")) return true;
  if (/^fe[89ab][0-9a-f]:/.test(host)) return true;
  const mappedV4 = decodeMappedIpv4(host);
  if (mappedV4) {
    return BLOCKED_METADATA_HOSTS.has(mappedV4) || mappedV4.startsWith("169.254.");
  }
  return false;
}

function isLoopbackHost(rawHost: string): boolean {
  const host = rawHost.toLowerCase().replace(/^\[|\]$/g, "");
  if (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.startsWith("127.") ||
    host === "0.0.0.0" ||
    host === "::1" ||
    host === "::" ||
    host === "0:0:0:0:0:0:0:1"
  ) {
    return true;
  }
  const mappedV4 = decodeMappedIpv4(host);
  return Boolean(mappedV4 && (mappedV4.startsWith("127.") || mappedV4 === "0.0.0.0"));
}

function isPublicOsvUrl(rawUrl: string): boolean {
  try {
    return new URL(rawUrl).hostname.toLowerCase() === "api.osv.dev";
  } catch {
    return true;
  }
}

export function validateOutboundUrl(
  rawUrl: string,
  allowPlainHttpForExplicitOrigin?: string,
): { ok: boolean; parsed?: URL; error?: string } {
  let parsed: URL;
  try {
    parsed = new URL(rawUrl);
  } catch {
    return { ok: false, error: `Malformed URL: ${rawUrl}` };
  }
  const host = parsed.hostname.toLowerCase().replace(/^\[|\]$/g, "");
  if (isMetadataOrLinkLocalHost(host)) {
    return { ok: false, error: `Blocked link-local/cloud metadata host '${host}' (SSRF defense).` };
  }
  const matchesExplicitOrigin = Boolean(allowPlainHttpForExplicitOrigin && parsed.origin === allowPlainHttpForExplicitOrigin);
  if (isLoopbackHost(host) && !matchesExplicitOrigin) {
    return { ok: false, error: `Blocked loopback/unspecified host '${host}' (SSRF defense).` };
  }
  if (parsed.protocol === "https:") {
    return { ok: true, parsed };
  }
  if (parsed.protocol === "http:" && matchesExplicitOrigin) {
    return { ok: true, parsed };
  }
  return {
    ok: false,
    error: `Rejected non-HTTPS outbound URL '${parsed.protocol}//${parsed.host}'.`,
  };
}

export async function fetchWithSafeRedirects(params: {
  url: string;
  headers: Record<string, string>;
  authToken?: string;
  allowedAuthOrigin?: string;
  allowPlainHttpOrigin?: string;
  signal: AbortSignal;
}): Promise<{ ok: boolean; response?: Response; error?: string }> {
  let currentUrl = params.url;
  for (let hop = 0; hop <= MAX_REDIRECT_HOPS; hop++) {
    const check = validateOutboundUrl(currentUrl, params.allowPlainHttpOrigin);
    if (!check.ok || !check.parsed) {
      return { ok: false, error: check.error };
    }
    const reqHeaders: Record<string, string> = { connection: "close" };
    // Strip sensitive credential headers case-insensitively before setting origin-scoped auth (CWE-200)
    for (const [k, v] of Object.entries(params.headers)) {
      const kl = k.toLowerCase();
      if (kl === "authorization" || kl === "proxy-authorization" || kl === "cookie") continue;
      reqHeaders[k] = v;
    }
    if (params.authToken && params.allowedAuthOrigin && check.parsed.origin === params.allowedAuthOrigin) {
      reqHeaders["authorization"] = `Bearer ${params.authToken}`;
    }

    const res = await fetch(currentUrl, {
      headers: reqHeaders,
      redirect: "manual",
      signal: params.signal,
    });

    if (res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (!location) return { ok: false, error: `Redirect HTTP ${res.status} without Location header` };
      try {
        currentUrl = new URL(location, currentUrl).toString();
      } catch {
        return { ok: false, error: "Invalid redirect Location URL" };
      }
      continue;
    }

    return { ok: true, response: res };
  }
  return { ok: false, error: `Exceeded max redirect hops (${MAX_REDIRECT_HOPS})` };
}

export interface RegistryVersionMetadata {
  name: string;
  version: string;
  tarball_url: string;
  integrity?: string;
  git_head?: string;
  repository_url?: string;
  repository_directory?: string;
  provenance_attested: boolean;
  published_at?: string;
  created_at?: string;
  license: string;
  creator: string;
  description: string;
  keywords: string[];
  scripts: Record<string, string>;
  dependencies: Record<string, string>;
  optional_dependencies: Record<string, string>;
  bin_names: string[];
}

export interface PackumentSummary {
  name: string;
  latest_version: string;
  created_at?: string;
  versions_desc: Array<{
    version: string;
    published_at?: string;
    tarball_url: string;
    integrity?: string;
    git_head?: string;
    provenance_attested: boolean;
    dependencies: Record<string, string>;
    optional_dependencies: Record<string, string>;
  }>;
  latest_meta: RegistryVersionMetadata;
}

function encodePkgName(name: string): string {
  return name.startsWith("@") ? `@${encodeURIComponent(name.slice(1))}` : encodeURIComponent(name);
}

function extractLicense(raw: unknown): string {
  if (typeof raw === "string" && raw.trim()) return raw.trim();
  if (raw && typeof raw === "object" && "type" in raw && typeof (raw as { type?: unknown }).type === "string") {
    return (raw as { type: string }).type;
  }
  return "UNKNOWN";
}

function extractCreator(raw: unknown): string {
  if (typeof raw === "string" && raw.trim()) return sanitizeUntrustedText(raw, 80);
  if (raw && typeof raw === "object" && "name" in raw && typeof (raw as { name?: unknown }).name === "string") {
    return sanitizeUntrustedText((raw as { name: string }).name, 80);
  }
  return "unknown";
}

function extractRepo(raw: unknown): { url?: string; directory?: string } {
  if (typeof raw === "string") return { url: raw };
  if (raw && typeof raw === "object") {
    const obj = raw as { url?: unknown; directory?: unknown };
    return {
      url: typeof obj.url === "string" ? obj.url : undefined,
      directory: typeof obj.directory === "string" ? obj.directory : undefined,
    };
  }
  return {};
}

function extractBinNames(pkgName: string, rawBin: unknown): string[] {
  if (typeof rawBin === "string") {
    const bare = pkgName.includes("/") ? pkgName.slice(pkgName.indexOf("/") + 1) : pkgName;
    return [bare];
  }
  if (rawBin && typeof rawBin === "object" && !Array.isArray(rawBin)) {
    return Object.keys(rawBin as Record<string, unknown>);
  }
  return [];
}

function hasNpmProvenance(versionObj: Record<string, unknown>): boolean {
  const dist = versionObj["dist"];
  if (!dist || typeof dist !== "object") return false;
  const attestations = (dist as Record<string, unknown>)["attestations"];
  return Boolean(attestations && typeof attestations === "object" && "url" in (attestations as Record<string, unknown>));
}

async function fetchJsonWithTimeout<T>(
  url: string,
  headers: Record<string, string>,
  timeoutMs = 12000,
  auth?: { token?: string; allowedOrigin?: string },
): Promise<{ ok: boolean; status: number; data?: T; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let allowHttpOrigin: string | undefined;
    try {
      const p = new URL(url);
      if (p.protocol === "http:") allowHttpOrigin = p.origin;
    } catch {
      allowHttpOrigin = undefined;
    }
    const fetched = await fetchWithSafeRedirects({
      url,
      headers,
      authToken: auth?.token,
      allowedAuthOrigin: auth?.allowedOrigin,
      allowPlainHttpOrigin: allowHttpOrigin,
      signal: controller.signal,
    });
    if (!fetched.ok || !fetched.response) {
      return { ok: false, status: 0, error: fetched.error ?? "fetch failed" };
    }
    const res = fetched.response;
    if (!res.ok) return { ok: false, status: res.status, error: `HTTP ${res.status}` };
    const data = (await res.json()) as T;
    return { ok: true, status: res.status, data };
  } catch (err) {
    return { ok: false, status: 0, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchTarballBuffer(
  tarballUrl: string,
  maxBytes: number,
  authToken?: string,
  timeoutMs = 20000,
  allowedAuthOrigin?: string,
): Promise<{ ok: boolean; buffer?: Buffer; error?: string }> {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    let allowHttpOrigin: string | undefined;
    if (allowedAuthOrigin && allowedAuthOrigin.startsWith("http://")) {
      allowHttpOrigin = allowedAuthOrigin;
    }
    const fetched = await fetchWithSafeRedirects({
      url: tarballUrl,
      headers: { "user-agent": USER_AGENT },
      authToken,
      allowedAuthOrigin,
      allowPlainHttpOrigin: allowHttpOrigin,
      signal: controller.signal,
    });
    if (!fetched.ok || !fetched.response) {
      return { ok: false, error: fetched.error ?? "Failed downloading tarball" };
    }
    const res = fetched.response;
    if (!res.ok) return { ok: false, error: `HTTP ${res.status} downloading tarball` };
    const contentLen = Number.parseInt(res.headers.get("content-length") ?? "", 10);
    if (Number.isFinite(contentLen) && contentLen > maxBytes) {
      return { ok: false, error: `Tarball content-length (${contentLen}) exceeded max_compressed_bytes (${maxBytes})` };
    }
    if (!res.body) return { ok: false, error: "Empty response body" };

    const chunks: Buffer[] = [];
    let total = 0;
    const reader = res.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > maxBytes) {
          await reader.cancel();
          return { ok: false, error: `Tarball download exceeded max_compressed_bytes (${maxBytes})` };
        }
        chunks.push(Buffer.from(value));
      }
    }
    return { ok: true, buffer: Buffer.concat(chunks) };
  } catch (err) {
    return { ok: false, error: err instanceof Error ? err.message : String(err) };
  } finally {
    clearTimeout(timer);
  }
}

export async function fetchVersionMetadata(params: {
  package_name: string;
  version?: string;
  registry_url: string;
  auth_token?: string;
}): Promise<{ ok: boolean; meta?: RegistryVersionMetadata; packument?: PackumentSummary; error?: string }> {
  const headers: Record<string, string> = {
    "user-agent": USER_AGENT,
    accept: "application/json",
  };
  let registryOrigin: string | undefined;
  try {
    registryOrigin = new URL(params.registry_url).origin;
  } catch {
    return { ok: false, error: `Invalid registry URL: ${params.registry_url}` };
  }
  const auth = params.auth_token ? { token: params.auth_token, allowedOrigin: registryOrigin } : undefined;

  const baseUrl = `${params.registry_url}/${encodePkgName(params.package_name)}`;
  // Fetch packument first so time[ver] (cooldown), time.created (slopsquat age), dist-tags, and release history
  // are ALWAYS preserved even when an explicit @version is inspected!
  const res = await fetchJsonWithTimeout<Record<string, unknown>>(baseUrl, headers, 12000, auth);

  if (res.ok && res.data) {
    const doc = res.data;
    const distTags = (doc["dist-tags"] ?? {}) as Record<string, string>;
    const versions = (doc["versions"] ?? {}) as Record<string, Record<string, unknown>>;
    const timeMap = (doc["time"] ?? {}) as Record<string, string>;
    const latestVer = distTags["latest"];
    const requestedVer =
      params.version && params.version !== "latest"
        ? (versions[params.version] ? params.version : distTags[params.version])
        : latestVer;

    const buildMeta = (ver: string, vObj: Record<string, unknown>): RegistryVersionMetadata => {
      const dist = (vObj["dist"] ?? {}) as Record<string, unknown>;
      const repo = extractRepo(vObj["repository"] ?? doc["repository"]);
      return {
        name: String(vObj["name"] ?? params.package_name),
        version: ver,
        tarball_url: String(dist["tarball"] ?? ""),
        integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
        git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
        repository_url: repo.url,
        repository_directory: repo.directory,
        provenance_attested: hasNpmProvenance(vObj),
        published_at: timeMap[ver],
        created_at: timeMap["created"],
        license: extractLicense(vObj["license"] ?? doc["license"]),
        creator: extractCreator(vObj["author"] ?? vObj["_npmUser"]),
        description: sanitizeUntrustedText(String(vObj["description"] ?? doc["description"] ?? ""), 220),
        keywords: Array.isArray(vObj["keywords"] ?? doc["keywords"])
          ? ((vObj["keywords"] ?? doc["keywords"]) as unknown[])
              .filter((k): k is string => typeof k === "string")
              .slice(0, 10)
          : [],
        scripts:
          vObj["scripts"] && typeof vObj["scripts"] === "object"
            ? (vObj["scripts"] as Record<string, string>)
            : {},
        dependencies:
          vObj["dependencies"] && typeof vObj["dependencies"] === "object"
            ? (vObj["dependencies"] as Record<string, string>)
            : {},
        optional_dependencies:
          vObj["optionalDependencies"] && typeof vObj["optionalDependencies"] === "object"
            ? (vObj["optionalDependencies"] as Record<string, string>)
            : {},
        bin_names: extractBinNames(params.package_name, vObj["bin"]),
      };
    };

    if (requestedVer && versions[requestedVer]) {
      const targetMeta = buildMeta(requestedVer, versions[requestedVer]!);
      const latestMeta = latestVer && versions[latestVer] ? buildMeta(latestVer, versions[latestVer]!) : targetMeta;
      const versionsDesc = Object.entries(versions)
        .map(([ver, vObj]) => {
          const dist = (vObj["dist"] ?? {}) as Record<string, unknown>;
          return {
            version: ver,
            published_at: timeMap[ver],
            tarball_url: String(dist["tarball"] ?? ""),
            integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
            git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
            provenance_attested: hasNpmProvenance(vObj),
            dependencies:
              vObj["dependencies"] && typeof vObj["dependencies"] === "object"
                ? (vObj["dependencies"] as Record<string, string>)
                : {},
            optional_dependencies:
              vObj["optionalDependencies"] && typeof vObj["optionalDependencies"] === "object"
                ? (vObj["optionalDependencies"] as Record<string, string>)
                : {},
          };
        })
        .sort((a, b) => Date.parse(b.published_at ?? "0") - Date.parse(a.published_at ?? "0"))
        .slice(0, 30);

      return {
        ok: true,
        meta: targetMeta,
        packument: {
          name: latestMeta.name,
          latest_version: latestVer ?? requestedVer,
          created_at: timeMap["created"],
          versions_desc: versionsDesc,
          latest_meta: latestMeta,
        },
      };
    }
  }

  // Fallback to single-version endpoint if packument omitted the explicit version or returned error
  if (params.version && params.version !== "latest") {
    const singleUrl = `${baseUrl}/${encodeURIComponent(params.version)}`;
    const single = await fetchJsonWithTimeout<Record<string, unknown>>(singleUrl, headers, 12000, auth);
    if (!single.ok || !single.data) {
      return { ok: false, error: single.error ?? res.error ?? "Failed to fetch version metadata" };
    }
    const vObj = single.data;
    const dist = (vObj["dist"] ?? {}) as Record<string, unknown>;
    const repo = extractRepo(vObj["repository"]);
    const meta: RegistryVersionMetadata = {
      name: String(vObj["name"] ?? params.package_name),
      version: String(vObj["version"] ?? params.version),
      tarball_url: String(dist["tarball"] ?? ""),
      integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
      git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
      repository_url: repo.url,
      repository_directory: repo.directory,
      provenance_attested: hasNpmProvenance(vObj),
      license: extractLicense(vObj["license"]),
      creator: extractCreator(vObj["author"] ?? vObj["_npmUser"]),
      description: sanitizeUntrustedText(String(vObj["description"] ?? ""), 220),
      keywords: Array.isArray(vObj["keywords"])
        ? vObj["keywords"].filter((k): k is string => typeof k === "string").slice(0, 10)
        : [],
      scripts:
        vObj["scripts"] && typeof vObj["scripts"] === "object"
          ? (vObj["scripts"] as Record<string, string>)
          : {},
      dependencies:
        vObj["dependencies"] && typeof vObj["dependencies"] === "object"
          ? (vObj["dependencies"] as Record<string, string>)
          : {},
      optional_dependencies:
        vObj["optionalDependencies"] && typeof vObj["optionalDependencies"] === "object"
          ? (vObj["optionalDependencies"] as Record<string, string>)
          : {},
      bin_names: extractBinNames(params.package_name, vObj["bin"]),
    };
    return { ok: true, meta };
  }

  return { ok: false, error: res.error ?? `No 'latest' version found for ${params.package_name}` };
}

function mapOsvSeverity(vuln: Record<string, unknown>): Severity {
  const id = String(vuln["id"] ?? "");
  if (id.startsWith("MAL-")) return "CRITICAL";
  const dbSpec = vuln["database_specific"] as Record<string, unknown> | undefined;
  const sevStr = String(dbSpec?.["severity"] ?? "").toUpperCase();
  if (sevStr === "CRITICAL") return "CRITICAL";
  if (sevStr === "HIGH") return "HIGH";
  if (sevStr === "MODERATE" || sevStr === "MEDIUM") return "MEDIUM";
  if (sevStr === "LOW") return "LOW";
  return "HIGH";
}

export async function queryOsvAdvisories(params: {
  packages: Array<{ name: string; version?: string }>;
  policy: PolicyConfig;
  cache?: SplitPlaneCache;
  route: "private" | "public";
}): Promise<{ advisories: AdvisoryRecord[]; unknowns: string[] }> {
  const unknowns: string[] = [];
  if (params.policy.offline_mode) {
    unknowns.push("OFFLINE_INTEL_SKIPPED: OSV/OpenSSF MAL-* lookup skipped in offline mode.");
    return { advisories: [], unknowns };
  }
  const osvBaseUrl = (params.policy.osv_api_url || "https://api.osv.dev").replace(/\/+$/, "");
  if (params.route === "private" && isPublicOsvUrl(osvBaseUrl)) {
    unknowns.push("PRIVATE_SCOPE_OSV_SUPPRESSED: skipped public api.osv.dev query to prevent internal package name leakage.");
    return { advisories: [], unknowns };
  }
  if (params.packages.length === 0) return { advisories: [], unknowns };

  let osvExplicitOrigin: string | undefined;
  try {
    const parsedOsv = new URL(osvBaseUrl);
    if (parsedOsv.protocol === "http:") osvExplicitOrigin = parsedOsv.origin;
  } catch {
    unknowns.push(`OSV_API_ERROR: invalid osv_api_url '${osvBaseUrl}'`);
    return { advisories: [], unknowns };
  }
  const batchUrl = `${osvBaseUrl}/v1/querybatch`;
  const batchCheck = validateOutboundUrl(batchUrl, osvExplicitOrigin);
  if (!batchCheck.ok) {
    unknowns.push(`OSV_API_ERROR: ${batchCheck.error ?? "rejected OSV URL"}`);
    return { advisories: [], unknowns };
  }

  const advisories: AdvisoryRecord[] = [];
  const toQuery: Array<{ name: string; version?: string; key: string }> = [];

  for (const p of params.packages) {
    const key = `osv:npm:${p.name}@${p.version ?? "*"}`;
    const cached = params.cache?.getThreatIntel<AdvisoryRecord[]>(key);
    if (cached && !cached.stale) {
      advisories.push(...cached.data);
    } else {
      toQuery.push({ ...p, key });
    }
  }

  if (toQuery.length === 0) return { advisories, unknowns };

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), 12000);
  try {
    const res = await fetch(batchUrl, {
      method: "POST",
      headers: { "content-type": "application/json", "user-agent": USER_AGENT, connection: "close" },
      redirect: "manual",
      body: JSON.stringify({
        queries: toQuery.map((q) => ({
          package: { ecosystem: "npm", name: q.name },
          ...(q.version ? { version: q.version } : {}),
        })),
      }),
      signal: controller.signal,
    });
    if (!res.ok) {
      unknowns.push(`OSV_API_UNAVAILABLE: HTTP ${res.status}`);
      return { advisories, unknowns };
    }
    const body = (await res.json()) as { results?: Array<{ vulns?: Array<{ id?: string }> }> };
    const results = body.results ?? [];

    for (let i = 0; i < toQuery.length; i++) {
      const q = toQuery[i]!;
      const vulns = results[i]?.vulns ?? [];
      const pkgAdvisories: AdvisoryRecord[] = [];

      // Fetch detail for up to 10 vulns per package to bound API fan-out
      for (const v of vulns.slice(0, 10)) {
        const vid = v.id;
        if (!vid) continue;
        const detailKey = `osv-vuln:${vid}`;
        const cachedDetail = params.cache?.getThreatIntel<Record<string, unknown>>(detailKey);
        let detailObj = cachedDetail && !cachedDetail.stale ? cachedDetail.data : undefined;
        if (!detailObj) {
          detailObj = await osvDetailFlight.run(detailKey, async () => {
            const detRes = await fetchJsonWithTimeout<Record<string, unknown>>(
              `${osvBaseUrl}/v1/vulns/${encodeURIComponent(vid)}`,
              { "user-agent": USER_AGENT },
              8000,
            );
            if (detRes.ok && detRes.data) {
              params.cache?.putThreatIntel({
                intel_key: detailKey,
                source: "osv",
                payload: detRes.data,
                ttl_seconds: params.policy.intel_ttl_seconds,
              });
              return detRes.data;
            }
            return undefined;
          });
        }
        const isMal = vid.startsWith("MAL-");
        const dbSpec = detailObj?.["database_specific"] as Record<string, unknown> | undefined;
        const kev = Boolean(dbSpec?.["cisa_kev"] || String(detailObj?.["summary"] ?? "").toLowerCase().includes("known exploited"));
        pkgAdvisories.push({
          id: vid,
          is_malicious: isMal,
          severity: detailObj ? mapOsvSeverity(detailObj) : isMal ? "CRITICAL" : "HIGH",
          kev,
          summary: sanitizeUntrustedText(String(detailObj?.["summary"] ?? (isMal ? "OpenSSF Malicious Package advisory" : "OSV advisory")), 160),
          package_name: q.name,
          affected_version: q.version,
        });
      }

      params.cache?.putThreatIntel({
        intel_key: q.key,
        source: "osv",
        payload: pkgAdvisories,
        ttl_seconds: params.policy.intel_ttl_seconds,
      });
      advisories.push(...pkgAdvisories);
    }
  } catch (err) {
    unknowns.push(`OSV_API_ERROR: ${err instanceof Error ? err.message : String(err)}`);
  } finally {
    clearTimeout(timer);
  }

  return { advisories, unknowns };
}

export async function discoverPackages(params: {
  query: string;
  org?: string;
  creator?: string;
  category?: string;
  limit?: number;
  policy: PolicyConfig;
  npmrc: NpmrcConfig;
  cache?: SplitPlaneCache;
}): Promise<DiscoveryCardList> {
  const unknowns: string[] = [];
  const candidates: DiscoveryCandidate[] = [];
  const blocked_candidates: Array<{ package_name: string; reason: string }> = [];

  const routeTarget = params.org ? (params.org.startsWith("@") ? params.org : `@${params.org}`) : params.query;
  const routing = routeDiscoveryQuery(params.query, params.org, params.policy, params.npmrc);
  if (routing.route === "blocked_typo" || routing.route === "blocked_unconfigured") {
    return {
      schema_version: "1",
      query: params.query,
      filters: { org: params.org, creator: params.creator, category: params.category },
      registry_route: "private",
      candidates: [],
      blocked_candidates: [{ package_name: routing.matched_scope_or_prefix ?? routeTarget, reason: routing.reason }],
      unknowns: [routing.reason],
    };
  }

  if (params.policy.offline_mode) {
    unknowns.push("OFFLINE_MODE: live registry discovery disabled.");
    return {
      schema_version: "1",
      query: params.query,
      filters: { org: params.org, creator: params.creator, category: params.category },
      registry_route: routing.route,
      candidates: [],
      blocked_candidates: [],
      unknowns,
    };
  }

  const terms: string[] = [];
  if (params.query.trim()) terms.push(params.query.trim());
  if (params.org) terms.push(`scope:${params.org.replace(/^@/, "")}`);
  if (params.creator) terms.push(`maintainer:${params.creator}`);
  if (params.category) terms.push(`keywords:${params.category}`);

  const searchText = terms.join(" ").trim();
  const rawLimit = typeof params.limit === "number" && Number.isFinite(params.limit) ? Math.floor(params.limit) : 10;
  const size = Math.min(Math.max(rawLimit, 1), 25);
  const searchUrl = `${routing.registry_url}/-/v1/search?text=${encodeURIComponent(searchText)}&size=${size}`;
  const headers: Record<string, string> = { "user-agent": USER_AGENT };
  let searchOrigin: string | undefined;
  try {
    searchOrigin = new URL(routing.registry_url).origin;
  } catch {
    searchOrigin = undefined;
  }

  const res = await fetchJsonWithTimeout<{ objects?: Array<{ package?: Record<string, unknown> }> }>(
    searchUrl,
    headers,
    12000,
    routing.auth_token && searchOrigin ? { token: routing.auth_token, allowedOrigin: searchOrigin } : undefined,
  );
  if (!res.ok || !res.data) {
    unknowns.push(`DISCOVERY_SEARCH_FAILED: ${res.error ?? "upstream registry error"}`);
    return {
      schema_version: "1",
      query: params.query,
      filters: { org: params.org, creator: params.creator, category: params.category },
      registry_route: routing.route,
      candidates: [],
      blocked_candidates: [],
      unknowns,
    };
  }

  for (const item of res.data.objects ?? []) {
    const pkg = item.package;
    if (!pkg || typeof pkg["name"] !== "string") continue;
    const pkgName = pkg["name"];
    const version = String(pkg["version"] ?? "0.0.0");
    const scope = pkgName.startsWith("@") ? pkgName.slice(0, pkgName.indexOf("/")) : "unscoped";
    const scopeLower = scope.toLowerCase();
    const license = extractLicense(pkg["license"]);

    if (params.policy.denied_orgs.includes(scopeLower)) {
      blocked_candidates.push({ package_name: pkgName, reason: `Org/scope '${scope}' is on policy denied_orgs list.` });
      continue;
    }
    if (params.policy.allowed_orgs.length > 0 && !params.policy.allowed_orgs.includes(scopeLower)) {
      blocked_candidates.push({ package_name: pkgName, reason: `Org/scope '${scope}' is not on policy allowed_orgs list.` });
      continue;
    }
    if (params.policy.blocked_licenses.some((b) => b.toLowerCase() === license.toLowerCase())) {
      blocked_candidates.push({ package_name: pkgName, reason: `License '${license}' is blocked by enterprise policy.` });
      continue;
    }

    const squatWarnings = evaluateSlopsquatAndCooldown({
      package_name: pkgName,
      version_published_at_iso: typeof pkg["date"] === "string" ? pkg["date"] : undefined,
      has_lifecycle_scripts: false,
      policy: params.policy,
    });

    const hasCritSquat = squatWarnings.some((o) => o.severity === "CRITICAL");
    const hasWarnSquat = squatWarnings.length > 0;

    candidates.push({
      package_name: pkgName,
      version,
      org_or_scope: scope,
      creator: extractCreator(pkg["publisher"] ?? pkg["author"]),
      summary: sanitizeUntrustedText(String(pkg["description"] ?? ""), 180),
      license,
      keywords: Array.isArray(pkg["keywords"])
        ? pkg["keywords"].filter((k): k is string => typeof k === "string").slice(0, 8)
        : [],
      published_at: typeof pkg["date"] === "string" ? pkg["date"] : undefined,
      squat_warnings: squatWarnings,
      verdict_preview: hasCritSquat
        ? "MALICIOUS_INDICATORS_FOUND"
        : hasWarnSquat
          ? "QUARANTINE_SUSPICIOUS"
          : "UNVERIFIABLE_UNKNOWN",
    });
  }

  // Batch-check returned candidates against OSV/OpenSSF MAL-* (public route or configured internal OSV mirror)
  if (candidates.length > 0) {
    const osvRes = await queryOsvAdvisories({
      packages: candidates.map((c) => ({ name: c.package_name, version: c.version })),
      policy: params.policy,
      cache: params.cache,
      route: routing.route,
    });
    if (osvRes.unknowns.length > 0) unknowns.push(...osvRes.unknowns);
    for (const adv of osvRes.advisories) {
      const cand = candidates.find((c) => c.package_name === adv.package_name);
      if (!cand) continue;
      if (adv.is_malicious) {
        cand.verdict_preview = "MALICIOUS_INDICATORS_FOUND";
        cand.squat_warnings.push({
          code: "OSV_MALICIOUS_PACKAGE_ADVISORY",
          severity: "CRITICAL",
          path: "<threat-intel>",
          attack_id: "T1195.002",
          detail: `${adv.id}: ${adv.summary}`,
        });
      } else if (
        cand.verdict_preview !== "MALICIOUS_INDICATORS_FOUND" &&
        ((params.policy.block_on_kev && adv.kev) ||
          (params.policy.block_on_critical_cve && adv.severity === "CRITICAL") ||
          (params.policy.block_on_high_cve && adv.severity === "HIGH"))
      ) {
        cand.verdict_preview = "QUARANTINE_SUSPICIOUS";
      }
    }
  }

  return {
    schema_version: "1",
    query: params.query,
    filters: { org: params.org, creator: params.creator, category: params.category },
    registry_route: routing.route,
    candidates,
    blocked_candidates,
    unknowns,
  };
}

/**
 * Dependency Confusion Audit (`T1195.001`):
 * Inspects local package.json + .npmrc + policy for unpinned private scopes
 * or unscoped internal prefixes vulnerable to public registry shadowing.
 */
export async function auditDependencyConfusion(params: {
  cwd: string;
  manifestPath?: string;
  policy: PolicyConfig;
  checkPublicClaimability?: boolean;
}): Promise<ConfusionReport> {
  const manifestPath = resolve(params.manifestPath ?? resolve(params.cwd, "package.json"));
  const npmrc = loadNpmrc(dirname(manifestPath));
  const findings: ConfusionFinding[] = [];
  const unknowns: string[] = [];

  if (!existsSync(manifestPath)) {
    return {
      schema_version: "1",
      manifest_path: manifestPath,
      npmrc_paths: npmrc.paths_loaded,
      findings: [],
      passed: false,
      unknowns: [`Manifest not found at ${manifestPath}`],
    };
  }

  let pkg: PackageManifest & { peerDependencies?: Record<string, string> };
  try {
    pkg = JSON.parse(readFileSync(manifestPath, "utf8")) as PackageManifest & {
      peerDependencies?: Record<string, string>;
    };
  } catch (err) {
    return {
      schema_version: "1",
      manifest_path: manifestPath,
      npmrc_paths: npmrc.paths_loaded,
      findings: [],
      passed: false,
      unknowns: [`MANIFEST_PARSE_ERROR: failed to parse ${manifestPath}: ${err instanceof Error ? err.message : String(err)}`],
    };
  }

  const allDeps: Record<string, string> = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
    ...(pkg.devDependencies ?? {}),
    ...(pkg.peerDependencies ?? {}),
  };

  for (const [depName, range] of Object.entries(allDeps)) {
    const lower = depName.toLowerCase();
    const isScoped = lower.startsWith("@");
    const scope = isScoped ? lower.slice(0, lower.indexOf("/")) : undefined;

    if (scope && params.policy.private_scopes.includes(scope)) {
      const pinnedUrl = npmrc.scoped_registries[scope] ?? params.policy.private_registries[scope];
      if (!pinnedUrl || isPublicNpmRegistryUrl(pinnedUrl)) {
        findings.push({
          package_name: depName,
          declared_range: range,
          issue: "UNPINNED_PRIVATE_SCOPE",
          severity: "CRITICAL",
          detail: `Private scope '${scope}' is declared in policy but not pinned to a private registry in .npmrc.`,
          remediation: `Add '${scope}:registry=https://<your-private-registry>/' to project .npmrc.`,
        });
      }
      continue;
    }

    const matchedPrefix = params.policy.private_prefixes.find((pref) => lower.startsWith(pref));
    if (!isScoped && matchedPrefix) {
      findings.push({
        package_name: depName,
        declared_range: range,
        issue: "UNSCOPED_PRIVATE_PREFIX",
        severity: "HIGH",
        detail: `Unscoped internal package '${depName}' (prefix '${matchedPrefix}') is vulnerable to public npm substitution (T1195.001).`,
        remediation: `Migrate '${depName}' into an organization scope pinned in .npmrc or reserve a placeholder package.`,
      });

      if (params.checkPublicClaimability && !params.policy.offline_mode) {
        const probe = await fetchJsonWithTimeout<Record<string, unknown>>(
          `https://registry.npmjs.org/${encodePkgName(depName)}`,
          { "user-agent": USER_AGENT, accept: "application/vnd.npm.install-v1+json" },
          6000,
        );
        if (probe.status === 404) {
          findings.push({
            package_name: depName,
            declared_range: range,
            issue: "CLAIMABLE_ON_PUBLIC_NPM",
            severity: "CRITICAL",
            detail: `Unscoped internal name '${depName}' returned HTTP 404 on public npmjs.org and is immediately claimable by an attacker.`,
            remediation: `Pin registry strictly to a non-merging private proxy and reserve or scope '${depName}'.`,
          });
        } else if (probe.ok) {
          findings.push({
            package_name: depName,
            declared_range: range,
            issue: "PUBLIC_SHADOW_EXISTS",
            severity: "CRITICAL",
            detail: `Unscoped internal name '${depName}' already exists on public npmjs.org; verify ownership immediately.`,
            remediation: `Verify publisher ownership on npmjs.org and isolate internal resolution via .npmrc.`,
          });
        }
      }
    }
  }

  return {
    schema_version: "1",
    manifest_path: manifestPath,
    npmrc_paths: npmrc.paths_loaded,
    findings,
    passed: findings.length === 0 && unknowns.length === 0,
    unknowns,
  };
}
