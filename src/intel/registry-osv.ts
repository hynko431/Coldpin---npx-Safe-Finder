import { createPublicKey, verify as cryptoVerify, X509Certificate } from "node:crypto";
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
  type Observation,
  type PackageManifest,
  type PolicyConfig,
  type ProvenanceStatus,
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
  provenance_status: ProvenanceStatus;
  provenance_url?: string;
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
    provenance_status: ProvenanceStatus;
    provenance_url?: string;
    dependencies: Record<string, string>;
    optional_dependencies: Record<string, string>;
  }>;
  latest_meta: RegistryVersionMetadata;
}

export interface ProvenanceInspectionResult {
  status: ProvenanceStatus;
  provenance_url?: string;
  provenance_attested: boolean;
  predicate_type?: string;
  builder_id?: string;
  source_repo?: string;
  source_commit?: string;
  has_rekor_tlog_entry?: boolean;
  observations: Observation[];
  unknowns: string[];
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

function extractProvenanceUrl(versionObj: Record<string, unknown>): string | undefined {
  const dist = versionObj["dist"];
  if (!dist || typeof dist !== "object") return undefined;
  const attestations = (dist as Record<string, unknown>)["attestations"];
  if (!attestations || typeof attestations !== "object") return undefined;
  const url = (attestations as Record<string, unknown>)["url"];
  return typeof url === "string" && url.trim().length > 0 ? url.trim() : undefined;
}

function sriOrHexToSha512Hex(raw: string): string | null {
  const trimmed = raw.trim();
  if (trimmed.startsWith("sha512-")) {
    const buf = Buffer.from(trimmed.slice("sha512-".length), "base64");
    return buf.length === 64 ? buf.toString("hex").toLowerCase() : null;
  }
  if (/^[0-9a-f]{128}$/i.test(trimmed)) {
    return trimmed.toLowerCase();
  }
  return null;
}

function parseNpmPurl(subjectName: string): { name: string; version?: string } | null {
  if (!subjectName.startsWith("pkg:npm/")) return null;
  let rest = subjectName.slice("pkg:npm/".length);
  const qIdx = rest.indexOf("?");
  if (qIdx !== -1) rest = rest.slice(0, qIdx);
  const hIdx = rest.indexOf("#");
  if (hIdx !== -1) rest = rest.slice(0, hIdx);
  if (!rest) return null;

  const atIdx = rest.lastIndexOf("@");
  const rawName = atIdx > 0 ? rest.slice(0, atIdx) : rest;
  const rawVersion = atIdx > 0 ? rest.slice(atIdx + 1) : undefined;
  let decodedName: string;
  try {
    decodedName = decodeURIComponent(rawName);
  } catch {
    decodedName = rawName.replace(/^%40/i, "@").replace(/%2f/gi, "/");
  }
  if (!decodedName) return null;
  let decodedVersion: string | undefined;
  if (rawVersion && rawVersion.length > 0) {
    try {
      decodedVersion = decodeURIComponent(rawVersion);
    } catch {
      decodedVersion = rawVersion;
    }
  }
  return { name: decodedName, ...(decodedVersion ? { version: decodedVersion } : {}) };
}

function dssePae(payloadType: string, payloadBytes: Buffer): Buffer {
  const ptBuf = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${ptBuf.length} `, "utf8"),
    ptBuf,
    Buffer.from(` ${payloadBytes.length} `, "utf8"),
    payloadBytes,
  ]);
}

/**
 * Locally inspects an npm Sigstore/SLSA attestation document against the downloaded tarball SHA-512.
 * Epistemic boundary:
 * - Verifies in-toto Statement subject SHA-512 + npm PURL package/version identity binding and verifies
 *   the DSSE signature against the bundled leaf X.509 certificate (or explicit publicKeyPem).
 * - NEVER sets `provenance_attested: true` without Sigstore Fulcio CA chain + Rekor TUF root
 *   verification; returns `dsse_leaf_verified_unanchored` with an explicit trust-root unknown instead.
 * - Flags tampered subject digests, mismatched package/version PURLs, or invalid DSSE signatures as CRITICAL.
 */
export function verifyNpmAttestationPayload(
  doc: unknown,
  expectedTarballSha512: string,
  expectedPackageName?: string,
  provenanceUrl?: string,
  expectedPackageVersion?: string,
): ProvenanceInspectionResult {
  const observations: Observation[] = [];
  const unknowns: string[] = [];
  const expectedHex = sriOrHexToSha512Hex(expectedTarballSha512);
  if (!expectedHex) {
    unknowns.push("PROVENANCE_CRYPTO_UNVERIFIED: could not normalize expected tarball SHA-512 for attestation comparison.");
    return { status: "metadata_url_only", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  let slsaBundle: Record<string, unknown> | null = null;
  let declaredPredicateType: string | undefined;

  if (doc && typeof doc === "object") {
    const obj = doc as Record<string, unknown>;
    if (Array.isArray(obj["attestations"])) {
      for (const item of obj["attestations"]) {
        if (!item || typeof item !== "object") continue;
        const rec = item as Record<string, unknown>;
        const pt = typeof rec["predicateType"] === "string" ? rec["predicateType"] : "";
        if (pt.startsWith("https://slsa.dev/provenance/") && rec["bundle"] && typeof rec["bundle"] === "object") {
          slsaBundle = rec["bundle"] as Record<string, unknown>;
          declaredPredicateType = pt;
          break;
        }
      }
    } else if (obj["dsseEnvelope"] && typeof obj["dsseEnvelope"] === "object") {
      slsaBundle = obj;
    }
  }

  if (!slsaBundle) {
    unknowns.push(
      "PROVENANCE_CRYPTO_UNVERIFIED: registry attestation endpoint returned no SLSA provenance bundle; Sigstore/SLSA provenance is NOT verified.",
    );
    return { status: "metadata_url_only", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const envelope = slsaBundle["dsseEnvelope"];
  if (!envelope || typeof envelope !== "object") {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "npm SLSA attestation bundle is missing a valid dsseEnvelope.",
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const envObj = envelope as Record<string, unknown>;
  const payloadType = typeof envObj["payloadType"] === "string" ? envObj["payloadType"] : "";
  const payloadB64 = typeof envObj["payload"] === "string" ? envObj["payload"] : "";
  const signatures = Array.isArray(envObj["signatures"]) ? (envObj["signatures"] as Array<Record<string, unknown>>) : [];
  const sigEntries = signatures
    .map((s) => (s && typeof s === "object" && typeof s["sig"] === "string" ? String(s["sig"]).trim() : ""))
    .filter((s) => s.length > 0);

  if (payloadType !== "application/vnd.in-toto+json" || !payloadB64 || sigEntries.length === 0) {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: `Invalid or incomplete DSSE envelope (payloadType='${sanitizeUntrustedText(payloadType, 64)}').`,
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const payloadBytes = Buffer.from(payloadB64, "base64");
  let statement: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(payloadBytes.toString("utf8"));
    if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
      throw new Error("Statement is not a JSON object");
    }
    statement = parsed as Record<string, unknown>;
  } catch {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "Failed to parse base64-encoded in-toto Statement JSON inside DSSE envelope.",
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const stmtType = typeof statement["_type"] === "string" ? statement["_type"] : "";
  const stmtPredicateType = typeof statement["predicateType"] === "string" ? statement["predicateType"] : declaredPredicateType;
  if (
    (stmtType !== "https://in-toto.io/Statement/v1" && stmtType !== "https://in-toto.io/Statement/v0.1") ||
    !stmtPredicateType?.startsWith("https://slsa.dev/provenance/")
  ) {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: `Unexpected in-toto statement _type ('${sanitizeUntrustedText(stmtType, 48)}') or predicateType ('${sanitizeUntrustedText(stmtPredicateType ?? "", 64)}').`,
    });
    return { status: "verification_failed", provenance_url: provenanceUrl, provenance_attested: false, observations, unknowns };
  }

  const subjects = Array.isArray(statement["subject"]) ? (statement["subject"] as Array<Record<string, unknown>>) : [];
  const matchedSubject = subjects.find((s) => {
    const dig = s?.["digest"];
    if (!dig || typeof dig !== "object") return false;
    const sha512 = (dig as Record<string, unknown>)["sha512"];
    return typeof sha512 === "string" && sha512.toLowerCase() === expectedHex;
  });

  if (!matchedSubject) {
    observations.push({
      code: "PROVENANCE_DIGEST_MISMATCH",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "SLSA attestation subject SHA-512 does not match the verified tarball digest.",
    });
    return {
      status: "verification_failed",
      provenance_url: provenanceUrl,
      provenance_attested: false,
      predicate_type: stmtPredicateType,
      observations,
      unknowns,
    };
  }

  if (expectedPackageName) {
    const rawSubName = typeof matchedSubject["name"] === "string" ? matchedSubject["name"].trim() : "";
    const parsedPurl = rawSubName ? parseNpmPurl(rawSubName) : null;
    if (!parsedPurl) {
      observations.push({
        code: "PROVENANCE_DIGEST_MISMATCH",
        severity: "CRITICAL",
        path: "<attestation>",
        attack_id: "T1195.002",
        detail: `SLSA attestation subject name '${sanitizeUntrustedText(rawSubName || "<missing>", 80)}' is not a valid npm PURL for inspected package '${sanitizeUntrustedText(expectedPackageName, 80)}'.`,
      });
      return {
        status: "verification_failed",
        provenance_url: provenanceUrl,
        provenance_attested: false,
        predicate_type: stmtPredicateType,
        observations,
        unknowns,
      };
    }
    if (parsedPurl.name.toLowerCase() !== expectedPackageName.toLowerCase()) {
      observations.push({
        code: "PROVENANCE_DIGEST_MISMATCH",
        severity: "CRITICAL",
        path: "<attestation>",
        attack_id: "T1195.002",
        detail: `SLSA attestation subject package '${sanitizeUntrustedText(parsedPurl.name, 80)}' does not match inspected package '${sanitizeUntrustedText(expectedPackageName, 80)}'.`,
      });
      return {
        status: "verification_failed",
        provenance_url: provenanceUrl,
        provenance_attested: false,
        predicate_type: stmtPredicateType,
        observations,
        unknowns,
      };
    }
    if (expectedPackageVersion && parsedPurl.version && parsedPurl.version !== expectedPackageVersion) {
      observations.push({
        code: "PROVENANCE_DIGEST_MISMATCH",
        severity: "CRITICAL",
        path: "<attestation>",
        attack_id: "T1195.002",
        detail: `SLSA attestation subject version '${sanitizeUntrustedText(parsedPurl.version, 48)}' does not match inspected version '${sanitizeUntrustedText(expectedPackageVersion, 48)}'.`,
      });
      return {
        status: "verification_failed",
        provenance_url: provenanceUrl,
        provenance_attested: false,
        predicate_type: stmtPredicateType,
        observations,
        unknowns,
      };
    }
  }

  // Extract optional SLSA v1 / v0.2 metadata for transparency
  const pred = (statement["predicate"] && typeof statement["predicate"] === "object"
    ? (statement["predicate"] as Record<string, unknown>)
    : {}) as Record<string, unknown>;
  const runDetails = pred["runDetails"] as Record<string, unknown> | undefined;
  const builderObj = (runDetails?.["builder"] ?? pred["builder"]) as Record<string, unknown> | undefined;
  const builderId = typeof builderObj?.["id"] === "string" ? sanitizeUntrustedText(builderObj["id"], 120) : undefined;
  const buildDef = pred["buildDefinition"] as Record<string, unknown> | undefined;
  const extParams = buildDef?.["externalParameters"] as Record<string, unknown> | undefined;
  const workflow = extParams?.["workflow"] as Record<string, unknown> | undefined;
  const invocation = pred["invocation"] as Record<string, unknown> | undefined;
  const configSource = invocation?.["configSource"] as Record<string, unknown> | undefined;
  const sourceRepoRaw =
    typeof workflow?.["repository"] === "string"
      ? workflow["repository"]
      : typeof configSource?.["uri"] === "string"
        ? configSource["uri"]
        : undefined;
  const sourceRepo = sourceRepoRaw ? sanitizeUntrustedText(sourceRepoRaw, 140) : undefined;
  const resolvedDeps = Array.isArray(buildDef?.["resolvedDependencies"])
    ? (buildDef["resolvedDependencies"] as Array<Record<string, unknown>>)
    : [];
  const firstDepDigest = resolvedDeps[0]?.["digest"] as Record<string, unknown> | undefined;
  const cfgDigest = configSource?.["digest"] as Record<string, unknown> | undefined;
  const sourceCommit =
    typeof firstDepDigest?.["gitCommit"] === "string"
      ? sanitizeUntrustedText(firstDepDigest["gitCommit"], 48)
      : typeof firstDepDigest?.["sha1"] === "string"
        ? sanitizeUntrustedText(firstDepDigest["sha1"], 48)
        : typeof cfgDigest?.["sha1"] === "string"
          ? sanitizeUntrustedText(cfgDigest["sha1"], 48)
          : undefined;

  // Verify DSSE signature against bundled leaf X.509 certificate or public key
  const vm = (slsaBundle["verificationMaterial"] && typeof slsaBundle["verificationMaterial"] === "object"
    ? (slsaBundle["verificationMaterial"] as Record<string, unknown>)
    : {}) as Record<string, unknown>;
  const hasRekorTlog = Array.isArray(vm["tlogEntries"]) && vm["tlogEntries"].length > 0;

  let leafCertRawB64: string | undefined;
  const certObj = vm["certificate"] as Record<string, unknown> | undefined;
  if (typeof certObj?.["rawBytes"] === "string") {
    leafCertRawB64 = certObj["rawBytes"];
  } else {
    const chainObj = vm["x509CertificateChain"] as Record<string, unknown> | undefined;
    const certs = Array.isArray(chainObj?.["certificates"]) ? (chainObj["certificates"] as Array<Record<string, unknown>>) : [];
    if (typeof certs[0]?.["rawBytes"] === "string") {
      leafCertRawB64 = certs[0]["rawBytes"];
    }
  }
  const pubKeyPem = typeof vm["publicKeyPem"] === "string" ? vm["publicKeyPem"] : undefined;

  if (!leafCertRawB64 && !pubKeyPem) {
    unknowns.push(
      "PROVENANCE_CRYPTO_UNVERIFIED: SLSA subject SHA-512 matched tarball, but verificationMaterial omitted a certificate/public key; DSSE signature and Sigstore trust root were NOT verified.",
    );
    return {
      status: "metadata_url_only",
      provenance_url: provenanceUrl,
      provenance_attested: false,
      predicate_type: stmtPredicateType,
      builder_id: builderId,
      source_repo: sourceRepo,
      source_commit: sourceCommit,
      has_rekor_tlog_entry: hasRekorTlog,
      observations,
      unknowns,
    };
  }

  let sigValid = false;
  try {
    const pubKey = leafCertRawB64
      ? new X509Certificate(Buffer.from(leafCertRawB64, "base64")).publicKey
      : createPublicKey(pubKeyPem!);
    const keyType = pubKey.asymmetricKeyType;
    const curve = pubKey.asymmetricKeyDetails?.namedCurve;
    const hashAlg =
      keyType === "ed25519" || keyType === "ed448"
        ? null
        : curve === "secp384r1"
          ? "sha384"
          : curve === "secp521r1"
            ? "sha512"
            : "sha256";
    const pae = dssePae(payloadType, payloadBytes);
    for (const sigB64 of sigEntries) {
      if (cryptoVerify(hashAlg, pae, pubKey, Buffer.from(sigB64, "base64"))) {
        sigValid = true;
        break;
      }
    }
  } catch {
    sigValid = false;
  }

  if (!sigValid) {
    observations.push({
      code: "PROVENANCE_DSSE_SIGNATURE_INVALID",
      severity: "CRITICAL",
      path: "<attestation>",
      attack_id: "T1195.002",
      detail: "SLSA DSSE envelope signature failed cryptographic verification against the bundled certificate/key.",
    });
    return {
      status: "verification_failed",
      provenance_url: provenanceUrl,
      provenance_attested: false,
      predicate_type: stmtPredicateType,
      builder_id: builderId,
      source_repo: sourceRepo,
      source_commit: sourceCommit,
      has_rekor_tlog_entry: hasRekorTlog,
      observations,
      unknowns,
    };
  }

  unknowns.push(
    "PROVENANCE_TRUST_ROOT_UNVERIFIED: SLSA DSSE signature verified against bundled leaf certificate and subject SHA-512 matched tarball, but Sigstore Fulcio CA chain and Rekor transparency-log proofs were NOT verified locally (no embedded Sigstore TUF trusted_root). Run 'npm audit signatures' or cosign for full cryptographic verification.",
  );
  return {
    status: "dsse_leaf_verified_unanchored",
    provenance_url: provenanceUrl,
    provenance_attested: false,
    predicate_type: stmtPredicateType,
    builder_id: builderId,
    source_repo: sourceRepo,
    source_commit: sourceCommit,
    has_rekor_tlog_entry: hasRekorTlog,
    observations,
    unknowns,
  };
}

export async function inspectNpmAttestationBundle(params: {
  attestationUrl: string;
  expectedTarballSha512: string;
  expectedPackageName?: string;
  expectedPackageVersion?: string;
  route?: "private" | "public";
  authToken?: string;
  allowedAuthOrigin?: string;
  timeoutMs?: number;
}): Promise<ProvenanceInspectionResult> {
  // Enforce private-scope non-leakage: never fetch public npmjs.org or off-registry attestation URLs for private scopes
  if (params.route === "private") {
    let attOrigin: string | undefined;
    try {
      attOrigin = new URL(params.attestationUrl).origin;
    } catch {
      attOrigin = undefined;
    }
    if (
      isPublicNpmRegistryUrl(params.attestationUrl) ||
      (params.allowedAuthOrigin && attOrigin !== params.allowedAuthOrigin)
    ) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          "PRIVATE_SCOPE_PROVENANCE_FETCH_SUPPRESSED: skipped off-origin/public dist.attestations.url fetch to prevent internal package metadata leakage.",
        ],
      };
    }
  }
  const MAX_ATTESTATION_BYTES = 2 * 1024 * 1024;
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), params.timeoutMs ?? 10000);
  try {
    let allowHttpOrigin: string | undefined;
    if (params.allowedAuthOrigin && params.allowedAuthOrigin.startsWith("http://")) {
      allowHttpOrigin = params.allowedAuthOrigin;
    }
    const fetched = await fetchWithSafeRedirects({
      url: params.attestationUrl,
      headers: { "user-agent": USER_AGENT, accept: "application/json" },
      authToken: params.authToken,
      allowedAuthOrigin: params.allowedAuthOrigin,
      allowPlainHttpOrigin: allowHttpOrigin,
      signal: controller.signal,
    });
    if (!fetched.ok || !fetched.response) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          `PROVENANCE_ATTESTATION_FETCH_FAILED: registry metadata advertised dist.attestations.url, but fetching the attestation bundle failed (${fetched.error ?? "network error"}); Sigstore/SLSA provenance is NOT verified.`,
        ],
      };
    }
    const res = fetched.response;
    if (!res.ok) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          `PROVENANCE_ATTESTATION_FETCH_FAILED: registry metadata advertised dist.attestations.url, but endpoint returned HTTP ${res.status}; Sigstore/SLSA provenance is NOT verified.`,
        ],
      };
    }
    if (!res.body) {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          "PROVENANCE_ATTESTATION_FETCH_FAILED: attestation endpoint returned empty body; Sigstore/SLSA provenance is NOT verified.",
        ],
      };
    }
    const chunks: Buffer[] = [];
    let total = 0;
    const reader = res.body.getReader();
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value) {
        total += value.byteLength;
        if (total > MAX_ATTESTATION_BYTES) {
          await reader.cancel();
          return {
            status: "metadata_url_only",
            provenance_url: params.attestationUrl,
            provenance_attested: false,
            observations: [],
            unknowns: [
              `PROVENANCE_ATTESTATION_FETCH_FAILED: attestation response exceeded ${MAX_ATTESTATION_BYTES} bytes; Sigstore/SLSA provenance is NOT verified.`,
            ],
          };
        }
        chunks.push(Buffer.from(value));
      }
    }
    let parsed: unknown;
    try {
      parsed = JSON.parse(Buffer.concat(chunks).toString("utf8"));
    } catch {
      return {
        status: "metadata_url_only",
        provenance_url: params.attestationUrl,
        provenance_attested: false,
        observations: [],
        unknowns: [
          "PROVENANCE_ATTESTATION_FETCH_FAILED: attestation endpoint returned malformed JSON; Sigstore/SLSA provenance is NOT verified.",
        ],
      };
    }
    return verifyNpmAttestationPayload(
      parsed,
      params.expectedTarballSha512,
      params.expectedPackageName,
      params.attestationUrl,
      params.expectedPackageVersion,
    );
  } catch (err) {
    return {
      status: "metadata_url_only",
      provenance_url: params.attestationUrl,
      provenance_attested: false,
      observations: [],
      unknowns: [
        `PROVENANCE_ATTESTATION_FETCH_FAILED: ${err instanceof Error ? err.message : String(err)}; Sigstore/SLSA provenance is NOT verified.`,
      ],
    };
  } finally {
    clearTimeout(timer);
  }
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
      const provUrl = extractProvenanceUrl(vObj);
      return {
        name: String(vObj["name"] ?? params.package_name),
        version: ver,
        tarball_url: String(dist["tarball"] ?? ""),
        integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
        git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
        repository_url: repo.url,
        repository_directory: repo.directory,
        // Packument dist.attestations.url alone is unverified metadata, never cryptographic Sigstore attestation
        provenance_attested: false,
        provenance_status: provUrl ? "metadata_url_only" : "none",
        provenance_url: provUrl,
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
          const provUrl = extractProvenanceUrl(vObj);
          return {
            version: ver,
            published_at: timeMap[ver],
            tarball_url: String(dist["tarball"] ?? ""),
            integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
            git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
            provenance_attested: false,
            provenance_status: provUrl ? ("metadata_url_only" as const) : ("none" as const),
            provenance_url: provUrl,
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
    const provUrl = extractProvenanceUrl(vObj);
    const meta: RegistryVersionMetadata = {
      name: String(vObj["name"] ?? params.package_name),
      version: String(vObj["version"] ?? params.version),
      tarball_url: String(dist["tarball"] ?? ""),
      integrity: typeof dist["integrity"] === "string" ? dist["integrity"] : undefined,
      git_head: typeof vObj["gitHead"] === "string" ? vObj["gitHead"] : undefined,
      repository_url: repo.url,
      repository_directory: repo.directory,
      provenance_attested: false,
      provenance_status: provUrl ? "metadata_url_only" : "none",
      provenance_url: provUrl,
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
