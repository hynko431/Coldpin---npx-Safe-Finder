import { resolve } from "node:path";
import {
  extractCommitDirectDependencies,
  verifyTarballVsGitParity,
  walkGitHistoryForCleanAnchor,
} from "../analysis/parity-and-bisect.ts";
import { LIFECYCLE_HOOKS, RULESET_SHA256, triageUnpackedEntries } from "../analysis/static-triage.ts";
import { buildFactCacheKey, type SplitPlaneCache } from "../cache/sqlite-store.ts";
import {
  appendAuditEventAsync,
  MAX_AUDIT_LOG_BYTES,
  verifyAuditLogContent,
} from "../compliance/audit-log.ts";
import { routeRegistry, type NpmrcConfig } from "../config/policy.ts";
import { evaluateSlopsquatAndCooldown } from "../discovery/slopsquat-guard.ts";
import {
  auditDependencyConfusion,
  discoverPackages,
  fetchTarballBuffer,
  fetchVersionMetadata,
  inspectNpmAttestationBundle,
  queryOsvAdvisories,
  type ProvenanceInspectionResult,
} from "../intel/registry-osv.ts";
import { unpackTarballInMemory } from "../quarantine/safe-unpack.ts";
import type {
  AdvisoryRecord,
  BatchDependencyFinding,
  ConfusionReport,
  DiscoveryCardList,
  ExitCode,
  HostCapabilities,
  ManifestBatchReport,
  Observation,
  PackageInspectionReport,
  PackageManifest,
  PolicyConfig,
  ProvenanceStatus,
  SafeAnchorDecision,
  TriageResult,
} from "../types.ts";
import { assembleInspectionReport, verdictToExitCode } from "../verdict/engine-and-formatters.ts";
import { openReadCappedFile, redactHomePath, resolveConfinedPath } from "./path-confinement.ts";

export type TelemetrySink = (event: Record<string, unknown>) => void;

export interface OperatorRuntimeConfig {
  readonly policyPath?: string;
  readonly trustWorkspacePolicy: boolean;
  readonly auditLogPath?: string;
  readonly cacheDir?: string;
  readonly allowedRoots: readonly string[];
  readonly forceOffline: boolean;
  readonly verbose: boolean;
  readonly allowPublicConfusionProbe: boolean;
}

export interface WorkflowContext {
  readonly cwd?: string;
  readonly workspaceRoots: readonly string[];
  readonly enforceRootConfinement: boolean;
  readonly policy: PolicyConfig;
  readonly policy_sha256: string;
  readonly npmrc: NpmrcConfig;
  readonly host_capabilities: HostCapabilities;
  readonly cache: SplitPlaneCache;
  readonly auditLogPath?: string;
  readonly overrideTicketId?: string;
  readonly invokerSurface: "cli" | "mcp";
  readonly mcpClientName?: string;
  readonly requestId: string;
  readonly signal?: AbortSignal;
  readonly onTelemetry?: TelemetrySink;
}

export function parsePkgSpec(spec: string): { name: string; version?: string } {
  const trimmed = spec.trim();
  const atIdx = trimmed.lastIndexOf("@");
  if (atIdx > 0) {
    return { name: trimmed.slice(0, atIdx), version: trimmed.slice(atIdx + 1) };
  }
  return { name: trimmed };
}

function emitTelemetry(ctx: WorkflowContext, event: Record<string, unknown>): void {
  if (ctx.onTelemetry) {
    ctx.onTelemetry({ request_id: ctx.requestId, ...event });
  }
}

export async function runDiscover(
  ctx: WorkflowContext,
  input: {
    query: string;
    org?: string;
    creator?: string;
    category?: string;
    limit?: number;
  },
): Promise<{ ok: true; report: DiscoveryCardList; exitCode: ExitCode }> {
  const limit = input.limit ?? 10;
  const res = await discoverPackages({
    query: input.query,
    org: input.org,
    creator: input.creator,
    category: input.category,
    limit,
    policy: ctx.policy,
    npmrc: ctx.npmrc,
    cache: ctx.cache,
  });

  if (ctx.auditLogPath) {
    await appendAuditEventAsync(ctx.auditLogPath, {
      request_id: ctx.requestId,
      invoker_surface: ctx.invokerSurface,
      ...(ctx.mcpClientName ? { mcp_client_name: ctx.mcpClientName } : {}),
      ...(ctx.invokerSurface === "mcp" ? { tool_name: "discover_packages" } : {}),
      action: "discover",
      target: input.query || input.org || "*",
      verdict: res.blocked_candidates.length > 0 && res.candidates.length === 0 ? "BLOCKED" : "OK",
      policy_sha256: ctx.policy_sha256,
      evidence_ids: [],
      ...(ctx.overrideTicketId ? { override_ticket_id: ctx.overrideTicketId } : {}),
    });
  }

  emitTelemetry(ctx, {
    stage: "discover_complete",
    candidates: res.candidates.length,
    blocked: res.blocked_candidates.length,
    route: res.registry_route,
  });

  const exitCode: ExitCode = res.blocked_candidates.length > 0 && res.candidates.length === 0 ? 2 : 0;
  return { ok: true, report: res, exitCode };
}

export async function runInspect(
  ctx: WorkflowContext,
  input: {
    packageSpec?: string;
    tarballPath?: string;
    localGitDir?: string;
    subdir?: string;
    offline?: boolean;
  },
): Promise<
  | {
      ok: true;
      report: PackageInspectionReport;
      dependencies?: Record<string, string>;
      exitCode: ExitCode;
    }
  | {
      ok: false;
      error: string;
      exitCode: ExitCode;
      isOperationalError: boolean;
    }
> {
  // LLM offline flag may only tighten false -> true
  const policy: PolicyConfig =
    input.offline && !ctx.policy.offline_mode ? { ...ctx.policy, offline_mode: true } : ctx.policy;

  let resolvedTarballPath: string | undefined;
  if (input.tarballPath) {
    if (ctx.enforceRootConfinement) {
      const confined = resolveConfinedPath(input.tarballPath, ctx.workspaceRoots, {
        requireRegularFile: true,
        rejectSymlink: true,
        label: "tarball_path",
      });
      if (!confined.ok) {
        return { ok: false, error: confined.error, exitCode: 1, isOperationalError: true };
      }
      resolvedTarballPath = confined.canonicalPath;
    } else {
      resolvedTarballPath = resolve(input.tarballPath);
    }
  }

  let resolvedGitDir: string | undefined;
  if (input.localGitDir) {
    if (ctx.enforceRootConfinement) {
      const confined = resolveConfinedPath(input.localGitDir, ctx.workspaceRoots, {
        requireDirectory: true,
        label: "git_dir",
      });
      if (!confined.ok) {
        return { ok: false, error: confined.error, exitCode: 1, isOperationalError: true };
      }
      resolvedGitDir = confined.canonicalPath;
    } else {
      resolvedGitDir = resolve(input.localGitDir);
    }
  }

  const targetArg = input.packageSpec;
  let tarballBuffer: Buffer;
  let expectedIntegrity: string | undefined;
  let pkgName = targetArg ? parsePkgSpec(targetArg).name : "local-tarball";
  let pkgVersion = targetArg ? (parsePkgSpec(targetArg).version ?? "0.0.0") : "0.0.0";
  let orgOrScope = pkgName.startsWith("@") ? pkgName.slice(0, pkgName.indexOf("/")) : "unscoped";
  let creator = "unknown";
  let summary = "";
  let license = "UNKNOWN";
  let categoryTags: string[] = [];
  let publishedAt: string | undefined;
  let provenanceAttested = false;
  let provenanceStatus: ProvenanceStatus = "none";
  let provenanceUrl: string | undefined;
  let provenanceInspection: ProvenanceInspectionResult | undefined;
  let registryAuthToken: string | undefined;
  let registryAllowedOrigin: string | undefined;
  let gitHead: string | undefined;
  let repoUrl: string | undefined;
  let binNames: string[] = [];
  const registryObservations: Observation[] = [];
  const registryUnknowns: string[] = [];
  let advisories: AdvisoryRecord[] = [];
  let routeKind: "private" | "public" = "public";
  let transitiveChecked = false;

  if (resolvedTarballPath) {
    try {
      // Allow reading slightly above policy cap? No: enforce policy.max_compressed_bytes at FD read boundary in MCP;
      // in CLI unpackTarballInMemory emits TARBALL_SIZE_LIMIT_EXCEEDED if > max_compressed_bytes, so cap FD at max(policy cap * 2, 50 MiB) for CLI and exact policy cap in MCP.
      const readCap = ctx.enforceRootConfinement
        ? policy.max_compressed_bytes
        : Math.max(policy.max_compressed_bytes * 2, 50 * 1024 * 1024);
      tarballBuffer = await openReadCappedFile(resolvedTarballPath, readCap, ctx.enforceRootConfinement);
    } catch (err) {
      return {
        ok: false,
        error: `Failed reading tarball: ${err instanceof Error ? err.message : String(err)}`,
        exitCode: 1,
        isOperationalError: true,
      };
    }
    if (policy.offline_mode) {
      registryUnknowns.push("OFFLINE_INTEL_SKIPPED: local tarball inspected in offline mode.");
    }
  } else {
    if (!targetArg) {
      return {
        ok: false,
        error: "inspect requires <pkg[@ver]> or --tarball <file.tgz>",
        exitCode: 1,
        isOperationalError: true,
      };
    }
    const spec = parsePkgSpec(targetArg);
    pkgName = spec.name;
    const routing = routeRegistry(pkgName, policy, ctx.npmrc);
    if (
      routing.route === "blocked_typo" ||
      routing.route === "blocked_unconfigured" ||
      routing.route === "blocked_secret"
    ) {
      return { ok: false, error: `BLOCKED: ${routing.reason}`, exitCode: 3, isOperationalError: false };
    }
    routeKind = routing.route;
    if (policy.offline_mode) {
      return {
        ok: false,
        error: "Offline mode requires a local tarball_path (--tarball <file.tgz>).",
        exitCode: 2,
        isOperationalError: true,
      };
    }

    const metaRes = await fetchVersionMetadata({
      package_name: pkgName,
      version: spec.version,
      registry_url: routing.registry_url,
      auth_token: routing.auth_token,
      signal: ctx.signal,
    });
    if (!metaRes.ok || !metaRes.meta) {
      return {
        ok: false,
        error: `Error fetching metadata for ${pkgName}: ${metaRes.error}`,
        exitCode: 2,
        isOperationalError: true,
      };
    }
    const meta = metaRes.meta;
    pkgName = meta.name;
    pkgVersion = meta.version;
    orgOrScope = pkgName.startsWith("@") ? pkgName.slice(0, pkgName.indexOf("/")) : "unscoped";
    creator = meta.creator;
    summary = meta.description;
    license = meta.license;
    categoryTags = meta.keywords;
    publishedAt = meta.published_at;
    provenanceAttested = meta.provenance_attested;
    provenanceStatus = meta.provenance_status;
    provenanceUrl = meta.provenance_url;
    gitHead = meta.git_head;
    repoUrl = meta.repository_url;
    expectedIntegrity = meta.integrity;
    binNames = meta.bin_names;

    registryObservations.push(
      ...evaluateSlopsquatAndCooldown({
        package_name: pkgName,
        created_at_iso: meta.created_at,
        version_published_at_iso: meta.published_at,
        has_lifecycle_scripts: Object.keys(meta.scripts).some((k) => LIFECYCLE_HOOKS.has(k.toLowerCase())),
        policy,
      }),
    );

    const directDepsEntries = Object.entries({ ...meta.dependencies, ...meta.optional_dependencies }).slice(0, 50);
    const osvTargets: Array<{ name: string; version?: string }> = [{ name: pkgName, version: pkgVersion }];
    let hasFloatingDirectDeps = false;
    for (const [depName, depRange] of directDepsEntries) {
      const trimmed = depRange.trim();
      const isExact = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(trimmed);
      if (isExact) {
        osvTargets.push({ name: depName, version: trimmed });
      } else {
        hasFloatingDirectDeps = true;
      }
    }
    if (hasFloatingDirectDeps) {
      registryUnknowns.push(
        "TRANSITIVE_FLOATING_RANGES_UNRESOLVED: declared dependencies include floating semver ranges that stock npx resolves live at runtime.",
      );
    }

    const osvRes = await queryOsvAdvisories({
      packages: osvTargets,
      policy,
      cache: ctx.cache,
      route: routeKind,
    });
    advisories = osvRes.advisories;
    registryUnknowns.push(...osvRes.unknowns);
    transitiveChecked = !policy.offline_mode && !hasFloatingDirectDeps && osvRes.unknowns.length === 0;

    let allowedAuthOrigin: string | undefined;
    try {
      allowedAuthOrigin = new URL(routing.registry_url).origin;
    } catch {
      allowedAuthOrigin = undefined;
    }
    registryAuthToken = routing.auth_token;
    registryAllowedOrigin = allowedAuthOrigin;
    const dl = await fetchTarballBuffer(
      meta.tarball_url,
      policy.max_compressed_bytes,
      routing.auth_token,
      20000,
      allowedAuthOrigin,
      ctx.signal,
    );
    if (!dl.ok || !dl.buffer) {
      return {
        ok: false,
        error: `Error downloading tarball: ${dl.error}`,
        exitCode: 2,
        isOperationalError: true,
      };
    }
    tarballBuffer = dl.buffer;
  }

  const unpack = await unpackTarballInMemory(tarballBuffer, policy, expectedIntegrity);

  const triageCacheKey = buildFactCacheKey({
    content_sha: unpack.tarball_sha512,
    ruleset_sha256: RULESET_SHA256,
    options: { max_single_file_bytes: policy.max_single_file_bytes },
  });
  let triage: TriageResult;
  let triageCacheHit = false;
  const cachedTriage =
    unpack.ok && !unpack.halted_by_cap ? ctx.cache.getArtifactFacts<TriageResult>(triageCacheKey) : null;
  if (cachedTriage) {
    triage = cachedTriage;
    triageCacheHit = true;
  } else {
    triage = triageUnpackedEntries(unpack.entries, policy);
    if (unpack.ok && !unpack.halted_by_cap) {
      ctx.cache.putArtifactFacts({
        cache_key: triageCacheKey,
        content_sha: unpack.tarball_sha512,
        ruleset_sha256: RULESET_SHA256,
        facts: triage,
      });
    }
  }

  emitTelemetry(ctx, {
    stage: "inspect_triage",
    target: pkgName,
    cache_hit: triageCacheHit,
    files_inspected: triage.files_inspected,
    observations: triage.observations.length,
  });

  if (triage.manifest && resolvedTarballPath) {
    pkgName = triage.manifest.name ?? pkgName;
    pkgVersion = triage.manifest.version ?? pkgVersion;
    orgOrScope = pkgName.startsWith("@") ? pkgName.slice(0, pkgName.indexOf("/")) : "unscoped";
    creator =
      typeof triage.manifest.author === "string"
        ? triage.manifest.author
        : triage.manifest.author?.name ?? creator;
    summary = triage.manifest.description ?? summary;
    license =
      typeof triage.manifest.license === "string"
        ? triage.manifest.license
        : triage.manifest.license?.type ?? license;
    categoryTags = Array.isArray(triage.manifest.keywords) ? triage.manifest.keywords : [];
    gitHead = triage.manifest.gitHead ?? gitHead;
    if (typeof triage.manifest.bin === "string") binNames = [pkgName];
    else if (triage.manifest.bin && typeof triage.manifest.bin === "object") {
      binNames = Object.keys(triage.manifest.bin);
    }
    registryObservations.push(
      ...evaluateSlopsquatAndCooldown({
        package_name: pkgName,
        has_lifecycle_scripts: Object.keys(triage.manifest.scripts ?? {}).some((k) =>
          LIFECYCLE_HOOKS.has(k.toLowerCase()),
        ),
        policy,
      }),
    );
  }

  if (!resolvedTarballPath && !policy.offline_mode && provenanceUrl) {
    provenanceInspection = await inspectNpmAttestationBundle({
      attestationUrl: provenanceUrl,
      expectedTarballSha512: unpack.tarball_sha512,
      expectedPackageName: pkgName,
      expectedPackageVersion: pkgVersion,
      route: routeKind,
      authToken: registryAuthToken,
      allowedAuthOrigin: registryAllowedOrigin,
    });
    provenanceStatus = provenanceInspection.status;
    provenanceAttested = provenanceInspection.provenance_attested;
  }

  const parity = await verifyTarballVsGitParity({
    tarballManifest: triage.manifest,
    tarballEntries: unpack.entries,
    provenanceAttested,
    provenanceStatus,
    provenanceUrl,
    provenanceInspection,
    gitHead,
    repositoryUrl: repoUrl,
    localGitDir: resolvedGitDir,
    subdir: input.subdir,
    signal: ctx.signal,
  });

  const lockfileCwd = ctx.enforceRootConfinement ? ctx.workspaceRoots[0] : ctx.cwd;
  const report = assembleInspectionReport({
    package_name: pkgName,
    version: pkgVersion,
    org_or_scope: orgOrScope,
    creator,
    category_tags: categoryTags,
    summary,
    license,
    published_at: publishedAt,
    bin_names: binNames,
    unpack,
    triage,
    parity,
    advisories,
    registryObservations,
    registryUnknowns,
    policy,
    host_capabilities: ctx.host_capabilities,
    cwd: lockfileCwd,
    transitive_checked: transitiveChecked,
  });

  if (ctx.auditLogPath) {
    await appendAuditEventAsync(ctx.auditLogPath, {
      request_id: ctx.requestId,
      invoker_surface: ctx.invokerSurface,
      ...(ctx.mcpClientName ? { mcp_client_name: ctx.mcpClientName } : {}),
      ...(ctx.invokerSurface === "mcp" ? { tool_name: "inspect_package_artifact" } : {}),
      action: "inspect",
      target: report.title.package_name,
      version: report.title.version,
      commit_sha: report.title.commit_sha,
      tarball_sha512: report.pinned_execution.tarball_sha512,
      verdict: report.verdict,
      policy_sha256: ctx.policy_sha256,
      evidence_ids: report.evidence.map((e) => e.evidence_id),
      ...(ctx.overrideTicketId ? { override_ticket_id: ctx.overrideTicketId } : {}),
    });
  }

  return {
    ok: true,
    report,
    dependencies: triage.manifest?.dependencies,
    exitCode: verdictToExitCode(report.verdict),
  };
}

export async function runResolveAnchor(
  ctx: WorkflowContext,
  input: {
    packageName?: string;
    localGitDir?: string;
    repoUrl?: string;
    subdir?: string;
    window?: number;
  },
): Promise<
  | { ok: true; decision: SafeAnchorDecision; exitCode: ExitCode }
  | { ok: false; error: string; exitCode: ExitCode; isOperationalError: boolean }
> {
  if (!input.packageName && !input.localGitDir) {
    return {
      ok: false,
      error: "resolve-anchor requires <pkg> and/or --git-dir <path>",
      exitCode: 1,
      isOperationalError: true,
    };
  }

  const effectivePolicy: PolicyConfig = { ...ctx.policy };
  if (input.window !== undefined) {
    effectivePolicy.bisect_max_commits = ctx.enforceRootConfinement
      ? Math.min(input.window, ctx.policy.bisect_max_commits)
      : input.window;
  }

  let resolvedGitDir: string | undefined;
  if (input.localGitDir) {
    if (ctx.enforceRootConfinement) {
      const confined = resolveConfinedPath(input.localGitDir, ctx.workspaceRoots, {
        requireDirectory: true,
        label: "git_dir",
      });
      if (!confined.ok) {
        return { ok: false, error: confined.error, exitCode: 1, isOperationalError: true };
      }
      resolvedGitDir = confined.canonicalPath;
    } else {
      resolvedGitDir = resolve(input.localGitDir);
    }
  }

  const pkgName = input.packageName ? parsePkgSpec(input.packageName).name : "local-repo";
  let repoTarget = resolvedGitDir ?? input.repoUrl;
  const isLocalDir = Boolean(resolvedGitDir);
  const releaseMap = new Map<
    string,
    { version: string; tarball_sha512?: string; provenance_attested: boolean; provenance_status?: ProvenanceStatus }
  >();
  const releaseDepsByCommit = new Map<
    string,
    { exactDeps: Array<{ name: string; version: string }>; hasFloating: boolean }
  >();
  const residualAdvisoriesByCommit = new Map<string, AdvisoryRecord[]>();
  const compromisedVersions = new Set<string>();
  let binName: string | undefined;
  let categoryKeywords: string[] = [];
  let routeKind: "private" | "public" = "public";
  let matchedPrivateScope = false;

  if (!effectivePolicy.offline_mode && input.packageName) {
    const routing = routeRegistry(pkgName, effectivePolicy, ctx.npmrc);
    if (
      routing.route === "blocked_typo" ||
      routing.route === "blocked_unconfigured" ||
      routing.route === "blocked_secret"
    ) {
      return { ok: false, error: `BLOCKED: ${routing.reason}`, exitCode: 3, isOperationalError: false };
    }
    routeKind = routing.route;
    matchedPrivateScope = Boolean(routing.matched_scope_or_prefix);

    const metaRes = await fetchVersionMetadata({
      package_name: pkgName,
      registry_url: routing.registry_url,
      auth_token: routing.auth_token,
      signal: ctx.signal,
    });
    if (metaRes.ok && metaRes.packument) {
      binName = metaRes.packument.latest_meta.bin_names[0];
      categoryKeywords = metaRes.packument.latest_meta.keywords;
      const releaseOsvTargets: Array<{ name: string; version: string }> = [];
      const depOwnerCommits = new Map<string, string[]>();

      for (const v of metaRes.packument.versions_desc.slice(0, 25)) {
        releaseOsvTargets.push({ name: pkgName, version: v.version });
        if (v.git_head) {
          releaseMap.set(v.git_head, {
            version: v.version,
            tarball_sha512: v.integrity,
            provenance_attested: v.provenance_attested,
            provenance_status: v.provenance_status,
          });
          const exactDeps: Array<{ name: string; version: string }> = [];
          let hasFloating = false;
          for (const [depName, depRange] of Object.entries({ ...v.dependencies, ...v.optional_dependencies }).slice(
            0,
            30,
          )) {
            const trimmed = depRange.trim();
            if (/^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/.test(trimmed)) {
              exactDeps.push({ name: depName, version: trimmed });
              const depKey = `${depName}@${trimmed}`;
              const owners = depOwnerCommits.get(depKey) ?? [];
              owners.push(v.git_head);
              depOwnerCommits.set(depKey, owners);
            } else {
              hasFloating = true;
            }
          }
          releaseDepsByCommit.set(v.git_head, { exactDeps, hasFloating });
        }
      }

      const seenTargets = new Set(releaseOsvTargets.map((t) => `${t.name}@${t.version}`));
      for (const depKey of Array.from(depOwnerCommits.keys()).slice(0, 60)) {
        if (!seenTargets.has(depKey)) {
          const atIdx = depKey.lastIndexOf("@");
          if (atIdx > 0) {
            releaseOsvTargets.push({ name: depKey.slice(0, atIdx), version: depKey.slice(atIdx + 1) });
            seenTargets.add(depKey);
          }
        }
      }

      const relOsv = await queryOsvAdvisories({
        packages: releaseOsvTargets,
        policy: effectivePolicy,
        cache: ctx.cache,
        route: routeKind,
      });
      for (const adv of relOsv.advisories) {
        if (adv.package_name === pkgName) {
          if (adv.is_malicious && adv.affected_version) {
            compromisedVersions.add(adv.affected_version);
          }
          if (adv.affected_version) {
            for (const [sha, rel] of releaseMap.entries()) {
              if (rel.version === adv.affected_version) {
                const list = residualAdvisoriesByCommit.get(sha) ?? [];
                list.push(adv);
                residualAdvisoriesByCommit.set(sha, list);
              }
            }
          }
        } else if (adv.affected_version) {
          const owners = depOwnerCommits.get(`${adv.package_name}@${adv.affected_version}`) ?? [];
          for (const sha of owners) {
            const list = residualAdvisoriesByCommit.get(sha) ?? [];
            list.push(adv);
            residualAdvisoriesByCommit.set(sha, list);
          }
        }
      }

      if (!repoTarget && metaRes.packument.latest_meta.repository_url) {
        repoTarget = metaRes.packument.latest_meta.repository_url
          .replace(/^git\+/, "")
          .replace(/^git:\/\//, "https://");
      }
    }
  }

  if (!repoTarget) {
    return {
      ok: false,
      error: "Could not resolve repository URL; supply git_dir or repo_url.",
      exitCode: 2,
      isOperationalError: true,
    };
  }

  if (isLocalDir && !binName) {
    const localMeta = await extractCommitDirectDependencies(repoTarget, "HEAD", input.subdir, ctx.signal);
    binName = localMeta.binName;
  }

  let decision = await walkGitHistoryForCleanAnchor({
    package_name: pkgName,
    repoUrlOrLocalPath: repoTarget,
    isLocalDir,
    subdir: input.subdir,
    binName,
    policy: effectivePolicy,
    cache: ctx.cache,
    releaseTarballByCommit: releaseMap,
    residualAdvisoriesByCommit,
    compromisedVersions,
    signal: ctx.signal,
  });

  const selectedAnchorSha = decision.safe_anchor?.commit_sha;
  if (selectedAnchorSha) {
    const relDeps = releaseDepsByCommit.get(selectedAnchorSha);
    const localDeps = isLocalDir
      ? await extractCommitDirectDependencies(repoTarget, selectedAnchorSha, input.subdir, ctx.signal)
      : null;
    if (relDeps?.hasFloating || localDeps?.deps.some((d) => d.isFloating)) {
      decision.unknowns.push(
        `TRANSITIVE_FLOATING_RANGES_UNRESOLVED: safe anchor commit ${selectedAnchorSha.slice(0, 10)} declares floating dependency ranges that stock npx resolves live.`,
      );
    }
  }

  if (
    !effectivePolicy.offline_mode &&
    !matchedPrivateScope &&
    decision.alternatives.length === 0 &&
    decision.recommended_action !== "USE_PINNED_LATEST" &&
    decision.recommended_action !== "ROLLBACK_TO_SAFE_ANCHOR"
  ) {
    const altQuery = categoryKeywords[0] ?? pkgName.replace(/^@[^/]+\//, "").split(/[-_]/)[0] ?? "";
    const compromisedOrg = pkgName.startsWith("@") ? pkgName.slice(0, pkgName.indexOf("/")).toLowerCase() : "";
    if (altQuery.length >= 3) {
      const altDiscovery = await discoverPackages({
        query: altQuery,
        category: categoryKeywords[0],
        limit: 6,
        policy: effectivePolicy,
        npmrc: ctx.npmrc,
        cache: ctx.cache,
      });
      const vettedAlts = altDiscovery.candidates
        .filter(
          (c) =>
            c.package_name !== pkgName &&
            (!compromisedOrg || c.org_or_scope.toLowerCase() !== compromisedOrg) &&
            c.verdict_preview !== "MALICIOUS_INDICATORS_FOUND" &&
            c.squat_warnings.length === 0,
        )
        .slice(0, 3)
        .map((c) => ({
          package_name: c.package_name,
          version: c.version,
          org_or_scope: c.org_or_scope,
          verdict: c.verdict_preview,
          pinned_command: null,
          reason: `Candidate alternative discovered via '${altQuery}'; run 'inspect ${c.package_name}@${c.version}' before execution.`,
        }));
      if (vettedAlts.length > 0) {
        decision = {
          ...decision,
          alternatives: vettedAlts,
          recommended_action: "SWITCH_TO_ALTERNATIVE",
        };
      }
    }
  }

  if (ctx.auditLogPath) {
    await appendAuditEventAsync(ctx.auditLogPath, {
      request_id: ctx.requestId,
      invoker_surface: ctx.invokerSurface,
      ...(ctx.mcpClientName ? { mcp_client_name: ctx.mcpClientName } : {}),
      ...(ctx.invokerSurface === "mcp" ? { tool_name: "resolve_safe_anchor" } : {}),
      action: "resolve-anchor",
      target: decision.package_name,
      version: decision.safe_anchor?.version,
      commit_sha: decision.safe_anchor?.commit_sha,
      tarball_sha512: decision.safe_anchor?.tarball_sha512,
      verdict: decision.recommended_action,
      policy_sha256: ctx.policy_sha256,
      evidence_ids: decision.evidence.map((e) => e.evidence_id),
      ...(ctx.overrideTicketId ? { override_ticket_id: ctx.overrideTicketId } : {}),
    });
  }

  const exitCode: ExitCode =
    decision.recommended_action === "USE_PINNED_LATEST" ||
    decision.recommended_action === "ROLLBACK_TO_SAFE_ANCHOR"
      ? 0
      : decision.recommended_action === "BLOCK_NO_SAFE_PATH"
        ? 3
        : 2;

  return { ok: true, decision, exitCode };
}

export async function runVerifyConfusion(
  ctx: WorkflowContext,
  input: {
    manifestPath?: string;
    checkPublic?: boolean;
    allowPublicProbe: boolean;
  },
): Promise<
  | { ok: true; report: ConfusionReport; exitCode: ExitCode }
  | { ok: false; error: string; exitCode: ExitCode; isOperationalError: boolean }
> {
  let resolvedManifestPath: string | undefined;
  let effectiveCwd = ctx.cwd ?? ctx.workspaceRoots[0] ?? "";

  if (ctx.enforceRootConfinement) {
    const rawTarget = input.manifestPath ?? (ctx.workspaceRoots[0] ? resolve(ctx.workspaceRoots[0], "package.json") : "");
    if (!rawTarget) {
      return {
        ok: false,
        error: "Local manifest_path access denied: no authorized workspace roots configured.",
        exitCode: 1,
        isOperationalError: true,
      };
    }
    const confined = resolveConfinedPath(rawTarget, ctx.workspaceRoots, {
      requireRegularFile: true,
      rejectSymlink: true,
      label: "manifest_path",
    });
    if (!confined.ok) {
      return { ok: false, error: confined.error, exitCode: 1, isOperationalError: true };
    }
    resolvedManifestPath = confined.canonicalPath;
    effectiveCwd = ctx.workspaceRoots[0]!;
  } else {
    resolvedManifestPath = input.manifestPath;
  }

  const checkPublicEffective = Boolean(input.checkPublic && input.allowPublicProbe);
  const report = await auditDependencyConfusion({
    cwd: effectiveCwd,
    manifestPath: resolvedManifestPath,
    policy: ctx.policy,
    checkPublicClaimability: checkPublicEffective,
    redactHomePaths: ctx.invokerSurface === "mcp",
  });

  if (input.checkPublic && !input.allowPublicProbe) {
    report.unknowns.push(
      "PUBLIC_CONFUSION_PROBE_SUPPRESSED: check_public requires operator env COLDPIN_ALLOW_PUBLIC_CONFUSION_PROBE=1.",
    );
  }

  if (ctx.auditLogPath) {
    await appendAuditEventAsync(ctx.auditLogPath, {
      request_id: ctx.requestId,
      invoker_surface: ctx.invokerSurface,
      ...(ctx.mcpClientName ? { mcp_client_name: ctx.mcpClientName } : {}),
      ...(ctx.invokerSurface === "mcp" ? { tool_name: "verify_confusion" } : {}),
      action: "verify-confusion",
      target: report.manifest_path,
      verdict: report.passed ? "PASSED" : "CONFUSION_RISK_FOUND",
      policy_sha256: ctx.policy_sha256,
      evidence_ids: [],
      ...(ctx.overrideTicketId ? { override_ticket_id: ctx.overrideTicketId } : {}),
    });
  }

  return { ok: true, report, exitCode: report.passed ? 0 : 3 };
}

export async function runAuditVerify(
  ctx: WorkflowContext,
  input: { auditLogPath: string },
): Promise<
  | {
      ok: true;
      result: { valid: boolean; total_events: number; broken_at_seq?: number; reason?: string };
      exitCode: ExitCode;
    }
  | { ok: false; error: string; exitCode: ExitCode; isOperationalError: boolean }
> {
  let targetPath: string;
  if (ctx.enforceRootConfinement) {
    const confined = resolveConfinedPath(input.auditLogPath, ctx.workspaceRoots, {
      requireRegularFile: true,
      rejectSymlink: true,
      label: "audit_log_path",
    });
    if (!confined.ok) {
      return { ok: false, error: confined.error, exitCode: 1, isOperationalError: true };
    }
    targetPath = confined.canonicalPath;
  } else {
    targetPath = resolve(input.auditLogPath);
  }

  let rawContent: string;
  try {
    const buf = await openReadCappedFile(targetPath, MAX_AUDIT_LOG_BYTES, ctx.enforceRootConfinement);
    rawContent = buf.toString("utf8");
  } catch (err) {
    return {
      ok: false,
      error: `Audit log unreadable or exceeds size cap: ${err instanceof Error ? err.message : String(err)}`,
      exitCode: 3,
      isOperationalError: true,
    };
  }

  const result = verifyAuditLogContent(rawContent);
  return { ok: true, result, exitCode: result.valid ? 0 : 3 };
}

const MAX_BATCH_DEPS_CAP = 50;
const MAX_BATCH_MANIFEST_BYTES = 2 * 1024 * 1024;

/**
 * Deterministic concurrent batch dependency triage (`v1.4.0`, `audit_manifest_batch`):
 * Screens up to 50 direct dependencies from a root-confined `package.json` locally at $0/mo
 * using private-scope routing, 7-primitive squat screening, exact-range checks, and batched
 * OSV/OpenSSF `MAL-*` lookups (reusing Split-Plane SQLite cache & SingleFlight).
 */
export async function runAuditManifestBatch(
  ctx: WorkflowContext,
  input: {
    manifestPath?: string;
    includeDev?: boolean;
    maxDeps?: number;
    offline?: boolean;
  },
): Promise<
  | { ok: true; report: ManifestBatchReport; exitCode: ExitCode }
  | { ok: false; error: string; exitCode: ExitCode; isOperationalError: boolean }
> {
  const policy: PolicyConfig =
    input.offline && !ctx.policy.offline_mode ? { ...ctx.policy, offline_mode: true } : ctx.policy;

  let resolvedManifestPath: string;
  if (ctx.enforceRootConfinement) {
    const rawTarget = input.manifestPath ?? (ctx.workspaceRoots[0] ? resolve(ctx.workspaceRoots[0], "package.json") : "");
    if (!rawTarget) {
      return {
        ok: false,
        error: "Local manifest_path access denied: no authorized workspace roots configured.",
        exitCode: 1,
        isOperationalError: true,
      };
    }
    const confined = resolveConfinedPath(rawTarget, ctx.workspaceRoots, {
      requireRegularFile: true,
      rejectSymlink: true,
      label: "manifest_path",
    });
    if (!confined.ok) {
      return { ok: false, error: confined.error, exitCode: 1, isOperationalError: true };
    }
    resolvedManifestPath = confined.canonicalPath;
  } else {
    resolvedManifestPath = resolve(input.manifestPath ?? resolve(ctx.cwd ?? process.cwd(), "package.json"));
  }

  let pkg: PackageManifest;
  try {
    const rawBuf = await openReadCappedFile(resolvedManifestPath, MAX_BATCH_MANIFEST_BYTES, ctx.enforceRootConfinement);
    pkg = JSON.parse(rawBuf.toString("utf8")) as PackageManifest;
  } catch (err) {
    return {
      ok: false,
      error: `Failed reading manifest: ${err instanceof Error ? err.message : String(err)}`,
      exitCode: 1,
      isOperationalError: true,
    };
  }

  const combined: Record<string, string> = {
    ...(pkg.dependencies ?? {}),
    ...(pkg.optionalDependencies ?? {}),
    ...(input.includeDev ? (pkg.devDependencies ?? {}) : {}),
  };
  const allEntries = Object.entries(combined).sort(([a], [b]) => a.localeCompare(b));
  const cap = Math.min(Math.max(Math.floor(input.maxDeps ?? MAX_BATCH_DEPS_CAP), 1), MAX_BATCH_DEPS_CAP);
  const selected = allEntries.slice(0, cap);
  const truncatedAtCap = allEntries.length > cap;

  const unknowns: string[] = [];
  if (truncatedAtCap) {
    unknowns.push(`BATCH_CAP_REACHED: evaluated first ${cap} of ${allEntries.length} declared dependencies.`);
  }

  const exactVerRe = /^\d+\.\d+\.\d+(?:-[0-9A-Za-z.-]+)?$/;
  const publicOsvTargets: Array<{ name: string; version?: string }> = [];
  const privateOsvTargets: Array<{ name: string; version?: string }> = [];

  interface DepWorkItem {
    name: string;
    range: string;
    exactVer?: string;
    route: BatchDependencyFinding["route"];
    reasons: string[];
    severityRank: number; // 0 = clean, 1 = suspicious, 2 = malicious/blocked
  }

  const items: DepWorkItem[] = [];
  for (const [depName, rawRange] of selected) {
    const range = typeof rawRange === "string" ? rawRange.trim() : "";
    const exactVer = exactVerRe.test(range) ? range : undefined;
    const routing = routeRegistry(depName, policy, ctx.npmrc);
    const reasons: string[] = [];
    let severityRank = 0;

    if (
      routing.route === "blocked_typo" ||
      routing.route === "blocked_unconfigured" ||
      routing.route === "blocked_secret"
    ) {
      severityRank = 2;
      reasons.push(routing.reason);
    } else {
      const scope = depName.startsWith("@") ? depName.slice(0, depName.indexOf("/")).toLowerCase() : "unscoped";
      if (policy.denied_orgs.includes(scope)) {
        severityRank = 2;
        reasons.push(`Org/scope '${scope}' is denied by policy.`);
      } else if (policy.allowed_orgs.length > 0 && !policy.allowed_orgs.includes(scope)) {
        severityRank = Math.max(severityRank, 1);
        reasons.push(`Org/scope '${scope}' is not on policy allowed_orgs list.`);
      }

      const squatObs = evaluateSlopsquatAndCooldown({
        package_name: depName,
        has_lifecycle_scripts: false,
        policy,
      });
      for (const obs of squatObs) {
        if (obs.severity === "CRITICAL") severityRank = 2;
        else if (obs.severity === "HIGH" || obs.severity === "MEDIUM") severityRank = Math.max(severityRank, 1);
        reasons.push(`${obs.code}: ${obs.detail}`);
      }

      if (severityRank < 2) {
        if (routing.route === "public") {
          publicOsvTargets.push({ name: depName, ...(exactVer ? { version: exactVer } : {}) });
        } else if (routing.route === "private") {
          privateOsvTargets.push({ name: depName, ...(exactVer ? { version: exactVer } : {}) });
        }
      }
    }

    items.push({ name: depName, range, exactVer, route: routing.route, reasons, severityRank });
  }

  // Batch OSV queries separately by route (private scopes NEVER leak to public api.osv.dev)
  const advisoriesByPkg = new Map<string, AdvisoryRecord[]>();
  const recordAdvisories = (advs: AdvisoryRecord[]) => {
    for (const adv of advs) {
      const list = advisoriesByPkg.get(adv.package_name) ?? [];
      list.push(adv);
      advisoriesByPkg.set(adv.package_name, list);
    }
  };

  let pubOsvUnavailable = policy.offline_mode;
  let privOsvUnavailable = policy.offline_mode;

  if (publicOsvTargets.length > 0) {
    const pubOsv = await queryOsvAdvisories({
      packages: publicOsvTargets,
      policy,
      cache: ctx.cache,
      route: "public",
    });
    recordAdvisories(pubOsv.advisories);
    unknowns.push(...pubOsv.unknowns);
    if (pubOsv.unknowns.some((u) => u.startsWith("OSV_API_") || u.startsWith("OFFLINE_INTEL_"))) {
      pubOsvUnavailable = true;
    }
  }
  if (privateOsvTargets.length > 0) {
    const privOsv = await queryOsvAdvisories({
      packages: privateOsvTargets,
      policy,
      cache: ctx.cache,
      route: "private",
    });
    recordAdvisories(privOsv.advisories);
    unknowns.push(...privOsv.unknowns);
    if (
      privOsv.unknowns.some(
        (u) => u.startsWith("PRIVATE_SCOPE_OSV_") || u.startsWith("OSV_API_") || u.startsWith("OFFLINE_INTEL_"),
      )
    ) {
      privOsvUnavailable = true;
    }
  }

  const flagged: BatchDependencyFinding[] = [];
  const counts = {
    clean_screened: 0,
    flagged_suspicious: 0,
    malicious_or_blocked: 0,
    unverifiable_offline: 0,
  };

  for (const item of items) {
    const advs = advisoriesByPkg.get(item.name) ?? [];
    const advisoryIds: string[] = [];
    for (const adv of advs) {
      advisoryIds.push(adv.id);
      if (adv.is_malicious) {
        item.severityRank = 2;
        item.reasons.push(`OSV_MALICIOUS (${adv.id}): ${adv.summary}`);
      } else if (
        (policy.block_on_kev && adv.kev) ||
        (policy.block_on_critical_cve && adv.severity === "CRITICAL")
      ) {
        item.severityRank = 2;
        item.reasons.push(`OSV_BLOCKING_ADVISORY (${adv.id}, ${adv.severity}${adv.kev ? "/KEV" : ""}): ${adv.summary}`);
      } else if (policy.block_on_high_cve && adv.severity === "HIGH") {
        item.severityRank = Math.max(item.severityRank, 1);
        item.reasons.push(`OSV_HIGH_ADVISORY (${adv.id}): ${adv.summary}`);
      }
    }

    let status: BatchDependencyFinding["status"];
    if (item.severityRank >= 2) {
      status = "MALICIOUS_OR_BLOCKED";
      counts.malicious_or_blocked++;
      flagged.push({
        package_name: item.name,
        declared_range: item.range,
        route: item.route,
        status,
        reasons: item.reasons,
        advisory_ids: advisoryIds,
      });
    } else if (item.severityRank === 1) {
      status = "FLAGGED_SUSPICIOUS";
      counts.flagged_suspicious++;
      flagged.push({
        package_name: item.name,
        declared_range: item.range,
        route: item.route,
        status,
        reasons: item.reasons,
        advisory_ids: advisoryIds,
      });
    } else if ((item.route === "public" && pubOsvUnavailable) || (item.route === "private" && privOsvUnavailable)) {
      status = "UNVERIFIABLE_OFFLINE";
      counts.unverifiable_offline++;
    } else {
      status = "CLEAN_SCREENED";
      counts.clean_screened++;
    }
  }

  // Prioritize MALICIOUS_OR_BLOCKED ahead of FLAGGED_SUSPICIOUS so compact summaries always surface critical findings first
  flagged.sort((a, b) => {
    if (a.status !== b.status) return a.status === "MALICIOUS_OR_BLOCKED" ? -1 : 1;
    return a.package_name.localeCompare(b.package_name);
  });

  const displayManifestPath = ctx.invokerSurface === "mcp" ? redactHomePath(resolvedManifestPath) : resolvedManifestPath;
  const report: ManifestBatchReport = {
    schema_version: "1",
    manifest_path: displayManifestPath,
    total_declared: allEntries.length,
    evaluated_count: selected.length,
    truncated_at_cap: truncatedAtCap,
    offline_mode: policy.offline_mode,
    summary_counts: counts,
    flagged,
    unknowns: Array.from(new Set(unknowns)),
  };

  if (ctx.auditLogPath) {
    await appendAuditEventAsync(ctx.auditLogPath, {
      request_id: ctx.requestId,
      invoker_surface: ctx.invokerSurface,
      ...(ctx.mcpClientName ? { mcp_client_name: ctx.mcpClientName } : {}),
      ...(ctx.invokerSurface === "mcp" ? { tool_name: "audit_manifest_batch" } : {}),
      action: "audit-manifest-batch",
      target: displayManifestPath,
      verdict:
        counts.malicious_or_blocked > 0
          ? "MALICIOUS_INDICATORS_FOUND"
          : counts.flagged_suspicious > 0
            ? "QUARANTINE_SUSPICIOUS"
            : counts.unverifiable_offline > 0
              ? "UNVERIFIABLE_UNKNOWN"
              : "VERIFIED_CLEAN_WITHIN_SCOPE",
      policy_sha256: ctx.policy_sha256,
      evidence_ids: [],
      ...(ctx.overrideTicketId ? { override_ticket_id: ctx.overrideTicketId } : {}),
    });
  }

  emitTelemetry(ctx, {
    stage: "audit_manifest_batch_complete",
    evaluated: selected.length,
    malicious_or_blocked: counts.malicious_or_blocked,
    flagged_suspicious: counts.flagged_suspicious,
  });

  const exitCode: ExitCode =
    counts.malicious_or_blocked > 0
      ? 3
      : counts.flagged_suspicious > 0 || counts.unverifiable_offline > 0
        ? 2
        : 0;
  return { ok: true, report, exitCode };
}
