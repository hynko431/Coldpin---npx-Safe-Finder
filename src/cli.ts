#!/usr/bin/env node
import { randomUUID } from "node:crypto";
import { readFileSync } from "node:fs";
import { resolve } from "node:path";
import {
  extractCommitDirectDependencies,
  verifyTarballVsGitParity,
  walkGitHistoryForCleanAnchor,
} from "./analysis/parity-and-bisect.ts";
import { LIFECYCLE_HOOKS, RULESET_SHA256, triageUnpackedEntries } from "./analysis/static-triage.ts";
import { buildFactCacheKey, defaultCacheDbPath, SplitPlaneCache } from "./cache/sqlite-store.ts";
import { appendAuditEvent, logOperationalEvent, verifyAuditLog } from "./compliance/audit-log.ts";
import { loadNpmrc, loadPolicy, probeHostCapabilities, routeRegistry } from "./config/policy.ts";
import { evaluateSlopsquatAndCooldown } from "./discovery/slopsquat-guard.ts";
import {
  auditDependencyConfusion,
  discoverPackages,
  fetchTarballBuffer,
  fetchVersionMetadata,
  queryOsvAdvisories,
} from "./intel/registry-osv.ts";
import { unpackTarballInMemory } from "./quarantine/safe-unpack.ts";
import { ENGINE_VERSION, type AdvisoryRecord, type ExitCode, type Observation, type TriageResult } from "./types.ts";
import {
  assembleInspectionReport,
  formatAnchorMarkdown,
  formatCycloneDxSbom,
  formatDiscoveryMarkdown,
  formatInspectionMarkdownCard,
  formatSarif210,
  verdictToExitCode,
} from "./verdict/engine-and-formatters.ts";

interface ParsedArgs {
  command: string;
  positionals: string[];
  flags: Record<string, string | boolean>;
  error?: string;
}

const BOOLEAN_FLAGS = new Set([
  "json",
  "sarif",
  "sbom",
  "offline",
  "verbose",
  "check-public",
  "help",
]);

const VALUE_FLAGS = new Set([
  "tarball",
  "git-dir",
  "repo-url",
  "subdir",
  "org",
  "creator",
  "category",
  "limit",
  "window",
  "policy",
  "cache-dir",
  "audit-log",
  "override-ticket",
]);

function parseCliArgs(argv: string[]): ParsedArgs {
  const positionals: string[] = [];
  const flags: Record<string, string | boolean> = {};
  const args = argv.slice(2);
  let i = 0;
  let afterDoubleDash = false;
  while (i < args.length) {
    const a = args[i]!;
    if (afterDoubleDash) {
      positionals.push(a);
      i++;
      continue;
    }
    if (a === "--") {
      afterDoubleDash = true;
      i++;
      continue;
    }
    if (a === "-h") {
      flags["help"] = true;
      i++;
      continue;
    }
    if (a.startsWith("--")) {
      const eqIdx = a.indexOf("=");
      if (eqIdx > 2) {
        const key = a.slice(2, eqIdx);
        const val = a.slice(eqIdx + 1);
        if (BOOLEAN_FLAGS.has(key)) {
          flags[key] = val === "true" || val === "1";
        } else if (VALUE_FLAGS.has(key)) {
          flags[key] = val;
        } else {
          return { command: "help", positionals, flags, error: `Unknown flag: --${key}` };
        }
      } else {
        const key = a.slice(2);
        if (BOOLEAN_FLAGS.has(key)) {
          flags[key] = true;
        } else if (VALUE_FLAGS.has(key)) {
          const next = args[i + 1];
          if (next === undefined || next.startsWith("--")) {
            return { command: "help", positionals, flags, error: `Flag --${key} requires a value` };
          }
          flags[key] = next;
          i++;
        } else {
          return { command: "help", positionals, flags, error: `Unknown flag: --${key}` };
        }
      }
    } else {
      positionals.push(a);
    }
    i++;
  }
  const command = positionals.shift() ?? "help";
  return { command, positionals, flags };
}

function strFlag(flags: Record<string, string | boolean>, name: string): string | undefined {
  const v = flags[name];
  return typeof v === "string" ? v : undefined;
}

function boolFlag(flags: Record<string, string | boolean>, name: string): boolean {
  return flags[name] === true || flags[name] === "true";
}

function parsePkgSpec(spec: string): { name: string; version?: string } {
  const trimmed = spec.trim();
  const atIdx = trimmed.lastIndexOf("@");
  if (atIdx > 0) {
    return { name: trimmed.slice(0, atIdx), version: trimmed.slice(atIdx + 1) };
  }
  return { name: trimmed };
}

function printHelp(): void {
  const help = `coldpin v${ENGINE_VERSION} — Inspect npx packages cold in memory; pin clean releases with verifiable evidence

USAGE:
  node src/cli.ts <command> [target] [flags]

COMMANDS:
  discover [query]          Search npm packages by query/category/creator/org with slopsquat & policy guards
  inspect <pkg[@ver]>       Zero-exec tarball inspection, AST taint triage, parity & verdict card
  resolve-anchor <pkg>      Identify patient-zero commit and safe pre-compromise release/alternative
  verify-confusion [path]   Audit package.json & .npmrc for dependency confusion (T1195.001)
  audit-verify <jsonl>      Verify local hash-chained audit.jsonl integrity

COMMON FLAGS:
  --json                    Emit canonical JSON to stdout
  --sarif                   Emit SARIF 2.1.0 JSON (inspect)
  --sbom                    Emit CycloneDX 1.5 SBOM + VEX JSON (inspect)
  --tarball <file.tgz>      Inspect a local tarball offline (inspect)
  --git-dir <dir>           Local Git repository path for parity or commit bisect
  --repo-url <url>          Git repository URL for treeless commit bisect (resolve-anchor)
  --subdir <path>           Monorepo subdirectory inside Git repo
  --org <scope>             Filter by npm org/scope (discover)
  --creator <handle>        Filter by maintainer/creator (discover)
  --category <keyword>      Filter by capability/category keyword (discover)
  --limit <n>               Max discovery results (default 10)
  --window <n>              Max commits to bisect (overrides policy bisect_max_commits)
  --policy <file>           Explicit .coldpin.policy.json path
  --cache-dir <dir>         Cache directory (or :memory:)
  --audit-log <file>        Append local hash-chained audit event to JSONL file
  --override-ticket <id>    Record security approval ticket ID in audit.jsonl (does not alter verdict)
  --verbose                 Emit structured operational JSON telemetry to stderr (zero secrets/PII)
  --offline                 Disable all outbound network queries (fail closed)
  --check-public            Probe public npmjs.org for unscoped claimability (verify-confusion)

EXIT CODES:
  0 = VERIFIED_CLEAN_WITHIN_SCOPE / check passed
  2 = QUARANTINE_SUSPICIOUS or UNVERIFIABLE_UNKNOWN
  3 = MALICIOUS_INDICATORS_FOUND / confusion or audit integrity failure
  1 = CLI usage or runtime error`;
  process.stdout.write(`${help}\n`);
}

async function main(): Promise<ExitCode> {
  const parsed = parseCliArgs(process.argv);
  if (parsed.error) {
    process.stderr.write(`Error: ${parsed.error}\n`);
    return 1;
  }
  if (parsed.command === "help" || boolFlag(parsed.flags, "help")) {
    printHelp();
    return 0;
  }

  const cwd = process.cwd();
  const { policy, policy_sha256 } = loadPolicy(cwd, strFlag(parsed.flags, "policy"));
  if (boolFlag(parsed.flags, "offline")) policy.offline_mode = true;
  const windowArg = strFlag(parsed.flags, "window");
  if (windowArg !== undefined) {
    const parsedWindow = Number(windowArg);
    if (!Number.isInteger(parsedWindow) || parsedWindow < 1) {
      process.stderr.write(`Error: --window must be a positive integer (got '${windowArg}')\n`);
      return 1;
    }
    policy.bisect_max_commits = parsedWindow;
  }

  const npmrc = loadNpmrc(cwd);
  const hostCaps = probeHostCapabilities();
  const cacheDir = strFlag(parsed.flags, "cache-dir");
  const cache = new SplitPlaneCache(cacheDir ? defaultCacheDbPath(cacheDir) : defaultCacheDbPath());
  const auditLogPath = strFlag(parsed.flags, "audit-log");
  const overrideTicketId = strFlag(parsed.flags, "override-ticket");
  const verbose = boolFlag(parsed.flags, "verbose");
  const requestId = `req_${randomUUID().slice(0, 12)}`;
  const asJson = boolFlag(parsed.flags, "json");

  logOperationalEvent(verbose, {
    request_id: requestId,
    stage: "cli_start",
    command: parsed.command,
    offline: policy.offline_mode,
  });

  try {
    if (parsed.command === "discover") {
      const query = parsed.positionals.join(" ");
      const limitStr = strFlag(parsed.flags, "limit");
      let limit = 10;
      if (limitStr !== undefined) {
        const parsedLimit = Number(limitStr);
        if (!Number.isInteger(parsedLimit) || parsedLimit < 1) {
          process.stderr.write(`Error: --limit must be a positive integer (got '${limitStr}')\n`);
          return 1;
        }
        limit = parsedLimit;
      }
      const res = await discoverPackages({
        query,
        org: strFlag(parsed.flags, "org"),
        creator: strFlag(parsed.flags, "creator"),
        category: strFlag(parsed.flags, "category"),
        limit,
        policy,
        npmrc,
        cache,
      });
      if (auditLogPath) {
        appendAuditEvent(auditLogPath, {
          request_id: requestId,
          action: "discover",
          target: query || strFlag(parsed.flags, "org") || "*",
          verdict: res.blocked_candidates.length > 0 && res.candidates.length === 0 ? "BLOCKED" : "OK",
          policy_sha256,
          evidence_ids: [],
          ...(overrideTicketId ? { override_ticket_id: overrideTicketId } : {}),
        });
      }
      logOperationalEvent(verbose, {
        request_id: requestId,
        stage: "discover_complete",
        candidates: res.candidates.length,
        blocked: res.blocked_candidates.length,
        route: res.registry_route,
      });
      process.stdout.write(asJson ? `${JSON.stringify(res, null, 2)}\n` : `${formatDiscoveryMarkdown(res)}\n`);
      return res.blocked_candidates.length > 0 && res.candidates.length === 0 ? 2 : 0;
    }

    if (parsed.command === "inspect") {
      const localTarballPath = strFlag(parsed.flags, "tarball");
      const localGitDir = strFlag(parsed.flags, "git-dir");
      const subdir = strFlag(parsed.flags, "subdir");
      const targetArg = parsed.positionals[0];

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
      let gitHead: string | undefined;
      let repoUrl: string | undefined;
      let binNames: string[] = [];
      const registryObservations: Observation[] = [];
      const registryUnknowns: string[] = [];
      let advisories: AdvisoryRecord[] = [];
      let routeKind: "private" | "public" = "public";
      let transitiveChecked = false;

      if (localTarballPath) {
        tarballBuffer = readFileSync(resolve(localTarballPath));
        if (policy.offline_mode) {
          registryUnknowns.push("OFFLINE_INTEL_SKIPPED: local tarball inspected in offline mode.");
        }
      } else {
        if (!targetArg) {
          process.stderr.write("Error: inspect requires <pkg[@ver]> or --tarball <file.tgz>\n");
          return 1;
        }
        const spec = parsePkgSpec(targetArg);
        pkgName = spec.name;
        const routing = routeRegistry(pkgName, policy, npmrc);
        if (routing.route === "blocked_typo" || routing.route === "blocked_unconfigured") {
          process.stderr.write(`BLOCKED: ${routing.reason}\n`);
          return 3;
        }
        routeKind = routing.route;
        if (policy.offline_mode) {
          process.stderr.write("Error: --offline requires --tarball <file.tgz>\n");
          return 2;
        }

        const metaRes = await fetchVersionMetadata({
          package_name: pkgName,
          version: spec.version,
          registry_url: routing.registry_url,
          auth_token: routing.auth_token,
        });
        if (!metaRes.ok || !metaRes.meta) {
          process.stderr.write(`Error fetching metadata for ${pkgName}: ${metaRes.error}\n`);
          return 2;
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

        // Query OSV for top-level package + up to 50 declared direct dependencies
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
          cache,
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
        const dl = await fetchTarballBuffer(
          meta.tarball_url,
          policy.max_compressed_bytes,
          routing.auth_token,
          20000,
          allowedAuthOrigin,
        );
        if (!dl.ok || !dl.buffer) {
          process.stderr.write(`Error downloading tarball: ${dl.error}\n`);
          return 2;
        }
        tarballBuffer = dl.buffer;
      }

      const unpack = await unpackTarballInMemory(tarballBuffer, policy, expectedIntegrity);

      // Split-Plane SQLite Cache: cache immutable static triage facts only when unpack succeeded without hitting caps
      const triageCacheKey = buildFactCacheKey({
        content_sha: unpack.tarball_sha512,
        ruleset_sha256: RULESET_SHA256,
        options: { max_single_file_bytes: policy.max_single_file_bytes },
      });
      let triage: TriageResult;
      let triageCacheHit = false;
      const cachedTriage =
        unpack.ok && !unpack.halted_by_cap ? cache.getArtifactFacts<TriageResult>(triageCacheKey) : null;
      if (cachedTriage) {
        triage = cachedTriage;
        triageCacheHit = true;
      } else {
        triage = triageUnpackedEntries(unpack.entries, policy);
        if (unpack.ok && !unpack.halted_by_cap) {
          cache.putArtifactFacts({
            cache_key: triageCacheKey,
            content_sha: unpack.tarball_sha512,
            ruleset_sha256: RULESET_SHA256,
            facts: triage,
          });
        }
      }

      logOperationalEvent(verbose, {
        request_id: requestId,
        stage: "inspect_triage",
        target: pkgName,
        cache_hit: triageCacheHit,
        files_inspected: triage.files_inspected,
        observations: triage.observations.length,
      });

      if (triage.manifest) {
        if (localTarballPath) {
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
          // Run typosquat check on local tarball's declared package name too
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
      }

      const parity = verifyTarballVsGitParity({
        tarballManifest: triage.manifest,
        tarballEntries: unpack.entries,
        provenanceAttested,
        gitHead,
        repositoryUrl: repoUrl,
        localGitDir: localGitDir ? resolve(localGitDir) : undefined,
        subdir,
      });

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
        host_capabilities: hostCaps,
        cwd,
        transitive_checked: transitiveChecked,
      });

      if (auditLogPath) {
        appendAuditEvent(auditLogPath, {
          request_id: requestId,
          action: "inspect",
          target: report.title.package_name,
          version: report.title.version,
          commit_sha: report.title.commit_sha,
          tarball_sha512: report.pinned_execution.tarball_sha512,
          verdict: report.verdict,
          policy_sha256,
          evidence_ids: report.evidence.map((e) => e.evidence_id),
          ...(overrideTicketId ? { override_ticket_id: overrideTicketId } : {}),
        });
      }

      if (boolFlag(parsed.flags, "sarif")) {
        process.stdout.write(`${JSON.stringify(formatSarif210(report), null, 2)}\n`);
      } else if (boolFlag(parsed.flags, "sbom")) {
        process.stdout.write(`${JSON.stringify(formatCycloneDxSbom(report, triage.manifest?.dependencies), null, 2)}\n`);
      } else if (asJson) {
        process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      } else {
        process.stdout.write(`${formatInspectionMarkdownCard(report)}\n`);
      }
      return verdictToExitCode(report.verdict);
    }

    if (parsed.command === "resolve-anchor") {
      const targetArg = parsed.positionals[0];
      const localGitDir = strFlag(parsed.flags, "git-dir");
      const explicitRepoUrl = strFlag(parsed.flags, "repo-url");
      const subdir = strFlag(parsed.flags, "subdir");

      if (!targetArg && !localGitDir) {
        process.stderr.write("Error: resolve-anchor requires <pkg> and/or --git-dir <path>\n");
        return 1;
      }

      const pkgName = targetArg ? parsePkgSpec(targetArg).name : "local-repo";
      let repoTarget = localGitDir ? resolve(localGitDir) : explicitRepoUrl;
      const isLocalDir = Boolean(localGitDir);
      const releaseMap = new Map<string, { version: string; tarball_sha512?: string; provenance_attested: boolean }>();
      const releaseDepsByCommit = new Map<string, { exactDeps: Array<{ name: string; version: string }>; hasFloating: boolean }>();
      const residualAdvisoriesByCommit = new Map<string, AdvisoryRecord[]>();
      const compromisedVersions = new Set<string>();
      let binName: string | undefined;
      let categoryKeywords: string[] = [];
      let routeKind: "private" | "public" = "public";
      let matchedPrivateScope = false;

      if (!policy.offline_mode && targetArg) {
        const routing = routeRegistry(pkgName, policy, npmrc);
        if (routing.route === "blocked_typo" || routing.route === "blocked_unconfigured") {
          process.stderr.write(`BLOCKED: ${routing.reason}\n`);
          return 3;
        }
        routeKind = routing.route;
        matchedPrivateScope = Boolean(routing.matched_scope_or_prefix);

        // Always fetch packument + OSV advisories when online (including with --git-dir) so releaseMap,
        // tarball-only MAL-* compromises, and rollback CVE/KEV gates are populated accurately!
        const metaRes = await fetchVersionMetadata({
          package_name: pkgName,
          registry_url: routing.registry_url,
          auth_token: routing.auth_token,
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
              });
              const exactDeps: Array<{ name: string; version: string }> = [];
              let hasFloating = false;
              for (const [depName, depRange] of Object.entries({ ...v.dependencies, ...v.optional_dependencies }).slice(0, 30)) {
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

          // Deduplicate direct dependency OSV targets across mapped releases (capped at 60)
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

          // Query OSV for published releases + exact-pinned direct deps so tarball-only MAL-* & poisoned deps block rollback
          const relOsv = await queryOsvAdvisories({
            packages: releaseOsvTargets,
            policy,
            cache,
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
        process.stderr.write("Error: could not resolve repository URL; supply --git-dir <dir> or --repo-url <url>\n");
        return 2;
      }

      if (isLocalDir && !binName) {
        const localMeta = extractCommitDirectDependencies(repoTarget, "HEAD", subdir);
        binName = localMeta.binName;
      }

      let decision = walkGitHistoryForCleanAnchor({
        package_name: pkgName,
        repoUrlOrLocalPath: repoTarget,
        isLocalDir,
        subdir,
        binName,
        policy,
        cache,
        releaseTarballByCommit: releaseMap,
        residualAdvisoriesByCommit,
        compromisedVersions,
      });

      // Disclose floating direct dependency ranges on the selected safe anchor
      const selectedAnchorSha = decision.safe_anchor?.commit_sha;
      if (selectedAnchorSha) {
        const relDeps = releaseDepsByCommit.get(selectedAnchorSha);
        const localDeps = isLocalDir ? extractCommitDirectDependencies(repoTarget, selectedAnchorSha, subdir) : null;
        if (relDeps?.hasFloating || localDeps?.deps.some((d) => d.isFloating)) {
          decision.unknowns.push(
            `TRANSITIVE_FLOATING_RANGES_UNRESOLVED: safe anchor commit ${selectedAnchorSha.slice(0, 10)} declares floating dependency ranges that stock npx resolves live.`,
          );
        }
      }

      // When online (and not a private-scoped package) and rollback is blocked/forensic-only, auto-discover alternatives
      if (
        !policy.offline_mode &&
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
            policy,
            npmrc,
            cache,
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

      if (auditLogPath) {
        appendAuditEvent(auditLogPath, {
          request_id: requestId,
          action: "resolve-anchor",
          target: decision.package_name,
          version: decision.safe_anchor?.version,
          commit_sha: decision.safe_anchor?.commit_sha,
          tarball_sha512: decision.safe_anchor?.tarball_sha512,
          verdict: decision.recommended_action,
          policy_sha256,
          evidence_ids: decision.evidence.map((e) => e.evidence_id),
          ...(overrideTicketId ? { override_ticket_id: overrideTicketId } : {}),
        });
      }

      process.stdout.write(asJson ? `${JSON.stringify(decision, null, 2)}\n` : `${formatAnchorMarkdown(decision)}\n`);
      return decision.recommended_action === "USE_PINNED_LATEST" ||
        decision.recommended_action === "ROLLBACK_TO_SAFE_ANCHOR"
        ? 0
        : decision.recommended_action === "BLOCK_NO_SAFE_PATH"
          ? 3
          : 2;
    }

    if (parsed.command === "verify-confusion") {
      const report = await auditDependencyConfusion({
        cwd,
        manifestPath: parsed.positionals[0],
        policy,
        checkPublicClaimability: boolFlag(parsed.flags, "check-public"),
      });
      if (auditLogPath) {
        appendAuditEvent(auditLogPath, {
          request_id: requestId,
          action: "verify-confusion",
          target: report.manifest_path,
          verdict: report.passed ? "PASSED" : "CONFUSION_RISK_FOUND",
          policy_sha256,
          evidence_ids: [],
          ...(overrideTicketId ? { override_ticket_id: overrideTicketId } : {}),
        });
      }
      process.stdout.write(`${JSON.stringify(report, null, 2)}\n`);
      return report.passed ? 0 : 3;
    }

    if (parsed.command === "audit-verify") {
      const target = parsed.positionals[0];
      if (!target) {
        process.stderr.write("Error: audit-verify requires <path-to-audit.jsonl>\n");
        return 1;
      }
      const res = verifyAuditLog(resolve(target));
      process.stdout.write(`${JSON.stringify(res, null, 2)}\n`);
      return res.valid ? 0 : 3;
    }

    process.stderr.write(`Unknown command: ${parsed.command}\n`);
    printHelp();
    return 1;
  } finally {
    cache.close();
  }
}

process.exitCode = await main();
