import { randomUUID } from "node:crypto";
import { existsSync } from "node:fs";
import { join } from "node:path";
import { readCappedRegularFileSync } from "../core/path-confinement.mjs";
             
                 
                    
                 
           
                   
              
                          
               
                      
               
                    
                    
                    
                     
               
               
               
                     
import { ENGINE_VERSION } from "../types.mjs";
import {
  escapeMarkdownCell,
  isSafeNpmBinName,
  isSafeNpmPackageName,
  isSafeNpmVersion,
  LIFECYCLE_HOOKS,
  sanitizeUntrustedText,
} from "../analysis/static-triage.mjs";

export function verdictToExitCode(verdict              )           {
  switch (verdict) {
    case "VERIFIED_CLEAN_WITHIN_SCOPE":
      return 0;
    case "QUARANTINE_SUSPICIOUS":
    case "UNVERIFIABLE_UNKNOWN":
      return 2;
    case "MALICIOUS_INDICATORS_FOUND":
      return 3;
  }
}

export function computeDeterministicVerdict(params   
                       
                       
                       
                               
                                      
                       
                     
                  
                            
 )   
                        
                                        
                                     
  {
  const policy_observations                = [];

  // Policy checks: org allow/deny, license block, CVE/KEV gates
  const orgLower = params.orgOrScope.toLowerCase();
  if (params.policy.denied_orgs.includes(orgLower)) {
    policy_observations.push({
      code: "POLICY_ORG_DENIED",
      severity: "HIGH",
      path: "<policy>",
      detail: `Organization/scope '${params.orgOrScope}' is listed in policy.denied_orgs.`,
    });
  }
  if (params.policy.allowed_orgs.length > 0 && !params.policy.allowed_orgs.includes(orgLower)) {
    policy_observations.push({
      code: "POLICY_ORG_NOT_ALLOWED",
      severity: "HIGH",
      path: "<policy>",
      detail: `Organization/scope '${params.orgOrScope}' is not on policy.allowed_orgs.`,
    });
  }
  if (params.policy.blocked_licenses.some((b) => b.toLowerCase() === params.license.toLowerCase())) {
    policy_observations.push({
      code: "POLICY_LICENSE_BLOCKED",
      severity: "HIGH",
      path: "<policy>",
      detail: `License '${params.license}' is blocked by enterprise policy.`,
    });
  }

  for (const adv of params.advisories) {
    if (adv.is_malicious) {
      policy_observations.push({
        code: "OSV_MALICIOUS_PACKAGE_ADVISORY",
        severity: "CRITICAL",
        path: "<threat-intel>",
        attack_id: "T1195.002",
        detail: `${adv.id}: ${adv.summary}`,
      });
    } else if (params.policy.block_on_kev && adv.kev) {
      policy_observations.push({
        code: "POLICY_CISA_KEV_BLOCK",
        severity: "HIGH",
        path: "<threat-intel>",
        detail: `${adv.id} is listed in CISA KEV: ${adv.summary}`,
      });
    } else if (params.policy.block_on_critical_cve && adv.severity === "CRITICAL") {
      policy_observations.push({
        code: "POLICY_CRITICAL_CVE_BLOCK",
        severity: "HIGH",
        path: "<threat-intel>",
        detail: `${adv.id} (CRITICAL): ${adv.summary}`,
      });
    } else if (params.policy.block_on_high_cve && adv.severity === "HIGH") {
      policy_observations.push({
        code: "POLICY_HIGH_CVE_BLOCK",
        severity: "HIGH",
        path: "<threat-intel>",
        detail: `${adv.id} (HIGH): ${adv.summary}`,
      });
    }
  }

  const allObs                = [
    ...params.unpack.observations,
    ...params.triage.observations,
    ...params.parity.observations,
    ...params.registryObservations,
    ...policy_observations,
  ];

  // 1. MALICIOUS_INDICATORS_FOUND (deterministic hard block)
  const hasCritical = allObs.some((o) => o.severity === "CRITICAL");
  if (hasCritical) {
    return {
      verdict: "MALICIOUS_INDICATORS_FOUND",
      recommended_action: "SWITCH_TO_ALTERNATIVE",
      policy_observations,
    };
  }

  // 2. QUARANTINE_SUSPICIOUS (high risk, obfuscation, lifecycle hooks, cooldown, policy gates)
  const hasSuspicious = allObs.some(
    (o) =>
      o.severity === "HIGH" ||
      o.code === "LIFECYCLE_HOOK_PRESENT" ||
      o.code === "RELEASE_COOLDOWN_QUARANTINE",
  );
  if (hasSuspicious || params.triage.has_obfuscation) {
    return {
      verdict: "QUARANTINE_SUSPICIOUS",
      recommended_action: "BLOCK_NO_SAFE_PATH",
      policy_observations,
    };
  }

  // 3. UNVERIFIABLE_UNKNOWN (incomplete coverage, cap hit, skipped files, corrupt/missing manifest, native/WASM without REA, OSV unavailable, strict policy missing proof)
  const effectiveProvStatus =
    params.parity.provenance_status ?? (params.parity.provenance_attested ? "sigstore_verified" : "none");
  const strictProvenanceGap =
    params.policy.require_provenance &&
    (!params.parity.provenance_attested || effectiveProvStatus !== "sigstore_verified");
  const strictSourceGap = params.policy.require_source_link && params.parity.tier === "SOURCE_UNLINKED";
  const incompleteCoverage =
    params.triage.files_skipped > 0 ||
    params.unpack.unknowns.some((u) => u.startsWith("ARCHIVE_UNSUPPORTED_TYPEFLAG")) ||
    params.triage.unknowns.some(
      (u) =>
        u.startsWith("MANIFEST_MISSING") ||
        u.startsWith("MANIFEST_PARSE_ERROR") ||
        u.startsWith("FILE_SIZE_CAP_SKIPPED"),
    );
  const intelUnavailable = params.offlineUnknowns.some(
    (u) =>
      u.startsWith("OFFLINE_INTEL_SKIPPED") ||
      u.startsWith("OSV_API_UNAVAILABLE") ||
      u.startsWith("OSV_API_ERROR"),
  );
  if (
    !params.unpack.ok ||
    params.unpack.halted_by_cap ||
    params.triage.has_native_or_wasm ||
    incompleteCoverage ||
    strictProvenanceGap ||
    strictSourceGap ||
    intelUnavailable
  ) {
    return {
      verdict: "UNVERIFIABLE_UNKNOWN",
      recommended_action: "BLOCK_NO_SAFE_PATH",
      policy_observations,
    };
  }

  // 4. VERIFIED_CLEAN_WITHIN_SCOPE
  return {
    verdict: "VERIFIED_CLEAN_WITHIN_SCOPE",
    recommended_action: "USE_PINNED_LATEST",
    policy_observations,
  };
}

export function buildPinnedExecution(params   
                       
                  
                      
                         
                        
 )                      {
  const bin = params.bin_names[0] ?? (params.package_name.includes("/") ? params.package_name.slice(params.package_name.indexOf("/") + 1) : params.package_name);
  if (params.verdict !== "VERIFIED_CLEAN_WITHIN_SCOPE") {
    return {
      command: null,
      exact_version: params.version,
      tarball_sha512: params.tarball_sha512,
      bin_name: bin,
      caveat: `Execution command suppressed because verdict is ${params.verdict}.`,
    };
  }
  if (!isSafeNpmPackageName(params.package_name) || !isSafeNpmVersion(params.version) || !isSafeNpmBinName(bin)) {
    return {
      command: null,
      exact_version: sanitizeUntrustedText(params.version, 64),
      tarball_sha512: params.tarball_sha512,
      bin_name: sanitizeUntrustedText(bin, 64),
      caveat: "Execution command suppressed because package name, version, or bin key contains shell-unsafe characters.",
    };
  }
  return {
    command: `npx --yes --ignore-scripts --package=${params.package_name}@${params.version} -- ${bin}`,
    exact_version: params.version,
    tarball_sha512: params.tarball_sha512,
    bin_name: bin,
    caveat:
      "Stock npx pins top-level version and disables install scripts, but cannot enforce SHA-512 integrity or transitive lockfiles at runtime. Verify dist.integrity and isolate transitives for regulated builds.",
  };
}

const CONTAINMENT_STEPS = [
  "1. Disconnect affected host/runner from production networks if package was installed without --ignore-scripts.",
  "2. Immediately rotate exposed tokens: ~/.npmrc, GitHub PATs, SSH keys, AWS/GCP/Azure credentials, and .env secrets.",
  "3. Preserve shell history, npm cache, and process/DNS logs before wiping node_modules (chain of custody).",
  "4. Notify Security/SOC immediately (evaluate India CERT-In 6h / EU NIS2 24h / CRA 24h / GDPR 72h reporting clocks).",
];

function escapeRegExp(s        )         {
  return s.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
}

function matchPnpmLock(content        , packageName        )                {
  // Matches pnpm lockfile v6/v9 entries like: "  /bad-cli@1.2.3:" or "  '@org/bad@1.2.3':" or "  bad-cli@1.2.3:"
  const esc = escapeRegExp(packageName);
  const re = new RegExp(`(?:^|\\n)\\s*['"]?/?${esc}@([0-9][^\\s:'"()]+)`, "m");
  const m = re.exec(content);
  return m?.[1] ?? null;
}

function matchYarnLock(content        , packageName        )                {
  // Matches Yarn classic & Berry blocks (including @npm: protocol and comma-separated multi-specifier headers):
  //   "@org/bad@^1.0.0": / "@org/bad@npm:^1.0.0": / "foo@^1.0.0", "@org/bad@npm:^1.0.0":
  const esc = escapeRegExp(packageName);
  const headerRe = new RegExp(`(?:^|\\n)[^\\n]*(?:^|[\\s,'"])${esc}@(?:npm:)?[^\\n]+:(?:\\r?\\n)([\\s\\S]{0,320})`, "m");
  const m = headerRe.exec(content);
  if (!m?.[1]) return null;
  const verMatch = /^\s+version[:\s]+['"]?([^\s'"]+)/m.exec(m[1]);
  return verMatch?.[1] ?? null;
}

export function checkLocalWorkspaceCompromised(
  cwd        ,
  packageName        ,
  verdict              ,
)                                                                     {
  if (verdict !== "MALICIOUS_INDICATORS_FOUND") return undefined;

  const MAX_LOCKFILE_BYTES = 25 * 1024 * 1024;

  // 1. npm package-lock.json (lockfileVersion 1, 2, 3 — top-level AND nested node_modules)
  const npmLockPath = join(cwd, "package-lock.json");
  if (existsSync(npmLockPath)) {
    try {
      const raw = JSON.parse(readCappedRegularFileSync(npmLockPath, MAX_LOCKFILE_BYTES).toString("utf8"))     
                                                        
                                                                                                                 
       ;
      const directKey = `node_modules/${packageName}`;
      const nestedSuffix = `/node_modules/${packageName}`;
      let matchedVer = raw.packages?.[directKey]?.version ?? raw.dependencies?.[packageName]?.version;
      if (!matchedVer && raw.packages) {
        for (const [k, entry] of Object.entries(raw.packages)) {
          if ((k === directKey || k.endsWith(nestedSuffix)) && entry?.version) {
            matchedVer = entry.version;
            break;
          }
        }
      }
      if (!matchedVer && raw.dependencies) {
        for (const dep of Object.values(raw.dependencies)) {
          const nested = dep?.dependencies?.[packageName]?.version;
          if (nested) {
            matchedVer = nested;
            break;
          }
        }
      }
      if (matchedVer) {
        return {
          lockfile_path: npmLockPath,
          lockfile_kind: "package-lock.json",
          matched_version: matchedVer,
          containment_steps: [...CONTAINMENT_STEPS],
        };
      }
    } catch {
      // Continue checking other lockfile ecosystems
    }
  }

  // 2. pnpm-lock.yaml
  const pnpmLockPath = join(cwd, "pnpm-lock.yaml");
  if (existsSync(pnpmLockPath)) {
    try {
      const matchedVer = matchPnpmLock(readCappedRegularFileSync(pnpmLockPath, MAX_LOCKFILE_BYTES).toString("utf8"), packageName);
      if (matchedVer) {
        return {
          lockfile_path: pnpmLockPath,
          lockfile_kind: "pnpm-lock.yaml",
          matched_version: matchedVer,
          containment_steps: [...CONTAINMENT_STEPS],
        };
      }
    } catch {
      // Ignore unreadable or oversized lockfile
    }
  }

  // 3. yarn.lock
  const yarnLockPath = join(cwd, "yarn.lock");
  if (existsSync(yarnLockPath)) {
    try {
      const matchedVer = matchYarnLock(readCappedRegularFileSync(yarnLockPath, MAX_LOCKFILE_BYTES).toString("utf8"), packageName);
      if (matchedVer) {
        return {
          lockfile_path: yarnLockPath,
          lockfile_kind: "yarn.lock",
          matched_version: matchedVer,
          containment_steps: [...CONTAINMENT_STEPS],
        };
      }
    } catch {
      // Ignore unreadable lockfile
    }
  }

  return undefined;
}

export function buildReaEscalationPlan(params   
                       
                       
                                      
 )                                {
  const steps                      = [];
  const seen = new Set        ();

  for (const obs of params.triage.observations) {
    if (obs.code === "NATIVE_OR_WASM_ARTIFACT") {
      const isWasm = obs.path.toLowerCase().endsWith(".wasm") || obs.detail.includes("WebAssembly");
      const tool = isWasm
        ? "inspect_wasm_artifact"
        : "open_binary -> inspect_artifact / inspect_binary_layout -> close_binary";
      const key = `${obs.path}|${tool}`;
      if (!seen.has(key)) {
        seen.add(key);
        steps.push({
          path: obs.path,
          signal: obs.code,
          recommended_tool: tool,
          rationale: obs.detail,
        });
      }
    } else if (obs.code === "HIGH_ENTROPY_OBFUSCATION" || obs.code === "OBFUSCATED_DYNAMIC_EXEC") {
      const tool = "analyze_javascript_application (detail='summary') / recover_javascript_sources";
      const key = `${obs.path}|${tool}`;
      if (!seen.has(key)) {
        seen.add(key);
        steps.push({
          path: obs.path,
          signal: obs.code,
          recommended_tool: tool,
          rationale: obs.detail,
        });
      }
    }
  }

  if (params.parity.tier === "TARBALL_SOURCE_DRIFT") {
    steps.push({
      path: "<tarball vs gitHead>",
      signal: "TARBALL_SOURCE_DRIFT",
      recommended_tool: "compare_application_versions",
      rationale: "Published tarball diverges from Git source commit; compare structurally across versions via REA.",
    });
  }

  if (steps.length === 0) return undefined;
  return {
    required: true,
    rea_available_on_host: params.host_capabilities.rea_cli_available,
    bootstrap_prohibition:
      "Never run 'npx -y rea-agents' to bootstrap REA; invoke REA only through a pre-registered MCP server or pre-installed binary.",
    steps,
  };
}

export function assembleInspectionReport(params   
                       
                  
                       
                  
                          
                  
                  
                        
                            
                      
                       
                       
                       
                               
                                      
                             
                       
                                      
              
                               
 )                          {
  const verdictRes = computeDeterministicVerdict({
    unpack: params.unpack,
    triage: params.triage,
    parity: params.parity,
    advisories: params.advisories,
    registryObservations: params.registryObservations,
    policy: params.policy,
    orgOrScope: params.org_or_scope,
    license: params.license,
    offlineUnknowns: params.registryUnknowns,
  });

  const evidence                   = [
    {
      evidence_id: `ev_t0_${params.unpack.tarball_sha512.slice(7, 19)}`,
      source: "tier0_intel",
      artifact_sha512: params.unpack.tarball_sha512,
      observations: [...params.registryObservations, ...verdictRes.policy_observations],
      inferences: [],
      unknowns: params.registryUnknowns,
      coverage: {
        files_inspected: 0,
        files_skipped: 0,
        rea_invoked: false,
        transitive_checked: params.transitive_checked ?? false,
      },
    },
    {
      evidence_id: `ev_t1_unpack_${params.unpack.tarball_sha512.slice(7, 19)}`,
      source: "tier1_unpack",
      artifact_sha512: params.unpack.tarball_sha512,
      observations: params.unpack.observations,
      inferences: [],
      unknowns: params.unpack.unknowns,
      coverage: {
        files_inspected: params.unpack.entries.length,
        files_skipped: 0,
        rea_invoked: false,
        transitive_checked: false,
      },
    },
    {
      evidence_id: `ev_t1_static_${params.triage.ruleset_sha256.slice(0, 12)}`,
      source: "tier1_static",
      artifact_sha512: params.unpack.tarball_sha512,
      observations: params.triage.observations,
      inferences: params.triage.inferences,
      unknowns: params.triage.unknowns,
      coverage: {
        files_inspected: params.triage.files_inspected,
        files_skipped: params.triage.files_skipped,
        rea_invoked: false,
        transitive_checked: false,
      },
    },
    {
      evidence_id: `ev_t1_parity_${(params.parity.git_head ?? "unlinked").slice(0, 12)}`,
      source: "tier1_parity",
      artifact_sha512: params.unpack.tarball_sha512,
      commit_sha: params.parity.git_head,
      observations: params.parity.observations,
      inferences: [],
      unknowns: params.parity.unknowns,
      coverage: {
        files_inspected: params.unpack.entries.length,
        files_skipped: 0,
        rea_invoked: false,
        transitive_checked: false,
      },
    },
  ];

  const lifecycleScripts = Object.keys(params.triage.manifest?.scripts ?? {}).filter((k) =>
    LIFECYCLE_HOOKS.has(k.toLowerCase()),
  );

  const pinned_execution = buildPinnedExecution({
    package_name: params.package_name,
    version: params.version,
    bin_names: params.bin_names,
    tarball_sha512: params.unpack.tarball_sha512,
    verdict: verdictRes.verdict,
  });

  const local_workspace_compromised = checkLocalWorkspaceCompromised(
    params.cwd,
    params.package_name,
    verdictRes.verdict,
  );

  const rea_escalation_plan = buildReaEscalationPlan({
    triage: params.triage,
    parity: params.parity,
    host_capabilities: params.host_capabilities,
  });

  const effectiveProvenanceStatus =
    params.parity.provenance_status ?? (params.parity.provenance_attested ? "sigstore_verified" : "none");

  return {
    schema_version: "1",
    generated_at_utc: new Date().toISOString(),
    title: {
      package_name: params.package_name,
      version: params.version,
      org_or_scope: params.org_or_scope,
      creator: sanitizeUntrustedText(params.creator, 80),
      category_tags: params.category_tags.map((c) => sanitizeUntrustedText(c, 40)),
      commit_sha: params.parity.git_head,
    },
    info: {
      summary: sanitizeUntrustedText(params.summary, 200),
      license: sanitizeUntrustedText(params.license, 60),
      published_at: params.published_at,
      weekly_downloads: params.weekly_downloads,
      has_bin: params.bin_names.length > 0,
      bin_names: params.bin_names,
      lifecycle_scripts: lifecycleScripts,
      direct_dependency_count: Object.keys(params.triage.manifest?.dependencies ?? {}).length,
      parity_tier: params.parity.tier,
      provenance_attested: params.parity.provenance_attested && effectiveProvenanceStatus === "sigstore_verified",
      provenance_status: effectiveProvenanceStatus,
      ...(params.parity.provenance_url ? { provenance_url: params.parity.provenance_url } : {}),
    },
    verdict: verdictRes.verdict,
    recommended_action: verdictRes.recommended_action,
    pinned_execution,
    advisories: params.advisories,
    evidence,
    iocs: params.triage.iocs,
    ...(rea_escalation_plan ? { rea_escalation_plan } : {}),
    local_workspace_compromised,
    host_capabilities: params.host_capabilities,
  };
}

export function formatInspectionMarkdownCard(report                         )         {
  const allObs = report.evidence.flatMap((e) => e.observations);
  const allInf = report.evidence.flatMap((e) => e.inferences);
  const allUnk = report.evidence.flatMap((e) => e.unknowns);

  const lines           = [
    `# Title: \`${escapeMarkdownCell(report.title.package_name, 100)}@${escapeMarkdownCell(report.title.version, 48)}\``,
    "",
    `- **Verdict:** \`${report.verdict}\``,
    `- **Recommended Action:** \`${report.recommended_action}\``,
    `- **Org / Scope:** \`${escapeMarkdownCell(report.title.org_or_scope, 64)}\` | **Creator:** ${escapeMarkdownCell(report.title.creator, 80)}`,
    `- **Category Tags:** ${report.title.category_tags.length ? report.title.category_tags.map((t) => `\`${escapeMarkdownCell(t, 40)}\``).join(", ") : "none"}`,
    `- **Commit SHA:** ${report.title.commit_sha ? `\`${escapeMarkdownCell(report.title.commit_sha, 48)}\`` : "`unlinked`"}`,
    "",
    "## Info",
    `- **Summary:** ${sanitizeUntrustedText(report.info.summary, 200) || "(no description)"}`,
    `- **License:** \`${escapeMarkdownCell(report.info.license, 60)}\` | **Direct Dependencies:** ${report.info.direct_dependency_count}`,
    `- **Binaries:** ${report.info.bin_names.length ? report.info.bin_names.map((b) => `\`${escapeMarkdownCell(b, 64)}\``).join(", ") : "none"} | **Lifecycle Hooks:** ${report.info.lifecycle_scripts.length ? report.info.lifecycle_scripts.map((s) => `\`${escapeMarkdownCell(s, 32)}\``).join(", ") : "none"}`,
    `- **Tarball Parity Tier:** \`${report.info.parity_tier}\` | **npm Provenance:** \`${report.info.provenance_status}\` (sigstore_verified=\`${report.info.provenance_attested}\`)`,
    `- **Verified SHA-512:** \`${report.pinned_execution.tarball_sha512 ?? "unavailable"}\``,
    "",
    "## Safe Execution Command",
    report.pinned_execution.command
      ? `\`\`\`bash\n${report.pinned_execution.command}\n\`\`\``
      : "_Blocked — no runnable command emitted._",
    `> Caveat: ${report.pinned_execution.caveat}`,
    "",
    "## Evidence Summary",
    `- **Evidence IDs:** ${report.evidence.map((e) => `\`${e.evidence_id}\``).join(", ")}`,
  ];

  if (allObs.length > 0) {
    lines.push("", "### Observations", "| Severity | Code | Location | Framework | Detail |", "|---|---|---|---|---|");
    for (const o of allObs) {
      const fw = [o.attack_id, o.atlas_id].filter(Boolean).join(" / ") || "-";
      const loc = o.line ? `${o.path}:${o.line}` : o.path;
      lines.push(`| \`${o.severity}\` | \`${o.code}\` | \`${escapeMarkdownCell(loc, 90)}\` | \`${fw}\` | ${escapeMarkdownCell(o.detail, 160)} |`);
    }
  } else {
    lines.push("- **Observations:** No malicious or suspicious static indicators observed within inspected scope.");
  }

  if (allInf.length > 0) {
    lines.push("", "### Inferences");
    for (const inf of allInf) lines.push(`- ${sanitizeUntrustedText(inf, 240)}`);
  }

  if (allUnk.length > 0) {
    lines.push("", "### Unknowns & Coverage Bounds");
    for (const unk of allUnk) lines.push(`- ${sanitizeUntrustedText(unk, 240)}`);
  }

  if (report.rea_escalation_plan) {
    lines.push(
      "",
      "### REA Tier-2 Escalation Plan",
      `- **REA Available on Host:** \`${report.rea_escalation_plan.rea_available_on_host}\``,
      `- **Policy:** ${report.rea_escalation_plan.bootstrap_prohibition}`,
      "| Artifact | Signal | Recommended REA Tool | Rationale |",
      "|---|---|---|---|",
    );
    for (const step of report.rea_escalation_plan.steps) {
      lines.push(
        `| \`${escapeMarkdownCell(step.path, 80)}\` | \`${step.signal}\` | \`${step.recommended_tool}\` | ${escapeMarkdownCell(step.rationale, 140)} |`,
      );
    }
  }

  if (report.iocs.length > 0) {
    lines.push("", "### Defanged IOCs", "| Kind | Value | TLP | Confidence | Source |", "|---|---|---|---|---|");
    for (const ioc of report.iocs.slice(0, 20)) {
      lines.push(
        `| \`${ioc.kind}\` | \`${escapeMarkdownCell(ioc.value, 120)}\` | \`${ioc.tlp}\` | \`${ioc.confidence}\` | \`${escapeMarkdownCell(ioc.source_path, 90)}\` |`,
      );
    }
  }

  if (report.local_workspace_compromised) {
    lines.push(
      "",
      "## URGENT: Local Workspace Compromise Match",
      `Detected \`${report.title.package_name}@${report.local_workspace_compromised.matched_version}\` inside \`${report.local_workspace_compromised.lockfile_path}\`.`,
      ...report.local_workspace_compromised.containment_steps.map((s) => `- ${s}`),
    );
  }

  return lines.join("\n");
}

export function formatDiscoveryMarkdown(list                   )         {
  const lines           = [
    `# npx Discovery Directory: \`${list.query || "*"}\``,
    `- **Registry Route:** \`${list.registry_route}\` | **Filters:** org=\`${list.filters.org ?? "*"}\`, creator=\`${list.filters.creator ?? "*"}\`, category=\`${list.filters.category ?? "*"}\``,
    "",
  ];
  if (list.candidates.length > 0) {
    lines.push("| Title (`pkg@ver`) | Org / Creator | License | Preview Verdict | Info |");
    lines.push("|---|---|---|---|---|");
    for (const c of list.candidates) {
      lines.push(
        `| \`${escapeMarkdownCell(c.package_name, 80)}@${escapeMarkdownCell(c.version, 32)}\` | \`${escapeMarkdownCell(c.org_or_scope, 40)}\` / ${escapeMarkdownCell(c.creator, 40)} | \`${escapeMarkdownCell(c.license, 30)}\` | \`${c.verdict_preview}\` | ${escapeMarkdownCell(c.summary, 160)} |`,
      );
    }
  } else {
    lines.push("_No matching candidates passed policy filters._");
  }
  if (list.blocked_candidates.length > 0) {
    lines.push("", "### Policy-Blocked Candidates");
    for (const b of list.blocked_candidates) {
      lines.push(`- \`${escapeMarkdownCell(b.package_name, 80)}\`: ${sanitizeUntrustedText(b.reason, 200)}`);
    }
  }
  if (list.unknowns.length > 0) {
    lines.push("", "### Unknowns");
    for (const u of list.unknowns) lines.push(`- ${sanitizeUntrustedText(u, 240)}`);
  }
  return lines.join("\n");
}

export function formatAnchorMarkdown(decision                    )         {
  const lines           = [
    `# Safe Anchor Resolution: \`${escapeMarkdownCell(decision.package_name, 100)}\``,
    `- **Recommended Action:** \`${decision.recommended_action}\``,
    `- **Compromised Latest:** ${sanitizeUntrustedText(decision.compromised_latest.reason, 220)}`,
    `- **Patient-Zero Commit SHA:** ${decision.compromised_latest.patient_zero_sha ? `\`${decision.compromised_latest.patient_zero_sha}\`` : "`unknown`"}`,
  ];
  if (decision.safe_anchor) {
    const anchorProvStatus =
      decision.safe_anchor.provenance_status ?? (decision.safe_anchor.provenance_attested ? "sigstore_verified" : "none");
    lines.push(
      "",
      "## Safe Anchor Candidate",
      `- **Commit SHA:** ${decision.safe_anchor.commit_sha ? `\`${decision.safe_anchor.commit_sha}\`` : "`none`"}`,
      `- **Mapped npm Version:** ${decision.safe_anchor.version ? `\`${escapeMarkdownCell(decision.safe_anchor.version, 48)}\`` : "`none`"}`,
      `- **Verified SHA-512:** ${decision.safe_anchor.tarball_sha512 ? `\`${decision.safe_anchor.tarball_sha512}\`` : "`none`"}`,
      `- **npm Provenance:** \`${anchorProvStatus}\` (sigstore_verified=\`${decision.safe_anchor.provenance_attested}\`)`,
      `- **Residual Advisories:** ${decision.safe_anchor.residual_advisories.length}`,
      decision.safe_anchor.pinned_execution.command
        ? `\`\`\`bash\n${decision.safe_anchor.pinned_execution.command}\n\`\`\``
        : `> ${decision.safe_anchor.pinned_execution.caveat}`,
    );
  }
  if (decision.alternatives.length > 0) {
    lines.push("", "## Vetted Alternatives");
    for (const alt of decision.alternatives) {
      lines.push(
        `- \`${escapeMarkdownCell(alt.package_name, 80)}@${escapeMarkdownCell(alt.version, 32)}\` (\`${alt.verdict}\`) — ${sanitizeUntrustedText(alt.reason, 180)}`,
      );
    }
  }
  if (decision.inspected_commits.length > 0) {
    lines.push("", "## Commit History Walk", "| Commit | Date | Verdict | Changed | Cache Hits | Findings | Subject |", "|---|---|---|---|---|---|---|");
    for (const c of decision.inspected_commits.slice(0, 15)) {
      lines.push(
        `| \`${c.commit_sha.slice(0, 10)}\` | ${c.committed_at_utc.slice(0, 10)} | \`${c.verdict}\` | ${c.changed_blobs} | ${c.cache_hits} | ${c.observations_count} | ${escapeMarkdownCell(c.subject, 100)} |`,
      );
    }
  }
  if (decision.unknowns.length > 0) {
    lines.push("", "## Unknowns");
    for (const u of decision.unknowns) lines.push(`- ${sanitizeUntrustedText(u, 240)}`);
  }
  return lines.join("\n");
}

/**
 * Valid SARIF 2.1.0 output for GitHub Code Scanning / enterprise CI dashboards.
 */
export function formatSarif210(report                         )                          {
  const allObs = report.evidence.flatMap((e) => e.observations);
  const rulesMap = new Map                                                                                                               ();

  for (const o of allObs) {
    if (!rulesMap.has(o.code)) {
      rulesMap.set(o.code, {
        id: o.code,
        name: o.code,
        shortDescription: { text: o.code.replaceAll("_", " ") },
        properties: {
          tags: [o.attack_id, o.atlas_id].filter(Boolean),
        },
      });
    }
  }

  const levelFor = (sev                         )                               => {
    if (sev === "CRITICAL" || sev === "HIGH") return "error";
    if (sev === "MEDIUM") return "warning";
    return "note";
  };

  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [
      {
        tool: {
          driver: {
            name: "coldpin",
            version: ENGINE_VERSION,
            informationUri: "https://github.com/hynko431/Coldpin-npx-Safe-Finder",
            rules: Array.from(rulesMap.values()),
          },
        },
        results: allObs.map((o) => ({
          ruleId: o.code,
          level: levelFor(o.severity),
          message: { text: o.detail },
          locations: [
            {
              physicalLocation: {
                artifactLocation: { uri: o.path },
                ...(o.line ? { region: { startLine: o.line } } : {}),
              },
            },
          ],
          properties: {
            severity: o.severity,
            verdict: report.verdict,
            attack_id: o.attack_id,
            atlas_id: o.atlas_id,
          },
        })),
      },
    ],
  };
}

/**
 * CycloneDX 1.5 SBOM + VEX JSON emitter for EU CRA / NIST SSDF / SOC 2 supply-chain evidence.
 */
export function formatCycloneDxSbom(
  report                         ,
  directDependencies                         ,
)                          {
  const encodePurlName = (name        ) =>
    name.startsWith("@") ? `%40${encodeURIComponent(name.slice(1)).replace(/%2F/gi, "/")}` : encodeURIComponent(name);
  const purl = `pkg:npm/${encodePurlName(report.title.package_name)}@${encodeURIComponent(report.title.version)}`;
  const sha512Hex = report.pinned_execution.tarball_sha512?.startsWith("sha512-")
    ? Buffer.from(report.pinned_execution.tarball_sha512.slice("sha512-".length), "base64").toString("hex")
    : undefined;

  const rootComponent = {
    type: "library",
    "bom-ref": purl,
    name: report.title.package_name,
    version: report.title.version,
    purl,
    licenses: report.info.license !== "UNKNOWN" ? [{ license: { id: report.info.license } }] : [],
    hashes: sha512Hex ? [{ alg: "SHA-512", content: sha512Hex }] : [],
    properties: [
      { name: "coldpin:verdict", value: report.verdict },
      { name: "coldpin:parity-tier", value: report.info.parity_tier },
      { name: "coldpin:provenance-attested", value: String(report.info.provenance_attested) },
      { name: "coldpin:provenance-status", value: report.info.provenance_status },
      ...(report.title.commit_sha ? [{ name: "coldpin:commit-sha", value: report.title.commit_sha }] : []),
    ],
  };

  const depEntries = Object.entries(directDependencies ?? {});
  const depRefByName = new Map                ();
  const depComponents = depEntries.map(([depName, depRange]) => {
    const depRef = `pkg:npm/${encodePurlName(depName)}@${encodeURIComponent(depRange)}`;
    depRefByName.set(depName, depRef);
    return {
      type: "library",
      "bom-ref": depRef,
      name: depName,
      version: depRange,
      purl: depRef,
    };
  });

  const vulnerabilities = report.advisories.map((adv) => {
    const affectedRef =
      adv.package_name === report.title.package_name
        ? purl
        : (depRefByName.get(adv.package_name) ?? purl);
    return {
      id: adv.id,
      source: { name: adv.is_malicious ? "OpenSSF Malicious Packages" : "OSV", url: "https://api.osv.dev" },
      description: adv.summary,
      ratings: [
        {
          severity: adv.severity.toLowerCase(),
          method: adv.is_malicious ? "other" : "CVSSv31",
        },
      ],
      analysis: {
        state: adv.is_malicious || adv.kev ? "exploitable" : "in_triage",
        detail: adv.is_malicious
          ? "OpenSSF MAL-* malicious package advisory matched inspected package."
          : adv.kev
            ? "Listed in CISA Known Exploited Vulnerabilities (KEV)."
            : "Matched OSV advisory; review impact against policy.",
      },
      affects: [{ ref: affectedRef }],
    };
  });

  return {
    bomFormat: "CycloneDX",
    specVersion: "1.5",
    serialNumber: `urn:uuid:${randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: report.generated_at_utc,
      tools: [{ vendor: "coldpin", name: "coldpin", version: ENGINE_VERSION }],
      component: rootComponent,
    },
    components: [rootComponent, ...depComponents],
    dependencies: [
      {
        ref: purl,
        dependsOn: depComponents.map((d) => d["bom-ref"]),
      },
    ],
    ...(vulnerabilities.length > 0 ? { vulnerabilities } : {}),
  };
}


//# sourceURL=verdict/engine-and-formatters.ts
