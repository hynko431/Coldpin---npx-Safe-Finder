#!/usr/bin/env node

function checkNodeVersionFloor(): void {
  const major = Number.parseInt(process.versions.node.split(".")[0] ?? "0", 10);
  if (!Number.isFinite(major) || major < 24) {
    process.stderr.write(
      `Coldpin requires Node.js >= 24.0.0; detected ${process.version}. Upgrade to Node 24+ LTS.\n`,
    );
    process.exit(1);
  }
}

checkNodeVersionFloor();

const { startMcpServerFromEnv } = await import("./mcp/server.ts");
process.exitCode = await startMcpServerFromEnv();
