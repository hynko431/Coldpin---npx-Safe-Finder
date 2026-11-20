import { createHash } from "node:crypto";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, statSync, unlinkSync } from "node:fs";
import { appendFile, mkdir, open, stat, unlink } from "node:fs/promises";
import { userInfo } from "node:os";
import { dirname } from "node:path";
import { openReadCappedFile, readCappedRegularFileSync } from "../core/path-confinement.ts";
import type { AuditEvent } from "../types.ts";

const GENESIS_HASH = "0".repeat(64);
const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 25;
const LOCK_MAX_ATTEMPTS = 80;
export const MAX_AUDIT_LOG_BYTES = 20 * 1024 * 1024;

const SLEEP_ARRAY = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms: number): void {
  Atomics.wait(SLEEP_ARRAY, 0, 0, ms);
}

function sleepAsync(ms: number): Promise<void> {
  return new Promise((r) => setTimeout(r, ms));
}

function withAuditFileLock<T>(auditLogPath: string, fn: () => T): T {
  const lockPath = `${auditLogPath}.lock`;
  mkdirSync(dirname(auditLogPath), { recursive: true });

  let fd: number | null = null;
  for (let attempt = 0; attempt < LOCK_MAX_ATTEMPTS; attempt++) {
    try {
      fd = openSync(lockPath, "wx");
      break;
    } catch (err) {
      const code = (err as { code?: string }).code;
      if (code !== "EEXIST") throw err;
      try {
        const st = statSync(lockPath);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          unlinkSync(lockPath);
          continue;
        }
      } catch {
        continue;
      }
      sleepSync(LOCK_WAIT_MS);
    }
  }

  if (fd === null) {
    throw new Error(`Timed out acquiring audit log lock at ${lockPath}`);
  }

  try {
    return fn();
  } finally {
    try {
      closeSync(fd);
    } catch {
      // Ignore close error on cleanup
    }
    try {
      unlinkSync(lockPath);
    } catch {
      // Ignore unlink error on cleanup
    }
  }
}

async function withAuditFileLockAsync<T>(auditLogPath: string, fn: () => Promise<T>): Promise<T> {
  const lockPath = `${auditLogPath}.lock`;
  await mkdir(dirname(auditLogPath), { recursive: true });

  let fh: Awaited<ReturnType<typeof open>> | null = null;
  for (let attempt = 0; attempt < LOCK_MAX_ATTEMPTS; attempt++) {
    try {
      fh = await open(lockPath, "wx");
      break;
    } catch (err) {
      const code = (err as { code?: string }).code;
      if (code !== "EEXIST") throw err;
      try {
        const st = await stat(lockPath);
        if (Date.now() - st.mtimeMs > LOCK_STALE_MS) {
          await unlink(lockPath);
          continue;
        }
      } catch {
        continue;
      }
      const jitter = Math.floor(Math.random() * 15);
      await sleepAsync(LOCK_WAIT_MS + jitter);
    }
  }

  if (fh === null) {
    throw new Error(`Timed out acquiring audit log lock at ${lockPath}`);
  }

  try {
    return await fn();
  } finally {
    try {
      await fh.close();
    } catch {
      // Ignore close error on cleanup
    }
    try {
      await unlink(lockPath);
    } catch {
      // Ignore unlink error on cleanup
    }
  }
}

/**
 * Structured operational JSON telemetry formatter — strictly separate from the
 * hash-chained audit trail (`audit.jsonl`). Never logs secrets, tokens, or PII.
 * Pure-core invariant: never writes directly to `process.stdout` or `process.stderr`;
 * callers inject a `writer` (CLI/MCP pass stderr).
 */
export function logOperationalEvent(
  verbose: boolean,
  event: Record<string, unknown>,
  writer?: (line: string) => void,
): string | null {
  if (!verbose) return null;
  const line = `${JSON.stringify({
    ts_utc: new Date().toISOString(),
    stream: "operational",
    ...event,
  })}\n`;
  if (writer) writer(line);
  return line;
}

const ALLOWED_AUDIT_KEYS = new Set([
  "seq",
  "ts_utc",
  "request_id",
  "invoker_surface",
  "mcp_client_name",
  "tool_name",
  "actor_id_hash",
  "action",
  "target",
  "version",
  "commit_sha",
  "tarball_sha512",
  "verdict",
  "policy_sha256",
  "evidence_ids",
  "override_ticket_id",
  "prev_hash",
  "entry_hash",
]);

function canonicalAuditPayload(ev: Omit<AuditEvent, "entry_hash">): string {
  const ordered: Record<string, unknown> = {
    seq: ev.seq,
    ts_utc: ev.ts_utc,
    ...(ev.request_id !== undefined ? { request_id: ev.request_id } : {}),
    ...(ev.invoker_surface !== undefined ? { invoker_surface: ev.invoker_surface } : {}),
    ...(ev.mcp_client_name !== undefined ? { mcp_client_name: ev.mcp_client_name } : {}),
    ...(ev.tool_name !== undefined ? { tool_name: ev.tool_name } : {}),
    actor_id_hash: ev.actor_id_hash,
    action: ev.action,
    target: ev.target,
    version: ev.version ?? null,
    commit_sha: ev.commit_sha ?? null,
    tarball_sha512: ev.tarball_sha512 ?? null,
    verdict: ev.verdict,
    policy_sha256: ev.policy_sha256,
    evidence_ids: [...ev.evidence_ids].sort(),
    ...(ev.override_ticket_id !== undefined ? { override_ticket_id: ev.override_ticket_id } : {}),
    prev_hash: ev.prev_hash,
  };
  return JSON.stringify(ordered);
}

export function computePseudonymousActorId(salt = "coldpin-local-v1"): string {
  let username = "unknown";
  try {
    username = userInfo().username;
  } catch {
    username = process.env["USER"] ?? process.env["USERNAME"] ?? "unknown";
  }
  return `actor_${createHash("sha256").update(`${salt}:${username}`).digest("hex").slice(0, 16)}`;
}

function buildChainedAuditEntry(
  rawExisting: string | null,
  auditLogPath: string,
  params: Omit<AuditEvent, "seq" | "ts_utc" | "actor_id_hash" | "prev_hash" | "entry_hash">,
): AuditEvent {
  let prevHash = GENESIS_HASH;
  let nextSeq = 1;

  if (rawExisting !== null) {
    const lines = rawExisting
      .split(/\r?\n/)
      .filter((l) => l.trim().length > 0);
    if (lines.length > 0) {
      let last: AuditEvent;
      try {
        last = JSON.parse(lines[lines.length - 1]!) as AuditEvent;
      } catch {
        throw new Error(`Corrupted final JSONL line in audit log ${auditLogPath}; refusing to chain.`);
      }
      if (typeof last.seq !== "number" || typeof last.entry_hash !== "string" || !/^[0-9a-f]{64}$/.test(last.entry_hash)) {
        throw new Error(`Invalid final audit entry fields in ${auditLogPath}; refusing to chain.`);
      }
      prevHash = last.entry_hash;
      nextSeq = last.seq + 1;
    }
  }

  const base: Omit<AuditEvent, "entry_hash"> = {
    seq: nextSeq,
    ts_utc: new Date().toISOString(),
    actor_id_hash: computePseudonymousActorId(),
    ...params,
    prev_hash: prevHash,
  };
  const entry_hash = createHash("sha256")
    .update(`${prevHash}|${canonicalAuditPayload(base)}`)
    .digest("hex");

  return { ...base, entry_hash };
}

/**
 * Local append-only hash-chained audit trail (`audit.jsonl`) with atomic lockfile
 * serialization so concurrent invocations cannot fork or corrupt the chain.
 */
export function appendAuditEvent(
  auditLogPath: string,
  params: Omit<AuditEvent, "seq" | "ts_utc" | "actor_id_hash" | "prev_hash" | "entry_hash">,
): AuditEvent {
  return withAuditFileLock(auditLogPath, () => {
    const rawExisting = existsSync(auditLogPath)
      ? readCappedRegularFileSync(auditLogPath, MAX_AUDIT_LOG_BYTES).toString("utf8")
      : null;
    const full = buildChainedAuditEntry(rawExisting, auditLogPath, params);
    appendFileSync(auditLogPath, `${JSON.stringify(full)}\n`, "utf8");
    return full;
  });
}

export async function appendAuditEventAsync(
  auditLogPath: string,
  params: Omit<AuditEvent, "seq" | "ts_utc" | "actor_id_hash" | "prev_hash" | "entry_hash">,
): Promise<AuditEvent> {
  return withAuditFileLockAsync(auditLogPath, async () => {
    let rawExisting: string | null = null;
    if (existsSync(auditLogPath)) {
      const buf = await openReadCappedFile(auditLogPath, MAX_AUDIT_LOG_BYTES);
      rawExisting = buf.toString("utf8");
    }
    const full = buildChainedAuditEntry(rawExisting, auditLogPath, params);
    await appendFile(auditLogPath, `${JSON.stringify(full)}\n`, "utf8");
    return full;
  });
}

export function verifyAuditLogContent(rawContent: string): {
  valid: boolean;
  total_events: number;
  broken_at_seq?: number;
  reason?: string;
} {
  const lines = rawContent
    .split(/\r?\n/)
    .filter((l) => l.trim().length > 0);

  let expectedPrev = GENESIS_HASH;
  for (let i = 0; i < lines.length; i++) {
    let ev: AuditEvent;
    try {
      ev = JSON.parse(lines[i]!) as AuditEvent;
    } catch {
      return { valid: false, total_events: lines.length, broken_at_seq: i + 1, reason: `Malformed JSON at line ${i + 1}` };
    }
    if (ev === null || typeof ev !== "object" || Array.isArray(ev)) {
      return { valid: false, total_events: lines.length, broken_at_seq: i + 1, reason: `Non-object JSON entry at line ${i + 1}` };
    }
    const expectedSeq = i + 1;
    if (ev.seq !== expectedSeq) {
      return {
        valid: false,
        total_events: lines.length,
        broken_at_seq: expectedSeq,
        reason: `Sequence gap/mismatch: expected ${expectedSeq}, found ${String(ev.seq)}`,
      };
    }
    if (ev.prev_hash !== expectedPrev) {
      return {
        valid: false,
        total_events: lines.length,
        broken_at_seq: ev.seq,
        reason: `Hash chain break at seq ${ev.seq}: prev_hash mismatch.`,
      };
    }
    const unexpectedKeys = Object.keys(ev as unknown as Record<string, unknown>).filter((k) => !ALLOWED_AUDIT_KEYS.has(k));
    if (unexpectedKeys.length > 0) {
      return {
        valid: false,
        total_events: lines.length,
        broken_at_seq: ev.seq,
        reason: `Unexpected unhashed field(s) injected at seq ${ev.seq} (${unexpectedKeys.length} disallowed key(s); redacted).`,
      };
    }
    const { entry_hash, ...rest } = ev;
    const recomputed = createHash("sha256")
      .update(`${expectedPrev}|${canonicalAuditPayload(rest)}`)
      .digest("hex");
    if (recomputed !== entry_hash) {
      return {
        valid: false,
        total_events: lines.length,
        broken_at_seq: ev.seq,
        reason: `Tampered payload detected at seq ${ev.seq}: entry_hash mismatch.`,
      };
    }
    expectedPrev = entry_hash;
  }

  return { valid: true, total_events: lines.length };
}

export function verifyAuditLog(
  auditLogPath: string,
  maxBytes = MAX_AUDIT_LOG_BYTES,
): {
  valid: boolean;
  total_events: number;
  broken_at_seq?: number;
  reason?: string;
} {
  if (!existsSync(auditLogPath)) {
    return { valid: false, total_events: 0, reason: `Audit log not found at ${auditLogPath}` };
  }
  let rawContent: string;
  try {
    rawContent = readCappedRegularFileSync(auditLogPath, maxBytes).toString("utf8");
  } catch (err) {
    return {
      valid: false,
      total_events: 0,
      reason: `Audit log unreadable or exceeds size cap: ${err instanceof Error ? err.message : String(err)}`,
    };
  }
  return verifyAuditLogContent(rawContent);
}
