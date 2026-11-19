import { createHash } from "node:crypto";
import { appendFileSync, closeSync, existsSync, mkdirSync, openSync, readFileSync, statSync, unlinkSync } from "node:fs";
import { userInfo } from "node:os";
import { dirname } from "node:path";
import type { AuditEvent } from "../types.ts";

const GENESIS_HASH = "0".repeat(64);
const LOCK_STALE_MS = 30_000;
const LOCK_WAIT_MS = 25;
const LOCK_MAX_ATTEMPTS = 80;

const SLEEP_ARRAY = new Int32Array(new SharedArrayBuffer(4));

function sleepSync(ms: number): void {
  Atomics.wait(SLEEP_ARRAY, 0, 0, ms);
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
        // Lock disappeared between EEXIST and statSync; retry immediately
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

/**
 * Structured operational JSON telemetry on stderr — strictly separate from the
 * hash-chained audit trail (`audit.jsonl`). Never logs secrets, tokens, or PII.
 */
export function logOperationalEvent(verbose: boolean, event: Record<string, unknown>): void {
  if (!verbose) return;
  const line = JSON.stringify({
    ts_utc: new Date().toISOString(),
    stream: "operational",
    ...event,
  });
  process.stderr.write(`${line}\n`);
}

const ALLOWED_AUDIT_KEYS = new Set([
  "seq",
  "ts_utc",
  "request_id",
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

/**
 * Local append-only hash-chained audit trail (`audit.jsonl`) with atomic lockfile
 * serialization so concurrent CLI invocations cannot fork or corrupt the chain.
 * Note: local files provide local tamper-evidence only; enterprise non-repudiation
 * requires forwarding events off-host to WORM / object-lock storage (Phase 3).
 */
export function appendAuditEvent(
  auditLogPath: string,
  params: Omit<AuditEvent, "seq" | "ts_utc" | "actor_id_hash" | "prev_hash" | "entry_hash">,
): AuditEvent {
  return withAuditFileLock(auditLogPath, () => {
    let prevHash = GENESIS_HASH;
    let nextSeq = 1;

    if (existsSync(auditLogPath)) {
      const lines = readFileSync(auditLogPath, "utf8")
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

    const full: AuditEvent = { ...base, entry_hash };
    appendFileSync(auditLogPath, `${JSON.stringify(full)}\n`, "utf8");
    return full;
  });
}

export function verifyAuditLog(auditLogPath: string): {
  valid: boolean;
  total_events: number;
  broken_at_seq?: number;
  reason?: string;
} {
  if (!existsSync(auditLogPath)) {
    return { valid: false, total_events: 0, reason: `Audit log not found at ${auditLogPath}` };
  }
  const lines = readFileSync(auditLogPath, "utf8")
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
    const expectedSeq = i + 1;
    if (ev.seq !== expectedSeq) {
      return {
        valid: false,
        total_events: lines.length,
        broken_at_seq: expectedSeq,
        reason: `Sequence gap/mismatch: expected ${expectedSeq}, found ${ev.seq}`,
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
        reason: `Unexpected unhashed field(s) injected at seq ${ev.seq}: ${unexpectedKeys.join(", ")}`,
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
