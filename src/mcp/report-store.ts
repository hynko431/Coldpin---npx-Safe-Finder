import { randomUUID } from "node:crypto";
import type {
  DiscoveryCardList,
  ManifestBatchReport,
  PackageInspectionReport,
  SafeAnchorDecision,
} from "../types.ts";

export const REPORT_STORE_MAX_ENTRIES = 25;
export const REPORT_STORE_TTL_MS = 30 * 60 * 1000;
export const REPORT_STORE_MAX_TOTAL_BYTES = 15 * 1024 * 1024;
export const REPORT_TEXT_CHUNK_MAX_BYTES = 24 * 1024;

export type StoredReportPayload =
  | {
      kind: "inspect";
      report: PackageInspectionReport;
      dependencies?: Record<string, string>;
    }
  | {
      kind: "discover";
      report: DiscoveryCardList;
    }
  | {
      kind: "anchor";
      decision: SafeAnchorDecision;
    }
  | {
      kind: "batch";
      report: ManifestBatchReport;
    };

interface StoreEntry {
  id: string;
  payload: StoredReportPayload;
  approxBytes: number;
  createdAt: number;
  lastAccessedAt: number;
}

/**
 * Slices a UTF-8 string starting at `byteOffset` up to `maxBytes` without ever
 * splitting a multi-byte UTF-8 codepoint or surrogate pair.
 */
export function sliceUtf8Safe(
  text: string,
  byteOffset = 0,
  maxBytes = REPORT_TEXT_CHUNK_MAX_BYTES,
): {
  chunk: string;
  byte_offset: number;
  next_byte_offset: number | null;
  total_bytes: number;
  truncated: boolean;
} {
  const buf = Buffer.from(text, "utf8");
  const totalBytes = buf.byteLength;
  const start = Math.max(0, Math.min(Math.floor(byteOffset), totalBytes));
  if (start >= totalBytes) {
    return {
      chunk: "",
      byte_offset: start,
      next_byte_offset: null,
      total_bytes: totalBytes,
      truncated: false,
    };
  }
  // Advance start if it lands on a UTF-8 continuation byte (10xxxxxx)
  let safeStart = start;
  while (safeStart < totalBytes && (buf[safeStart]! & 0xc0) === 0x80) {
    safeStart++;
  }
  let safeEnd = Math.min(totalBytes, safeStart + Math.max(1, maxBytes));
  // Back off end if it lands inside a multi-byte sequence
  if (safeEnd < totalBytes) {
    while (safeEnd > safeStart && (buf[safeEnd]! & 0xc0) === 0x80) {
      safeEnd--;
    }
  }
  const chunk = buf.subarray(safeStart, safeEnd).toString("utf8");
  const truncated = safeEnd < totalBytes;
  return {
    chunk,
    byte_offset: safeStart,
    next_byte_offset: truncated ? safeEnd : null,
    total_bytes: totalBytes,
    truncated,
  };
}

/**
 * Session-only, byte-bounded LRU report store (`ADR-004`).
 * Keeps full inspection/discovery/anchor reports in process memory for paginated
 * retrieval via `get_artifact_report` without ever persisting composite verdicts to SQLite.
 */
export class BoundedReportStore {
  private readonly entries = new Map<string, StoreEntry>();
  private totalBytes = 0;
  private readonly maxEntries: number;
  private readonly ttlMs: number;
  private readonly maxTotalBytes: number;

  constructor(opts?: { maxEntries?: number; ttlMs?: number; maxTotalBytes?: number }) {
    this.maxEntries = opts?.maxEntries ?? REPORT_STORE_MAX_ENTRIES;
    this.ttlMs = opts?.ttlMs ?? REPORT_STORE_TTL_MS;
    this.maxTotalBytes = opts?.maxTotalBytes ?? REPORT_STORE_MAX_TOTAL_BYTES;
  }

  private pruneExpired(nowMs: number): void {
    for (const [id, entry] of this.entries) {
      if (nowMs - entry.createdAt > this.ttlMs) {
        this.totalBytes -= entry.approxBytes;
        this.entries.delete(id);
      }
    }
  }

  put(payload: StoredReportPayload, nowMs = Date.now()): string {
    this.pruneExpired(nowMs);
    const approxBytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
    const id = `rpt_${randomUUID().slice(0, 12)}`;

    // Evict oldest entries until both count and byte budgets hold
    while (
      this.entries.size > 0 &&
      (this.entries.size >= this.maxEntries || this.totalBytes + approxBytes > this.maxTotalBytes)
    ) {
      const oldestKey = this.entries.keys().next().value as string | undefined;
      if (!oldestKey) break;
      const oldest = this.entries.get(oldestKey);
      if (oldest) this.totalBytes -= oldest.approxBytes;
      this.entries.delete(oldestKey);
    }

    // If a single report alone exceeds maxTotalBytes, still store it temporarily if empty or cap
    if (approxBytes <= this.maxTotalBytes) {
      this.entries.set(id, {
        id,
        payload,
        approxBytes,
        createdAt: nowMs,
        lastAccessedAt: nowMs,
      });
      this.totalBytes += approxBytes;
    }
    return id;
  }

  get(id: string, nowMs = Date.now()): StoredReportPayload | null {
    this.pruneExpired(nowMs);
    const entry = this.entries.get(id);
    if (!entry) return null;
    // Refresh LRU order (delete + re-insert moves to MRU tail of Map)
    entry.lastAccessedAt = nowMs;
    this.entries.delete(id);
    this.entries.set(id, entry);
    return entry.payload;
  }

  get size(): number {
    return this.entries.size;
  }

  get bytesUsed(): number {
    return this.totalBytes;
  }

  clear(): void {
    this.entries.clear();
    this.totalBytes = 0;
  }
}
