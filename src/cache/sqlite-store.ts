import { createHash } from "node:crypto";
import { mkdirSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { CACHE_SCHEMA_VERSION, ENGINE_VERSION } from "../types.ts";

export function defaultCacheDbPath(customDir?: string): string {
  if (customDir === ":memory:") return ":memory:";
  const baseDir =
    customDir ??
    (process.platform === "win32"
      ? join(process.env["LOCALAPPDATA"] ?? join(homedir(), "AppData", "Local"), "coldpin")
      : join(process.env["XDG_CACHE_HOME"] ?? join(homedir(), ".cache"), "coldpin"));
  return join(baseDir, "cache.sqlite");
}

function openSqliteWithFallback(preferredPath: string): { db: DatabaseSync; resolvedPath: string } {
  if (preferredPath === ":memory:") {
    return { db: new DatabaseSync(":memory:"), resolvedPath: ":memory:" };
  }
  const candidates = [preferredPath, join(tmpdir(), "coldpin", "cache.sqlite")];
  for (const p of candidates) {
    try {
      mkdirSync(dirname(p), { recursive: true });
      const db = new DatabaseSync(p);
      db.exec("PRAGMA journal_mode = WAL;");
      return { db, resolvedPath: p };
    } catch {
      // Fall back to tmpdir or in-memory SQLite when host/sandbox restricts AppData/HOME writes
    }
  }
  return { db: new DatabaseSync(":memory:"), resolvedPath: ":memory:" };
}

export function buildFactCacheKey(params: {
  content_sha: string;
  ruleset_sha256: string;
  options: Record<string, unknown>;
}): string {
  const canonicalOptions = JSON.stringify(
    Object.keys(params.options)
      .sort()
      .reduce<Record<string, unknown>>((acc, k) => {
        acc[k] = params.options[k];
        return acc;
      }, {}),
  );
  const raw = [
    params.content_sha,
    params.ruleset_sha256,
    ENGINE_VERSION,
    canonicalOptions,
    CACHE_SCHEMA_VERSION,
  ].join("|");
  return createHash("sha256").update(raw).digest("hex");
}

/**
 * Producer-once in-flight deduplicator (REA `rea-analysis-optimization` pattern).
 * Coalesces concurrent identical async lookups so work runs once per key without
 * letting a single caller failure corrupt unrelated keys.
 */
export class SingleFlight<T> {
  private readonly inflight = new Map<string, Promise<T>>();

  run(key: string, producer: () => Promise<T>): Promise<T> {
    const existing = this.inflight.get(key);
    if (existing) return existing;
    const promise = Promise.resolve()
      .then(producer)
      .finally(() => {
        if (this.inflight.get(key) === promise) {
          this.inflight.delete(key);
        }
      });
    this.inflight.set(key, promise);
    return promise;
  }

  get activeCount(): number {
    return this.inflight.size;
  }
}

/**
 * Split-Plane SQLite Cache:
 * 1. `artifact_facts`: immutable structural byte facts keyed by 5-tuple SHA-256.
 * 2. `threat_intel_cache`: TTL-bounded mutable OSV/MAL-star/KEV intelligence.
 * Composite verdicts are NEVER cached directly; always recomputed dynamically.
 */
export class SplitPlaneCache {
  readonly dbPath: string;
  private readonly db: DatabaseSync;

  constructor(dbPath?: string) {
    const opened = openSqliteWithFallback(dbPath ?? defaultCacheDbPath());
    this.dbPath = opened.resolvedPath;
    this.db = opened.db;
    this.db.exec("PRAGMA busy_timeout = 5000;");
    this.db.exec("PRAGMA foreign_keys = ON;");
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS artifact_facts (
        cache_key TEXT PRIMARY KEY,
        content_sha TEXT NOT NULL,
        ruleset_sha256 TEXT NOT NULL,
        engine_version TEXT NOT NULL,
        facts_json TEXT NOT NULL,
        created_at_utc TEXT NOT NULL
      );

      CREATE TABLE IF NOT EXISTS threat_intel_cache (
        intel_key TEXT PRIMARY KEY,
        source TEXT NOT NULL,
        payload_json TEXT NOT NULL,
        fetched_at_ms INTEGER NOT NULL,
        expires_at_ms INTEGER NOT NULL
      );
    `);
  }

  getArtifactFacts<T>(cacheKey: string): T | null {
    const stmt = this.db.prepare("SELECT facts_json FROM artifact_facts WHERE cache_key = ?");
    const row = stmt.get(cacheKey) as { facts_json?: string } | undefined;
    if (!row?.facts_json) return null;
    try {
      return JSON.parse(row.facts_json) as T;
    } catch {
      return null;
    }
  }

  putArtifactFacts(params: {
    cache_key: string;
    content_sha: string;
    ruleset_sha256: string;
    facts: unknown;
  }): void {
    const stmt = this.db.prepare(`
      INSERT INTO artifact_facts (cache_key, content_sha, ruleset_sha256, engine_version, facts_json, created_at_utc)
      VALUES (?, ?, ?, ?, ?, ?)
      ON CONFLICT(cache_key) DO UPDATE SET
        facts_json = excluded.facts_json,
        created_at_utc = excluded.created_at_utc
    `);
    stmt.run(
      params.cache_key,
      params.content_sha,
      params.ruleset_sha256,
      ENGINE_VERSION,
      JSON.stringify(params.facts),
      new Date().toISOString(),
    );
  }

  getThreatIntel<T>(intelKey: string, nowMs = Date.now()): { data: T; stale: boolean } | null {
    const stmt = this.db.prepare(
      "SELECT payload_json, expires_at_ms FROM threat_intel_cache WHERE intel_key = ?",
    );
    const row = stmt.get(intelKey) as { payload_json?: string; expires_at_ms?: number } | undefined;
    if (!row?.payload_json || typeof row.expires_at_ms !== "number") return null;
    try {
      const data = JSON.parse(row.payload_json) as T;
      return { data, stale: nowMs > row.expires_at_ms };
    } catch {
      return null;
    }
  }

  putThreatIntel(params: {
    intel_key: string;
    source: string;
    payload: unknown;
    ttl_seconds: number;
    now_ms?: number;
  }): void {
    const now = params.now_ms ?? Date.now();
    const expires = now + params.ttl_seconds * 1000;
    const stmt = this.db.prepare(`
      INSERT INTO threat_intel_cache (intel_key, source, payload_json, fetched_at_ms, expires_at_ms)
      VALUES (?, ?, ?, ?, ?)
      ON CONFLICT(intel_key) DO UPDATE SET
        source = excluded.source,
        payload_json = excluded.payload_json,
        fetched_at_ms = excluded.fetched_at_ms,
        expires_at_ms = excluded.expires_at_ms
    `);
    stmt.run(params.intel_key, params.source, JSON.stringify(params.payload), now, expires);
  }

  pruneExpiredIntel(nowMs = Date.now()): number {
    const stmt = this.db.prepare("DELETE FROM threat_intel_cache WHERE expires_at_ms < ?");
    const res = stmt.run(nowMs);
    return Number(res.changes ?? 0);
  }

  getStats(): { artifact_facts_count: number; threat_intel_count: number } {
    const a = this.db.prepare("SELECT COUNT(*) AS c FROM artifact_facts").get() as { c?: number } | undefined;
    const t = this.db.prepare("SELECT COUNT(*) AS c FROM threat_intel_cache").get() as { c?: number } | undefined;
    return {
      artifact_facts_count: Number(a?.c ?? 0),
      threat_intel_count: Number(t?.c ?? 0),
    };
  }

  close(): void {
    this.db.close();
  }
}
