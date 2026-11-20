import { createHash } from "node:crypto";
import { chmodSync, mkdirSync } from "node:fs";
import { homedir } from "node:os";
import { dirname, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { CACHE_SCHEMA_VERSION, ENGINE_VERSION } from "../types.mjs";

export function defaultCacheDbPath(customDir         )         {
  if (customDir === ":memory:") return ":memory:";
  const baseDir =
    customDir ??
    (process.platform === "win32"
      ? join(process.env["LOCALAPPDATA"] ?? join(homedir(), "AppData", "Local"), "coldpin")
      : join(process.env["XDG_CACHE_HOME"] ?? join(homedir(), ".cache"), "coldpin"));
  return join(baseDir, "cache.sqlite");
}

function openSqliteWithFallback(preferredPath        )                                             {
  if (preferredPath === ":memory:") {
    return { db: new DatabaseSync(":memory:"), resolvedPath: ":memory:" };
  }
  // Never fall back to world-writable shared tmpdir() (prevents multi-user /tmp cache race [MCP-13]);
  // fall directly to isolated in-memory SQLite when preferred user/plugin cache path is unwritable.
  try {
    const parentDir = dirname(preferredPath);
    mkdirSync(parentDir, { recursive: true, mode: 0o700 });
    if (process.platform !== "win32") {
      try {
        chmodSync(parentDir, 0o700);
      } catch {
        // Best-effort owner-only directory permissions
      }
    }
    const db = new DatabaseSync(preferredPath);
    if (process.platform !== "win32") {
      try {
        chmodSync(preferredPath, 0o600);
      } catch {
        // Best-effort owner-only database file permissions
      }
    }
    db.exec("PRAGMA journal_mode = WAL;");
    return { db, resolvedPath: preferredPath };
  } catch {
    return { db: new DatabaseSync(":memory:"), resolvedPath: ":memory:" };
  }
}

export function buildFactCacheKey(params   
                      
                         
                                   
 )         {
  const canonicalOptions = JSON.stringify(
    Object.keys(params.options)
      .sort()
      .reduce                         ((acc, k) => {
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

export function raceWithAbort   (promise            , signal              )             {
  if (!signal) return promise;
  if (signal.aborted) {
    return Promise.reject(new Error("Operation aborted"));
  }
  return new Promise   ((resolvePromise, rejectPromise) => {
    const onAbort = () => {
      rejectPromise(new Error("Operation aborted"));
    };
    signal.addEventListener("abort", onAbort, { once: true });
    promise.then(
      (val) => {
        signal.removeEventListener("abort", onAbort);
        resolvePromise(val);
      },
      (err) => {
        signal.removeEventListener("abort", onAbort);
        rejectPromise(err);
      },
    );
  });
}

/**
 * Producer-once in-flight deduplicator (REA `rea-analysis-optimization` pattern).
 * Coalesces concurrent identical async lookups so work runs once per key without
 * letting a single caller failure or cancellation corrupt unrelated waiters.
 */
export class SingleFlight    {
                   inflight = new Map                    ();

  run(key        , producer                  , callerSignal              )             {
    let promise = this.inflight.get(key);
    if (!promise) {
      promise = Promise.resolve()
        .then(producer)
        .finally(() => {
          if (this.inflight.get(key) === promise) {
            this.inflight.delete(key);
          }
        });
      // Prevent unhandled rejection if every waiter aborts before the shared producer settles
      promise.catch(() => undefined);
      this.inflight.set(key, promise);
    }
    return raceWithAbort(promise, callerSignal);
  }

  get activeCount()         {
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
           dbPath        ;
                   db              ;

  constructor(dbPath         ) {
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

  getArtifactFacts   (cacheKey        )           {
    const stmt = this.db.prepare("SELECT facts_json FROM artifact_facts WHERE cache_key = ?");
    const row = stmt.get(cacheKey)                                       ;
    if (!row?.facts_json) return null;
    try {
      return JSON.parse(row.facts_json)     ;
    } catch {
      return null;
    }
  }

  putArtifactFacts(params   
                      
                        
                           
                   
   )       {
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

  getThreatIntel   (intelKey        , nowMs = Date.now())                                     {
    const stmt = this.db.prepare(
      "SELECT payload_json, expires_at_ms FROM threat_intel_cache WHERE intel_key = ?",
    );
    const row = stmt.get(intelKey)                                                                 ;
    if (!row?.payload_json || typeof row.expires_at_ms !== "number") return null;
    try {
      const data = JSON.parse(row.payload_json)     ;
      return { data, stale: nowMs > row.expires_at_ms };
    } catch {
      return null;
    }
  }

  putThreatIntel(params   
                      
                   
                     
                        
                    
   )       {
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

  pruneExpiredIntel(nowMs = Date.now())         {
    const stmt = this.db.prepare("DELETE FROM threat_intel_cache WHERE expires_at_ms < ?");
    const res = stmt.run(nowMs);
    return Number(res.changes ?? 0);
  }

  getStats()                                                               {
    const a = this.db.prepare("SELECT COUNT(*) AS c FROM artifact_facts").get()                              ;
    const t = this.db.prepare("SELECT COUNT(*) AS c FROM threat_intel_cache").get()                              ;
    return {
      artifact_facts_count: Number(a?.c ?? 0),
      threat_intel_count: Number(t?.c ?? 0),
    };
  }

  close()       {
    this.db.close();
  }
}


//# sourceURL=cache/sqlite-store.ts
