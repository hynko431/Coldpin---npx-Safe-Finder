import { randomUUID } from "node:crypto";
                                                                                                  

export const REPORT_STORE_MAX_ENTRIES = 25;
export const REPORT_STORE_TTL_MS = 30 * 60 * 1000;
export const REPORT_STORE_MAX_TOTAL_BYTES = 15 * 1024 * 1024;
export const REPORT_TEXT_CHUNK_MAX_BYTES = 24 * 1024;

                                 
     
                      
                                      
                                            
     
     
                       
                                
     
     
                     
                                   
      

                      
             
                               
                      
                    
                         
 

/**
 * Slices a UTF-8 string starting at `byteOffset` up to `maxBytes` without ever
 * splitting a multi-byte UTF-8 codepoint or surrogate pair.
 */
export function sliceUtf8Safe(
  text        ,
  byteOffset = 0,
  maxBytes = REPORT_TEXT_CHUNK_MAX_BYTES,
)   
                
                      
                                  
                      
                     
  {
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
  while (safeStart < totalBytes && (buf[safeStart]  & 0xc0) === 0x80) {
    safeStart++;
  }
  let safeEnd = Math.min(totalBytes, safeStart + Math.max(1, maxBytes));
  // Back off end if it lands inside a multi-byte sequence
  if (safeEnd < totalBytes) {
    while (safeEnd > safeStart && (buf[safeEnd]  & 0xc0) === 0x80) {
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
                   entries = new Map                    ();
          totalBytes = 0;
                   maxEntries        ;
                   ttlMs        ;
                   maxTotalBytes        ;

  constructor(opts                                                                  ) {
    this.maxEntries = opts?.maxEntries ?? REPORT_STORE_MAX_ENTRIES;
    this.ttlMs = opts?.ttlMs ?? REPORT_STORE_TTL_MS;
    this.maxTotalBytes = opts?.maxTotalBytes ?? REPORT_STORE_MAX_TOTAL_BYTES;
  }

          pruneExpired(nowMs        )       {
    for (const [id, entry] of this.entries) {
      if (nowMs - entry.createdAt > this.ttlMs) {
        this.totalBytes -= entry.approxBytes;
        this.entries.delete(id);
      }
    }
  }

  put(payload                     , nowMs = Date.now())         {
    this.pruneExpired(nowMs);
    const approxBytes = Buffer.byteLength(JSON.stringify(payload), "utf8");
    const id = `rpt_${randomUUID().slice(0, 12)}`;

    // Evict oldest entries until both count and byte budgets hold
    while (
      this.entries.size > 0 &&
      (this.entries.size >= this.maxEntries || this.totalBytes + approxBytes > this.maxTotalBytes)
    ) {
      const oldestKey = this.entries.keys().next().value                      ;
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

  get(id        , nowMs = Date.now())                             {
    this.pruneExpired(nowMs);
    const entry = this.entries.get(id);
    if (!entry) return null;
    // Refresh LRU order (delete + re-insert moves to MRU tail of Map)
    entry.lastAccessedAt = nowMs;
    this.entries.delete(id);
    this.entries.set(id, entry);
    return entry.payload;
  }

  get size()         {
    return this.entries.size;
  }

  get bytesUsed()         {
    return this.totalBytes;
  }

  clear()       {
    this.entries.clear();
    this.totalBytes = 0;
  }
}


//# sourceURL=mcp/report-store.ts
