import { closeSync, fstatSync, lstatSync, openSync, readSync, realpathSync, statSync } from "node:fs";
import { open } from "node:fs/promises";
import { homedir } from "node:os";
import { isAbsolute, parse as parsePath, resolve, sep } from "node:path";

export const MAX_AUTHORIZED_ROOTS = 10;

export function hasUnsafePathChars(rawPath        )          {
  if (!rawPath || rawPath.length > 4096) return true;
  if (/[\x00-\x1f\x7f]/.test(rawPath)) return true;
  // Reject NTFS Alternate Data Stream colons while preserving Windows drive prefixes (e.g. C:\)
  const withoutDrive = /^[A-Za-z]:[\\/]/.test(rawPath) ? rawPath.slice(2) : rawPath;
  if (withoutDrive.includes(":")) return true;
  return false;
}

export function isDangerousRootPath(rawPath        )          {
  const normalized = resolve(rawPath);
  const parsed = parsePath(normalized);
  if (normalized === parsed.root) return true;
  // Also guard Windows UNC roots (\\server\share) and bare drive specs
  if (/^[A-Za-z]:[\\/]?$/.test(normalized)) return true;
  if (/^\\\\[^\\]+\\[^\\]+[\\/]?$/.test(normalized)) return true;
  return false;
}

function normalizeForCompare(p        )         {
  const trimmed = p.endsWith(sep) && p.length > 1 ? p.slice(0, -1) : p;
  return process.platform === "win32" ? trimmed.toLowerCase() : trimmed;
}

export function isPathWithinRoot(canonicalTarget        , canonicalRoot        )          {
  const targetCmp = normalizeForCompare(canonicalTarget);
  const rootCmp = normalizeForCompare(canonicalRoot);
  return targetCmp === rootCmp || targetCmp.startsWith(`${rootCmp}${sep}`);
}

export function canonicalizeAuthorizedRoots(rawRoots                   )           {
  const out           = [];
  const seen = new Set        ();
  for (const raw of rawRoots) {
    if (out.length >= MAX_AUTHORIZED_ROOTS) break;
    const trimmed = raw.trim();
    if (!trimmed || hasUnsafePathChars(trimmed)) continue;
    try {
      const resolved = resolve(trimmed);
      if (isDangerousRootPath(resolved)) continue;
      const canonical = realpathSync(resolved);
      if (isDangerousRootPath(canonical)) continue;
      if (!statSync(canonical).isDirectory()) continue;
      const key = normalizeForCompare(canonical);
      if (!seen.has(key)) {
        seen.add(key);
        out.push(canonical);
      }
    } catch {
      // Ignore nonexistent or inaccessible root entries
    }
  }
  return out;
}

export function intersectAuthorizedRoots(
  clientRoots                   ,
  operatorRoots                   ,
)           {
  const canonOp = canonicalizeAuthorizedRoots(operatorRoots);
  const canonClient = canonicalizeAuthorizedRoots(clientRoots);
  if (canonOp.length === 0) return canonClient;
  if (canonClient.length === 0) return canonOp;
  const out           = [];
  for (const c of canonClient) {
    if (canonOp.some((op) => isPathWithinRoot(c, op))) {
      out.push(c);
    }
  }
  // If client roots are broader than operator roots, keep operator roots inside client roots
  for (const op of canonOp) {
    if (canonClient.some((c) => isPathWithinRoot(op, c)) && !out.includes(op)) {
      out.push(op);
    }
  }
  return out.slice(0, MAX_AUTHORIZED_ROOTS);
}

export function parseFileUriToPath(uri        )                {
  try {
    const parsed = new URL(uri);
    if (parsed.protocol !== "file:") return null;
    let pathname = decodeURIComponent(parsed.pathname);
    if (process.platform === "win32") {
      if (/^\/[A-Za-z]:/.test(pathname)) pathname = pathname.slice(1);
      pathname = pathname.replace(/\//g, "\\");
    }
    return pathname;
  } catch {
    return null;
  }
}

                                 
                               
                             
                          
                 
 

export function resolveConfinedPath(
  rawPath        ,
  authorizedRoots                   ,
  opts                 = {},
)                                                                     {
  const label = opts.label ?? "path";
  if (authorizedRoots.length === 0) {
    return {
      ok: false,
      error: `Local ${label} access denied: no authorized workspace roots configured (set COLDPIN_ALLOWED_ROOTS or provide MCP client roots).`,
    };
  }
  if (hasUnsafePathChars(rawPath)) {
    return { ok: false, error: `Invalid ${label}: contains NUL, control characters, or disallowed NTFS ADS colon.` };
  }

  const candidate = isAbsolute(rawPath) ? resolve(rawPath) : resolve(authorizedRoots[0] , rawPath);

  if (opts.rejectSymlink) {
    try {
      const lst = lstatSync(candidate);
      if (lst.isSymbolicLink()) {
        return { ok: false, error: `Rejected ${label}: symbolic link targets are not permitted.` };
      }
    } catch {
      return { ok: false, error: `Path not found or unreadable for ${label}.` };
    }
  }

  let canonical        ;
  try {
    canonical = realpathSync(candidate);
  } catch {
    return { ok: false, error: `Path not found or unreadable for ${label}.` };
  }

  if (isDangerousRootPath(canonical)) {
    return { ok: false, error: `Rejected ${label}: filesystem root paths are not permitted.` };
  }

  const allowed = authorizedRoots.some((root) => isPathWithinRoot(canonical, root));
  if (!allowed) {
    return { ok: false, error: `Access denied for ${label}: resolved path escapes authorized workspace roots.` };
  }

  try {
    const st = lstatSync(canonical);
    if (opts.rejectSymlink && st.isSymbolicLink()) {
      return { ok: false, error: `Rejected ${label}: symbolic link targets are not permitted.` };
    }
    if (opts.requireRegularFile && !st.isFile()) {
      return { ok: false, error: `Rejected ${label}: target is not a regular file.` };
    }
    if (opts.requireDirectory && !st.isDirectory()) {
      return { ok: false, error: `Rejected ${label}: target is not a directory.` };
    }
  } catch {
    return { ok: false, error: `Failed to stat ${label}.` };
  }

  return { ok: true, canonicalPath: canonical };
}

/**
 * TOCTOU-free single-FD capped reader (async).
 * Opens the target file descriptor once, verifies `isFile()` and `size <= maxBytes`,
 * and reads at most `maxBytes + 1` bytes before failing closed.
 */
export async function openReadCappedFile(
  filePath        ,
  maxBytes        ,
  rejectSymlink = false,
)                  {
  if (hasUnsafePathChars(filePath)) {
    throw new Error("Unsafe file path rejected.");
  }
  if (rejectSymlink) {
    const lst = lstatSync(filePath);
    if (lst.isSymbolicLink()) {
      throw new Error("Symbolic link file rejected.");
    }
  }
  const fh = await open(filePath, "r");
  try {
    const st = await fh.stat();
    if (!st.isFile()) {
      throw new Error("Target is not a regular file.");
    }
    if (st.size > maxBytes) {
      throw new Error(`File size (${st.size} bytes) exceeds limit (${maxBytes} bytes).`);
    }
    const chunks           = [];
    let total = 0;
    const chunkSize = Math.min(64 * 1024, Math.max(1024, maxBytes + 1));
    while (true) {
      const remaining = maxBytes + 1 - total;
      if (remaining <= 0) {
        throw new Error(`File stream exceeded limit (${maxBytes} bytes).`);
      }
      const buf = Buffer.allocUnsafe(Math.min(chunkSize, remaining));
      const { bytesRead } = await fh.read(buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) {
        throw new Error(`File stream exceeded limit (${maxBytes} bytes).`);
      }
      chunks.push(bytesRead === buf.length ? buf : buf.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks, total);
  } finally {
    await fh.close();
  }
}

/**
 * TOCTOU-free single-FD capped reader (sync) for synchronous helpers such as
 * lockfile inspection and CLI `audit-verify`.
 */
export function readCappedRegularFileSync(
  filePath        ,
  maxBytes        ,
  rejectSymlink = false,
)         {
  if (hasUnsafePathChars(filePath)) {
    throw new Error("Unsafe file path rejected.");
  }
  if (rejectSymlink) {
    const lst = lstatSync(filePath);
    if (lst.isSymbolicLink()) {
      throw new Error("Symbolic link file rejected.");
    }
  }
  const fd = openSync(filePath, "r");
  try {
    const st = fstatSync(fd);
    if (!st.isFile()) {
      throw new Error("Target is not a regular file.");
    }
    if (st.size > maxBytes) {
      throw new Error(`File size (${st.size} bytes) exceeds limit (${maxBytes} bytes).`);
    }
    const chunks           = [];
    let total = 0;
    const chunkSize = Math.min(64 * 1024, Math.max(1024, maxBytes + 1));
    while (true) {
      const remaining = maxBytes + 1 - total;
      if (remaining <= 0) {
        throw new Error(`File stream exceeded limit (${maxBytes} bytes).`);
      }
      const buf = Buffer.allocUnsafe(Math.min(chunkSize, remaining));
      const bytesRead = readSync(fd, buf, 0, buf.length, null);
      if (bytesRead === 0) break;
      total += bytesRead;
      if (total > maxBytes) {
        throw new Error(`File stream exceeded limit (${maxBytes} bytes).`);
      }
      chunks.push(bytesRead === buf.length ? buf : buf.subarray(0, bytesRead));
    }
    return Buffer.concat(chunks, total);
  } finally {
    closeSync(fd);
  }
}

export function redactHomePath(rawPath        )         {
  try {
    const home = homedir();
    if (!home) return rawPath;
    const normHome = normalizeForCompare(home);
    const normPath = normalizeForCompare(rawPath);
    if (normPath === normHome) return "~";
    if (normPath.startsWith(`${normHome}${sep}`)) {
      return `~${rawPath.slice(home.length).replace(/\\/g, "/")}`;
    }
  } catch {
    // Fall through
  }
  return rawPath;
}


//# sourceURL=core/path-confinement.ts
