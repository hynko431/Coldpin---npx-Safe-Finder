import { createHash } from "node:crypto";
import { Readable, Transform } from "node:stream";
import { pipeline } from "node:stream/promises";
import { createGunzip } from "node:zlib";
                                                                                     

const WINDOWS_RESERVED_NAMES = new Set([
  "con",
  "prn",
  "aux",
  "nul",
  "com1",
  "com2",
  "com3",
  "com4",
  "com5",
  "com6",
  "com7",
  "com8",
  "com9",
  "lpt1",
  "lpt2",
  "lpt3",
  "lpt4",
  "lpt5",
  "lpt6",
  "lpt7",
  "lpt8",
  "lpt9",
]);

function readAsciiZ(buf        , start        , length        )         {
  let end = start;
  const max = Math.min(buf.length, start + length);
  while (end < max && buf[end] !== 0) end++;
  return buf.subarray(start, end).toString("utf8");
}

function parseOctalOrBase256(buf        , start        , length        )         {
  const first = buf[start] ?? 0;
  if ((first & 0x80) !== 0) {
    // GNU base-256 big-endian unsigned integer
    let val = first & 0x7f;
    for (let i = 1; i < length; i++) {
      val = val * 256 + (buf[start + i] ?? 0);
    }
    return val;
  }
  const str = readAsciiZ(buf, start, length).trim();
  if (!str) return 0;
  const parsed = Number.parseInt(str, 8);
  return Number.isFinite(parsed) && parsed >= 0 ? parsed : -1;
}

function verifyTarHeaderChecksum(header        )          {
  const stored = parseOctalOrBase256(header, 148, 8);
  if (stored < 0) return false;
  let unsignedSum = 0;
  let signedSum = 0;
  for (let i = 0; i < 512; i++) {
    const b = i >= 148 && i < 156 ? 0x20 : (header[i] ?? 0);
    unsignedSum += b;
    signedSum += b > 127 ? b - 256 : b;
  }
  return stored === unsignedSum || stored === signedSum;
}

const HIDDEN_ARCHIVE_UNICODE_RE = /[\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u2069\ufeff\u00ad\u{e0000}-\u{e007f}]/u;

function parsePaxRecords(data        )                                                          {
  const out                         = {};
  let offset = 0;
  while (offset < data.length) {
    const spaceIdx = data.indexOf(0x20, offset);
    if (spaceIdx === -1) return { records: out, malformed: true };
    const lenStr = data.subarray(offset, spaceIdx).toString("ascii");
    if (!/^\d+$/.test(lenStr)) return { records: out, malformed: true };
    const recLen = Number.parseInt(lenStr, 10);
    if (!Number.isFinite(recLen) || recLen <= spaceIdx - offset + 1 || offset + recLen > data.length) {
      return { records: out, malformed: true };
    }
    if (data[offset + recLen - 1] !== 0x0a) {
      return { records: out, malformed: true };
    }
    const record = data.subarray(spaceIdx + 1, offset + recLen - 1).toString("utf8");
    const eqIdx = record.indexOf("=");
    if (eqIdx <= 0) {
      return { records: out, malformed: true };
    }
    out[record.slice(0, eqIdx)] = record.slice(eqIdx + 1);
    offset += recLen;
  }
  return { records: out, malformed: false };
}

export function validateArchivePath(rawPath        )   
                
                     
                  
  {
  if (!rawPath || rawPath.includes("\0")) {
    return { safe: false, normalized: rawPath, reason: "Empty path or embedded NUL byte" };
  }
  // Reject control characters
  for (let i = 0; i < rawPath.length; i++) {
    const code = rawPath.charCodeAt(i);
    if (code < 0x20 || code === 0x7f) {
      return { safe: false, normalized: rawPath, reason: "Control character in archive path" };
    }
  }
  // Reject backslashes, Windows drive letters, NTFS ADS colons, leading slash
  if (rawPath.includes("\\")) {
    return { safe: false, normalized: rawPath, reason: "Backslash path separator rejected" };
  }
  if (rawPath.startsWith("/")) {
    return { safe: false, normalized: rawPath, reason: "Absolute path rejected (Zip Slip)" };
  }
  if (/^[a-zA-Z]:/.test(rawPath) || rawPath.includes(":")) {
    return { safe: false, normalized: rawPath, reason: "Drive letter or NTFS Alternate Data Stream colon rejected" };
  }
  if (/[<>"|?*]/.test(rawPath)) {
    return { safe: false, normalized: rawPath, reason: "Windows-illegal filename character (< > \" | ? *) rejected" };
  }
  if (HIDDEN_ARCHIVE_UNICODE_RE.test(rawPath)) {
    return { safe: false, normalized: rawPath, reason: "Hidden or bidirectional Unicode character in archive path rejected" };
  }

  let cleaned = rawPath.replace(/^\.\//, "");
  if (cleaned.startsWith("package/")) {
    cleaned = cleaned.slice("package/".length);
  } else if (cleaned === "package") {
    cleaned = "";
  }
  cleaned = cleaned.replace(/\/+$/, "");
  if (!cleaned) return { safe: true, normalized: "" };

  const segments = cleaned.split("/");
  for (const seg of segments) {
    if (!seg || seg === "." || seg === "..") {
      return { safe: false, normalized: rawPath, reason: `Path traversal segment '${seg}' rejected (Zip Slip)` };
    }
    if (seg.endsWith(".") || seg.endsWith(" ")) {
      return { safe: false, normalized: rawPath, reason: `Windows trailing dot/space segment '${seg}' rejected` };
    }
    const baseName = seg.split(".")[0]?.toLowerCase() ?? "";
    if (WINDOWS_RESERVED_NAMES.has(baseName)) {
      return { safe: false, normalized: rawPath, reason: `Windows reserved device name '${seg}' rejected` };
    }
  }

  return { safe: true, normalized: segments.join("/") };
}

async function gunzipWithHardCap(
  compressed        ,
  maxUncompressedBytes        ,
)                                                                                                {
  const chunks           = [];
  let totalBytes = 0;
  let capped = false;

  const capTransform = new Transform({
    transform(chunk        , _enc, cb) {
      totalBytes += chunk.length;
      if (totalBytes > maxUncompressedBytes) {
        capped = true;
        cb(new Error(`UNCOMPRESSED_CAP_EXCEEDED:${maxUncompressedBytes}`));
        return;
      }
      chunks.push(Buffer.from(chunk));
      cb();
    },
  });

  try {
    await pipeline(Readable.from([compressed]), createGunzip(), capTransform);
    return { ok: true, buffer: Buffer.concat(chunks), totalBytes, capped: false };
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err);
    return { ok: false, buffer: Buffer.alloc(0), totalBytes, capped, error: msg };
  }
}

export function computeSha512Integrity(buf        )         {
  return `sha512-${createHash("sha512").update(buf).digest("base64")}`;
}

/**
 * In-memory zero-execution streaming tarball verifier & unpacker.
 * Never writes untrusted files to disk; prevents Zip-Slip, symlink escapes,
 * duplicate-entry parser differentials, Windows NTFS collisions, and zip bombs.
 */
export async function unpackTarballInMemory(
  tarballBuffer        ,
  policy              ,
  expectedIntegrity         ,
)                        {
  const observations                = [];
  const unknowns           = [];
  const entries             = [];

  const tarball_sha512 = computeSha512Integrity(tarballBuffer);

  if (expectedIntegrity && expectedIntegrity !== tarball_sha512) {
    observations.push({
      code: "TARBALL_INTEGRITY_MISMATCH",
      severity: "CRITICAL",
      path: "<tarball>",
      attack_id: "T1195.002",
      detail: `Tarball SHA-512 mismatch: expected ${expectedIntegrity}, observed ${tarball_sha512}.`,
    });
    return {
      ok: false,
      tarball_sha512,
      compressed_bytes: tarballBuffer.length,
      uncompressed_bytes: 0,
      entries,
      observations,
      unknowns,
      halted_by_cap: false,
    };
  }

  if (tarballBuffer.length > policy.max_compressed_bytes) {
    unknowns.push(
      `ARCHIVE_COMPRESSED_CAP_EXCEEDED: ${tarballBuffer.length} bytes > ${policy.max_compressed_bytes} bytes.`,
    );
    return {
      ok: false,
      tarball_sha512,
      compressed_bytes: tarballBuffer.length,
      uncompressed_bytes: 0,
      entries,
      observations,
      unknowns,
      halted_by_cap: true,
    };
  }

  // Detect gzip magic (0x1f 0x8b) vs raw tar buffer
  const isGzip = tarballBuffer.length >= 2 && tarballBuffer[0] === 0x1f && tarballBuffer[1] === 0x8b;
  let tarBuf        ;
  let uncompressedBytes        ;

  if (isGzip) {
    const gunzipped = await gunzipWithHardCap(tarballBuffer, policy.max_uncompressed_bytes);
    if (!gunzipped.ok) {
      if (gunzipped.capped) {
        unknowns.push(
          `ARCHIVE_UNCOMPRESSED_CAP_EXCEEDED: decompressed stream exceeded ${policy.max_uncompressed_bytes} bytes (potential zip bomb).`,
        );
        observations.push({
          code: "ARCHIVE_DECOMPRESSION_BOMB",
          severity: "HIGH",
          path: "<tarball>",
          attack_id: "T1499",
          detail: `Decompressed archive exceeded configured hard cap of ${policy.max_uncompressed_bytes} bytes.`,
        });
        return {
          ok: false,
          tarball_sha512,
          compressed_bytes: tarballBuffer.length,
          uncompressed_bytes: gunzipped.totalBytes,
          entries,
          observations,
          unknowns,
          halted_by_cap: true,
        };
      }
      unknowns.push(`ARCHIVE_GUNZIP_ERROR: ${gunzipped.error ?? "malformed gzip stream"}`);
      return {
        ok: false,
        tarball_sha512,
        compressed_bytes: tarballBuffer.length,
        uncompressed_bytes: 0,
        entries,
        observations,
        unknowns,
        halted_by_cap: false,
      };
    }
    tarBuf = gunzipped.buffer;
    uncompressedBytes = gunzipped.totalBytes;
  } else {
    if (tarballBuffer.length > policy.max_uncompressed_bytes) {
      unknowns.push(`ARCHIVE_UNCOMPRESSED_CAP_EXCEEDED: ${tarballBuffer.length} bytes.`);
      return {
        ok: false,
        tarball_sha512,
        compressed_bytes: tarballBuffer.length,
        uncompressed_bytes: tarballBuffer.length,
        entries,
        observations,
        unknowns,
        halted_by_cap: true,
      };
    }
    tarBuf = tarballBuffer;
    uncompressedBytes = tarballBuffer.length;
  }

  const seenExact = new Set        ();
  const seenLower = new Map                ();
  let globalPax                         = {};
  let pendingPax                                = null;
  let pendingGnuLongName                = null;
  let offset = 0;
  let fileCount = 0;

  while (offset + 512 <= tarBuf.length) {
    const header = tarBuf.subarray(offset, offset + 512);
    // Two zero blocks signal end of tar archive
    let allZero = true;
    for (let i = 0; i < 512; i++) {
      if (header[i] !== 0) {
        allZero = false;
        break;
      }
    }
    if (allZero) {
      // Detect tar EOF polyglot / single-zero-block smuggling: any non-zero byte after a zero block is hostile
      let trailingNonZeroOffset = -1;
      for (let j = offset + 512; j < tarBuf.length; j++) {
        if (tarBuf[j] !== 0) {
          trailingNonZeroOffset = j;
          break;
        }
      }
      if (trailingNonZeroOffset !== -1) {
        observations.push({
          code: "ARCHIVE_EOF_POLYGLOT_SMUGGLING",
          severity: "CRITICAL",
          path: "<tarball>",
          attack_id: "T1195.002",
          detail: `Non-zero trailing bytes found at offset ${trailingNonZeroOffset} after tar EOF zero block (tar polyglot/single-zero-block smuggling risk).`,
        });
        return {
          ok: false,
          tarball_sha512,
          compressed_bytes: tarballBuffer.length,
          uncompressed_bytes: uncompressedBytes,
          entries,
          observations,
          unknowns,
          halted_by_cap: false,
        };
      }
      break;
    }

    if (!verifyTarHeaderChecksum(header)) {
      observations.push({
        code: "ARCHIVE_CORRUPT_HEADER_CHECKSUM",
        severity: "CRITICAL",
        path: "<tarball>",
        attack_id: "T1195.002",
        detail: `Tar header checksum verification failed at byte offset ${offset} (corrupted or polyglot archive).`,
      });
      return {
        ok: false,
        tarball_sha512,
        compressed_bytes: tarballBuffer.length,
        uncompressed_bytes: uncompressedBytes,
        entries,
        observations,
        unknowns,
        halted_by_cap: false,
      };
    }

    const nameField = readAsciiZ(header, 0, 100);
    const prefixField = readAsciiZ(header, 345, 155);
    const typeFlag = String.fromCharCode(header[156] ?? 0);
    const mergedPax = typeFlag === "x" || typeFlag === "g" ? null : { ...globalPax, ...(pendingPax ?? {}) };
    const paxSizeRaw = mergedPax?.["size"];
    let size = parseOctalOrBase256(header, 124, 12);
    if (paxSizeRaw !== undefined) {
      if (!/^\d+$/.test(paxSizeRaw)) {
        observations.push({
          code: "ARCHIVE_MALFORMED_PAX_HEADER",
          severity: "CRITICAL",
          path: "<tarball>",
          attack_id: "T1195.002",
          detail: `Malformed non-numeric PAX size override at byte offset ${offset}.`,
        });
        return {
          ok: false,
          tarball_sha512,
          compressed_bytes: tarballBuffer.length,
          uncompressed_bytes: uncompressedBytes,
          entries,
          observations,
          unknowns,
          halted_by_cap: false,
        };
      }
      const parsedPaxSize = Number.parseInt(paxSizeRaw, 10);
      if (Number.isFinite(parsedPaxSize) && parsedPaxSize >= 0) {
        size = parsedPaxSize;
      }
    }
    offset += 512;

    if (size < 0 || offset + size > tarBuf.length) {
      unknowns.push(`ARCHIVE_MALFORMED_HEADER: invalid tar entry size at offset ${offset - 512}.`);
      return {
        ok: false,
        tarball_sha512,
        compressed_bytes: tarballBuffer.length,
        uncompressed_bytes: uncompressedBytes,
        entries,
        observations,
        unknowns,
        halted_by_cap: false,
      };
    }

    const content = tarBuf.subarray(offset, offset + size);
    const paddedSize = Math.ceil(size / 512) * 512;
    offset += paddedSize;

    // PAX extended header ('x') or global PAX ('g')
    if (typeFlag === "x" || typeFlag === "g") {
      const parsedPax = parsePaxRecords(content);
      if (parsedPax.malformed) {
        observations.push({
          code: "ARCHIVE_MALFORMED_PAX_HEADER",
          severity: "CRITICAL",
          path: "<tarball>",
          attack_id: "T1195.002",
          detail: `Malformed or truncated PAX '${typeFlag}' extended header (parser differential risk).`,
        });
        return {
          ok: false,
          tarball_sha512,
          compressed_bytes: tarballBuffer.length,
          uncompressed_bytes: uncompressedBytes,
          entries,
          observations,
          unknowns,
          halted_by_cap: false,
        };
      }
      if (typeFlag === "x") pendingPax = parsedPax.records;
      else globalPax = { ...globalPax, ...parsedPax.records };
      continue;
    }
    // GNU LongLink filename ('L')
    if (typeFlag === "L") {
      pendingGnuLongName = content.toString("utf8").replace(/\0+$/, "");
      continue;
    }

    const combinedName =
      mergedPax?.["path"] ??
      pendingGnuLongName ??
      (prefixField ? `${prefixField}/${nameField}` : nameField);
    const hasPaxLinkPath = Boolean(mergedPax?.["linkpath"]);
    pendingPax = null;
    pendingGnuLongName = null;

    // Reject symlinks, hardlinks, GNU LongLink targets ('K'), character/block devices, FIFOs, or PAX linkpath smuggling
    if (
      hasPaxLinkPath ||
      typeFlag === "1" ||
      typeFlag === "2" ||
      typeFlag === "3" ||
      typeFlag === "4" ||
      typeFlag === "6" ||
      typeFlag === "K"
    ) {
      observations.push({
        code: "ARCHIVE_UNSAFE_LINK_OR_DEVICE",
        severity: "CRITICAL",
        path: combinedName,
        attack_id: "T1546",
        detail: `Rejected non-regular tar entry (typeflag='${typeFlag}'${hasPaxLinkPath ? ", pax_linkpath" : ""}) at '${combinedName}'.`,
      });
      continue;
    }

    // Directories ('5'): validate path safety, do not add to file list
    const pathCheck = validateArchivePath(combinedName);
    if (!pathCheck.safe) {
      observations.push({
        code: "ARCHIVE_PATH_TRAVERSAL_OR_WINDOWS_HAZARD",
        severity: "CRITICAL",
        path: combinedName,
        attack_id: "T1546",
        detail: `${pathCheck.reason ?? "Unsafe archive path"}: '${combinedName}'.`,
      });
      continue;
    }

    if (typeFlag === "5" || !pathCheck.normalized) continue;

    // Only allow regular files ('0' or '\0')
    if (typeFlag !== "0" && typeFlag !== "\0") {
      unknowns.push(`ARCHIVE_UNSUPPORTED_TYPEFLAG: '${typeFlag}' on '${pathCheck.normalized}'.`);
      continue;
    }

    fileCount++;
    if (fileCount > policy.max_files) {
      unknowns.push(`ARCHIVE_FILE_COUNT_CAP_EXCEEDED: > ${policy.max_files} files.`);
      return {
        ok: false,
        tarball_sha512,
        compressed_bytes: tarballBuffer.length,
        uncompressed_bytes: uncompressedBytes,
        entries,
        observations,
        unknowns,
        halted_by_cap: true,
      };
    }

    // Reject duplicate archive entries (prevents tar parser differential attacks)
    if (seenExact.has(pathCheck.normalized)) {
      observations.push({
        code: "ARCHIVE_DUPLICATE_ENTRY_DIFFERENTIAL",
        severity: "CRITICAL",
        path: pathCheck.normalized,
        attack_id: "T1195.002",
        detail: `Duplicate archive entry '${pathCheck.normalized}' detected (parser differential smuggling risk).`,
      });
      continue;
    }
    seenExact.add(pathCheck.normalized);

    // Reject Windows/macOS case-insensitive filename collisions (Index.js vs index.js)
    const lower = pathCheck.normalized.toLowerCase();
    const prior = seenLower.get(lower);
    if (prior) {
      observations.push({
        code: "ARCHIVE_CASE_COLLISION",
        severity: "HIGH",
        path: pathCheck.normalized,
        attack_id: "T1195.002",
        detail: `Case-insensitive filename collision between '${prior}' and '${pathCheck.normalized}' (NTFS/APFS hazard).`,
      });
      continue;
    }
    seenLower.set(lower, pathCheck.normalized);

    const sha256 = createHash("sha256").update(content).digest("hex");
    entries.push({
      path: pathCheck.normalized,
      size: content.length,
      sha256,
      content,
    });
  }

  return {
    ok: true,
    tarball_sha512,
    compressed_bytes: tarballBuffer.length,
    uncompressed_bytes: uncompressedBytes,
    entries,
    observations,
    unknowns,
    halted_by_cap: false,
  };
}


//# sourceURL=quarantine/safe-unpack.ts
