import assert from "node:assert/strict";
import { describe, it } from "node:test";
import { DEFAULT_POLICY } from "../src/config/policy.ts";
import { computeSha512Integrity, unpackTarballInMemory } from "../src/quarantine/safe-unpack.ts";
import { buildSyntheticTgz } from "./helpers.ts";

describe("In-Memory Zero-Execution Quarantine Unpacker (safe-unpack)", () => {
  it("unpacks clean npm tarball and verifies SHA-512 integrity", async () => {
    const tgz = buildSyntheticTgz([
      { name: "package/package.json", content: JSON.stringify({ name: "clean-cli", version: "1.0.0" }) },
      { name: "package/index.js", content: "console.log('hello');\n" },
    ]);
    const integrity = computeSha512Integrity(tgz);
    const res = await unpackTarballInMemory(tgz, DEFAULT_POLICY, integrity);
    assert.equal(res.ok, true);
    assert.equal(res.observations.length, 0);
    assert.equal(res.entries.length, 2);
    assert.equal(res.entries[0]?.path, "package.json");
    assert.equal(res.entries[1]?.path, "index.js");
  });

  it("blocks tarball SHA-512 integrity mismatch", async () => {
    const tgz = buildSyntheticTgz([{ name: "package/package.json", content: "{}" }]);
    const res = await unpackTarballInMemory(tgz, DEFAULT_POLICY, "sha512-WRONGDIGEST==");
    assert.equal(res.ok, false);
    assert.ok(res.observations.some((o) => o.code === "TARBALL_INTEGRITY_MISMATCH" && o.severity === "CRITICAL"));
  });

  it("rejects Zip Slip traversal, absolute paths, backslashes, NTFS ADS, and Windows reserved names", async () => {
    const tgz = buildSyntheticTgz([
      { name: "package/../../.bashrc", content: "evil" },
      { name: "/etc/passwd", content: "evil" },
      { name: "package/sub\\escape.js", content: "evil" },
      { name: "package/index.js:stream", content: "evil" },
      { name: "package/CON.js", content: "evil" },
      { name: "package/trailing.", content: "evil" },
    ]);
    const res = await unpackTarballInMemory(tgz, DEFAULT_POLICY);
    assert.equal(res.entries.length, 0);
    assert.equal(res.observations.filter((o) => o.code === "ARCHIVE_PATH_TRAVERSAL_OR_WINDOWS_HAZARD").length, 6);
  });

  it("rejects symlinks and hardlinks", async () => {
    const tgz = buildSyntheticTgz([
      { name: "package/link-a", typeflag: "2" },
      { name: "package/link-b", typeflag: "1" },
    ]);
    const res = await unpackTarballInMemory(tgz, DEFAULT_POLICY);
    assert.equal(res.entries.length, 0);
    assert.equal(res.observations.filter((o) => o.code === "ARCHIVE_UNSAFE_LINK_OR_DEVICE").length, 2);
  });

  it("rejects duplicate archive entries (tar parser differential) and NTFS case collisions", async () => {
    const tgz = buildSyntheticTgz([
      { name: "package/index.js", content: "console.log('clean');" },
      { name: "package/index.js", content: "eval('malicious');" },
      { name: "package/Index.js", content: "eval('ntfs-collision');" },
    ]);
    const res = await unpackTarballInMemory(tgz, DEFAULT_POLICY);
    assert.equal(res.entries.length, 1);
    assert.ok(res.observations.some((o) => o.code === "ARCHIVE_DUPLICATE_ENTRY_DIFFERENTIAL" && o.severity === "CRITICAL"));
    assert.ok(res.observations.some((o) => o.code === "ARCHIVE_CASE_COLLISION" && o.severity === "HIGH"));
  });

  it("halts decompression zip bomb at hard uncompressed byte cap", async () => {
    const hugeZeroes = Buffer.alloc(2 * 1024 * 1024, 0x41);
    const tgz = buildSyntheticTgz([{ name: "package/big.txt", content: hugeZeroes }]);
    const strictPolicy = { ...DEFAULT_POLICY, max_uncompressed_bytes: 256 * 1024 };
    const res = await unpackTarballInMemory(tgz, strictPolicy);
    assert.equal(res.ok, false);
    assert.equal(res.halted_by_cap, true);
    assert.ok(res.observations.some((o) => o.code === "ARCHIVE_DECOMPRESSION_BOMB"));
  });
});
