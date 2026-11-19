import { gzipSync } from "node:zlib";

export interface SyntheticTarEntry {
  name: string;
  content?: Buffer | string;
  typeflag?: string;
}

export function buildSyntheticTgz(entries: SyntheticTarEntry[]): Buffer {
  const blocks: Buffer[] = [];
  for (const e of entries) {
    const data =
      e.content === undefined
        ? Buffer.alloc(0)
        : Buffer.isBuffer(e.content)
          ? e.content
          : Buffer.from(e.content, "utf8");
    const header = Buffer.alloc(512, 0);
    header.write(e.name, 0, Math.min(100, Buffer.byteLength(e.name)), "utf8");
    header.write("0000644\0", 100, 8, "ascii");
    header.write("0000000\0", 108, 8, "ascii");
    header.write("0000000\0", 116, 8, "ascii");
    header.write(`${data.length.toString(8).padStart(11, "0")}\0`, 124, 12, "ascii");
    header.write("00000000000\0", 136, 12, "ascii");
    header.write("        ", 148, 8, "ascii");
    header.write(e.typeflag ?? "0", 156, 1, "ascii");
    header.write("ustar\0", 257, 6, "ascii");
    header.write("00", 263, 2, "ascii");

    let chksum = 0;
    for (let i = 0; i < 512; i++) chksum += header[i] ?? 0;
    header.write(`${chksum.toString(8).padStart(6, "0")}\0 `, 148, 8, "ascii");

    blocks.push(header);
    if (data.length > 0) {
      blocks.push(data);
      const rem = data.length % 512;
      if (rem !== 0) blocks.push(Buffer.alloc(512 - rem, 0));
    }
  }
  blocks.push(Buffer.alloc(1024, 0));
  return gzipSync(Buffer.concat(blocks));
}
