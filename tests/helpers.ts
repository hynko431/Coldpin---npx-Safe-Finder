import { createSign, generateKeyPairSync, X509Certificate } from "node:crypto";
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

function derLen(len: number): Buffer {
  if (len < 0x80) return Buffer.from([len]);
  if (len < 0x100) return Buffer.from([0x81, len]);
  return Buffer.from([0x82, (len >> 8) & 0xff, len & 0xff]);
}

function derTlv(tag: number, content: Buffer): Buffer {
  return Buffer.concat([Buffer.from([tag]), derLen(content.length), content]);
}

function buildSelfSignedEcX509Der(): {
  certDer: Buffer;
  privateKey: ReturnType<typeof generateKeyPairSync>["privateKey"];
} {
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const spkiDer = publicKey.export({ type: "spki", format: "der" }) as Buffer;
  // SEQUENCE { OID 1.2.840.10045.4.3.2 (ecdsa-with-SHA256) }
  const sigAlg = Buffer.from("300a06082a8648ce3d040302", "hex");
  const cnAttr = derTlv(
    0x30,
    Buffer.concat([Buffer.from("0603550403", "hex"), derTlv(0x0c, Buffer.from("coldpin-test-leaf", "utf8"))]),
  );
  const name = derTlv(0x30, derTlv(0x31, cnAttr));
  const validity = derTlv(
    0x30,
    Buffer.concat([
      derTlv(0x17, Buffer.from("260101000000Z", "ascii")),
      derTlv(0x17, Buffer.from("360101000000Z", "ascii")),
    ]),
  );
  const tbs = derTlv(
    0x30,
    Buffer.concat([
      derTlv(0xa0, derTlv(0x02, Buffer.from([0x02]))), // v3
      derTlv(0x02, Buffer.from([0x01])), // serialNumber = 1
      sigAlg,
      name,
      validity,
      name,
      spkiDer,
    ]),
  );
  const signer = createSign("SHA256");
  signer.update(tbs);
  const sig = signer.sign(privateKey);
  const certDer = derTlv(0x30, Buffer.concat([tbs, sigAlg, derTlv(0x03, Buffer.concat([Buffer.from([0x00]), sig]))]));
  // Sanity-check that Node's OpenSSL X509Certificate parser accepts it
  new X509Certificate(certDer);
  return { certDer, privateKey };
}

export function buildTestNpmSlsaAttestation(params: {
  packageName: string;
  version: string;
  tarballSha512Sri: string;
  tamperDigest?: boolean;
  tamperSignature?: boolean;
  overrideSubjectName?: string;
  omitCert?: boolean;
}): Record<string, unknown> {
  const { certDer, privateKey } = buildSelfSignedEcX509Der();
  const sha512Hex = Buffer.from(params.tarballSha512Sri.slice("sha512-".length), "base64").toString("hex");
  const digestHex = params.tamperDigest ? "0".repeat(128) : sha512Hex;
  const encodePurl = (n: string) => (n.startsWith("@") ? `%40${encodeURIComponent(n.slice(1)).replace(/%2F/gi, "/")}` : encodeURIComponent(n));
  const subjectName = params.overrideSubjectName ?? `pkg:npm/${encodePurl(params.packageName)}@${params.version}`;

  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: subjectName, digest: { sha512: digestHex } }],
    predicateType: "https://slsa.dev/provenance/v1",
    predicate: {
      buildDefinition: {
        buildType: "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1",
        externalParameters: { workflow: { repository: "https://github.com/example/pkg" } },
        resolvedDependencies: [{ uri: "git+https://github.com/example/pkg", digest: { gitCommit: "a".repeat(40) } }],
      },
      runDetails: { builder: { id: "https://github.com/actions/runner/github-hosted" } },
    },
  };

  const payloadType = "application/vnd.in-toto+json";
  const payloadBytes = Buffer.from(JSON.stringify(statement), "utf8");
  const ptBuf = Buffer.from(payloadType, "utf8");
  const pae = Buffer.concat([
    Buffer.from(`DSSEv1 ${ptBuf.length} `, "utf8"),
    ptBuf,
    Buffer.from(` ${payloadBytes.length} `, "utf8"),
    payloadBytes,
  ]);
  const signer = createSign("SHA256");
  signer.update(pae);
  const sigBuf = signer.sign(privateKey);
  if (params.tamperSignature && sigBuf.length > 4) {
    sigBuf[sigBuf.length - 1] = (sigBuf[sigBuf.length - 1]! ^ 0xff) & 0xff;
  }

  return {
    attestations: [
      {
        predicateType: "https://slsa.dev/provenance/v1",
        bundle: {
          mediaType: "application/vnd.dev.sigstore.bundle+json;version=0.2",
          verificationMaterial: params.omitCert
            ? { tlogEntries: [{ logIndex: "12345" }] }
            : {
                x509CertificateChain: { certificates: [{ rawBytes: certDer.toString("base64") }] },
                tlogEntries: [{ logIndex: "12345" }],
              },
          dsseEnvelope: {
            payloadType,
            payload: payloadBytes.toString("base64"),
            signatures: [{ sig: sigBuf.toString("base64") }],
          },
        },
      },
    ],
  };
}
