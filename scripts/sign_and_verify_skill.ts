#!/usr/bin/env node
/**
 * Cryptographic Skill Attestation Signer & Verifier (`skill.oms.sig`)
 * Modeled on NVIDIA Auto-Ontology's Sigstore Bundle v0.3 + in-toto DSSE v1.0 envelope
 * (`https://in-toto.io/Statement/v1`, `https://model_signing/signature/v1.0`, `allow_symlinks: false`).
 *
 * Uses Node 24 built-in `node:crypto` (ECDSA P-256 / SHA-256) with zero external packages.
 * Explicitly labels local signatures as `local-dev-self-signed`; production CI releases
 * replace the local key with Sigstore Fulcio keyless OIDC X.509 certificates.
 */

import { createHash, createSign, createVerify, generateKeyPairSync } from "node:crypto";
import { lstatSync, readdirSync, readFileSync, writeFileSync } from "node:fs";
import { join, relative, resolve } from "node:path";

const ROOT = resolve(import.meta.dirname, "..");
const SKILL_DIR = join(ROOT, "skill-src", "coldpin");
const SIG_PATH = join(SKILL_DIR, "skill.oms.sig");
const PAYLOAD_TYPE = "application/vnd.in-toto+json";

function collectSkillFiles(dir: string): Array<{ rel: string; full: string }> {
  const out: Array<{ rel: string; full: string }> = [];
  const walk = (cur: string) => {
    for (const name of readdirSync(cur).sort()) {
      const full = join(cur, name);
      const st = lstatSync(full);
      if (st.isSymbolicLink()) {
        throw new Error(`Symlink rejected in signed skill bundle (allow_symlinks=false): ${full}`);
      }
      if (st.isDirectory()) {
        walk(full);
      } else if (st.isFile()) {
        const rel = relative(dir, full).replace(/\\/g, "/");
        if (rel === "skill.oms.sig") continue;
        out.push({ rel, full });
      }
    }
  };
  walk(dir);
  return out.sort((a, b) => a.rel.localeCompare(b.rel));
}

function computeFileDigests(dir: string): {
  resources: Array<{ algorithm: "sha256"; name: string; digest: string }>;
  subjectDigest: string;
} {
  const files = collectSkillFiles(dir);
  const resources = files.map((f) => ({
    algorithm: "sha256" as const,
    name: f.rel,
    digest: createHash("sha256").update(readFileSync(f.full)).digest("hex"),
  }));
  const aggregate = createHash("sha256");
  for (const r of resources) {
    aggregate.update(`${r.name}:${r.digest}\n`);
  }
  return { resources, subjectDigest: aggregate.digest("hex") };
}

function dssePae(payloadType: string, payloadBytes: Buffer): Buffer {
  const ptBuf = Buffer.from(payloadType, "utf8");
  return Buffer.concat([
    Buffer.from(`DSSEv1 ${ptBuf.length} `, "utf8"),
    ptBuf,
    Buffer.from(` ${payloadBytes.length} `, "utf8"),
    payloadBytes,
  ]);
}

function signSkill(): void {
  const { resources, subjectDigest } = computeFileDigests(SKILL_DIR);
  const statement = {
    _type: "https://in-toto.io/Statement/v1",
    subject: [{ name: "coldpin", digest: { sha256: subjectDigest } }],
    predicateType: "https://model_signing/signature/v1.0",
    predicate: {
      serialization: {
        allow_symlinks: false,
        hash_type: "sha256",
        method: "files",
        ignore_paths: [".git", ".github", ".gitattributes", ".gitignore", "skill.oms.sig"],
      },
      resources,
    },
  };

  const payloadBytes = Buffer.from(JSON.stringify(statement, null, 2), "utf8");
  const pae = dssePae(PAYLOAD_TYPE, payloadBytes);
  const { publicKey, privateKey } = generateKeyPairSync("ec", { namedCurve: "prime256v1" });
  const signer = createSign("SHA256");
  signer.update(pae);
  const sigBase64 = signer.sign(privateKey).toString("base64");
  const pubPem = publicKey.export({ type: "spki", format: "pem" }).toString();
  const keyId = createHash("sha256").update(pubPem).digest("hex").slice(0, 16);

  const bundle = {
    mediaType: "application/vnd.dev.sigstore.bundle.v0.3+json",
    verificationMaterial: {
      trustTier: "local-dev-self-signed",
      note: "Local ECDSA P-256 verification key; replace with Sigstore Fulcio keyless OIDC X.509 certificate chain in production CI releases.",
      publicKeyPem: pubPem,
      keyId,
    },
    dsseEnvelope: {
      payload: payloadBytes.toString("base64"),
      payloadType: PAYLOAD_TYPE,
      signatures: [{ sig: sigBase64, keyid: keyId }],
    },
  };

  writeFileSync(SIG_PATH, `${JSON.stringify(bundle, null, 2)}\n`, "utf8");
  console.log(`SIGNED SKILL OK: ${resources.length} files attested -> skill.oms.sig (subject sha256=${subjectDigest.slice(0, 16)}..., keyid=${keyId})`);
}

function verifySkill(): void {
  const bundle = JSON.parse(readFileSync(SIG_PATH, "utf8")) as {
    mediaType: string;
    verificationMaterial: { trustTier: string; publicKeyPem: string; keyId: string };
    dsseEnvelope: { payload: string; payloadType: string; signatures: Array<{ sig: string; keyid: string }> };
  };

  if (bundle.dsseEnvelope.payloadType !== PAYLOAD_TYPE) {
    throw new Error(`Unexpected DSSE payloadType: ${bundle.dsseEnvelope.payloadType}`);
  }
  const payloadBytes = Buffer.from(bundle.dsseEnvelope.payload, "base64");
  const pae = dssePae(bundle.dsseEnvelope.payloadType, payloadBytes);
  const sigObj = bundle.dsseEnvelope.signatures[0];
  if (!sigObj) throw new Error("Missing DSSE signature");

  const verifier = createVerify("SHA256");
  verifier.update(pae);
  const sigValid = verifier.verify(bundle.verificationMaterial.publicKeyPem, Buffer.from(sigObj.sig, "base64"));
  if (!sigValid) {
    throw new Error("DSSE ECDSA P-256 signature verification FAILED");
  }

  const statement = JSON.parse(payloadBytes.toString("utf8")) as {
    subject: Array<{ name: string; digest: { sha256: string } }>;
    predicate: { resources: Array<{ name: string; digest: string }> };
  };

  const current = computeFileDigests(SKILL_DIR);
  const expectedMap = new Map(statement.predicate.resources.map((r) => [r.name, r.digest]));
  const actualMap = new Map(current.resources.map((r) => [r.name, r.digest]));

  const mismatches: string[] = [];
  for (const [name, digest] of expectedMap) {
    if (actualMap.get(name) !== digest) {
      mismatches.push(`Modified or missing attested file: ${name}`);
    }
  }
  for (const name of actualMap.keys()) {
    if (!expectedMap.has(name)) {
      mismatches.push(`Unattested extra file in skill directory: ${name}`);
    }
  }
  if (statement.subject[0]?.digest.sha256 !== current.subjectDigest) {
    mismatches.push("Aggregate subject SHA-256 mismatch");
  }

  if (mismatches.length > 0) {
    throw new Error(`Signature integrity mismatch:\n  - ${mismatches.join("\n  - ")}`);
  }

  console.log(
    `VERIFY SIG OK: ${current.resources.length} files verified (DSSE ECDSA P-256, trustTier=${bundle.verificationMaterial.trustTier}, subject=${current.subjectDigest.slice(0, 16)}...)`,
  );
}

const mode = process.argv[2] ?? "--verify";
if (mode === "--sign") {
  signSkill();
} else if (mode === "--verify") {
  verifySkill();
} else {
  console.error("Usage: node --no-warnings scripts/sign_and_verify_skill.ts [--sign | --verify]");
  process.exit(1);
}
