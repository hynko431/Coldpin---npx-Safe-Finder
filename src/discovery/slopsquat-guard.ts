import { levenshtein } from "../config/policy.ts";
import type { Observation, PolicyConfig } from "../types.ts";

/**
 * High-value npm CLI & core ecosystem target corpus for offline 7-primitive typosquat screening.
 * Kept intentionally focused on high-target npx CLIs and core libraries to prevent false positives.
 */
export const TOP_NPM_TARGETS: readonly string[] = [
  "eslint",
  "prettier",
  "typescript",
  "create-react-app",
  "create-next-app",
  "create-vite",
  "create-astro",
  "create-svelte",
  "cross-env",
  "nodemon",
  "concurrently",
  "rimraf",
  "http-server",
  "live-server",
  "serve",
  "ngrok",
  "playwright",
  "cypress",
  "vitest",
  "jest",
  "mocha",
  "webpack",
  "esbuild",
  "rollup",
  "parcel",
  "turbo",
  "nx",
  "lerna",
  "changesets",
  "semantic-release",
  "husky",
  "lint-staged",
  "commitlint",
  "storybook",
  "prisma",
  "drizzle-kit",
  "supabase",
  "firebase-tools",
  "wrangler",
  "vercel",
  "netlify-cli",
  "aws-cdk",
  "serverless",
  "tailwindcss",
  "postcss",
  "autoprefixer",
  "shadcn",
  "degit",
  "tiged",
  "taze",
  "npm-check-updates",
  "depcheck",
  "madge",
  "knip",
  "biome",
  "oxlint",
  "tsx",
  "ts-node",
  "lodash",
  "axios",
  "express",
  "commander",
  "yargs",
  "inquirer",
  "chalk",
  "ora",
  "dotenv",
  "semver",
  "uuid",
  "zod",
  "react",
  "next",
  "vite",
  "astro",
  "svelte",
  "vue",
  "angular",
  "electron",
  "puppeteer",
  "sharp",
  "bcrypt",
  "jsonwebtoken",
  "mongoose",
  "sequelize",
  "typeorm",
  "socket.io",
  "graphql",
  "apollo",
  "trpc",
  "hono",
  "fastify",
  "koa",
  "nestjs",
  "renovate",
  "snyk",
  "trivy",
  "rea-agents",
];

const HOMOGLYPH_MAP: Record<string, string> = {
  "0": "o",
  "1": "l",
  "3": "e",
  "4": "a",
  "5": "s",
  "7": "t",
  rn: "m",
  vv: "w",
};

function normalizeHomoglyphs(name: string): string {
  let out = name.toLowerCase();
  for (const [k, v] of Object.entries(HOMOGLYPH_MAP)) {
    out = out.replaceAll(k, v);
  }
  return out;
}

function stripDelimiters(name: string): string {
  return name.toLowerCase().replace(/[-_.]/g, "");
}

function sortedTokens(name: string): string {
  return name
    .toLowerCase()
    .split(/[-_.]/)
    .filter(Boolean)
    .sort()
    .join("-");
}

function stripCommonSuffix(name: string): string {
  return name.toLowerCase().replace(/-(js|ts|cli|node|npm|pkg|official|lib)$/, "");
}

function isSingleTransposition(a: string, b: string): boolean {
  if (a.length !== b.length || a.length < 3) return false;
  const diffs: number[] = [];
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) diffs.push(i);
    if (diffs.length > 2) return false;
  }
  if (diffs.length !== 2) return false;
  const i0 = diffs[0]!;
  const i1 = diffs[1]!;
  return i1 === i0 + 1 && a[i0] === b[i1] && a[i1] === b[i0];
}

export interface SquatMatch {
  target: string;
  primitive:
    | "transposition"
    | "omission_or_repetition"
    | "delimiter_swap"
    | "word_order"
    | "homoglyph"
    | "suffix_brandjack";
}

/**
 * Checks a candidate npm package name against all 7 canonical typosquatting primitives
 * while suppressing false positives on short names (< 5 chars).
 */
export function detectTyposquatPrimitives(
  rawPackageName: string,
  corpus: readonly string[] = TOP_NPM_TARGETS,
): SquatMatch | null {
  // Strip @scope/ for bare-name comparison, unless exact scoped match is checked separately
  const bare = rawPackageName.includes("/")
    ? rawPackageName.slice(rawPackageName.indexOf("/") + 1).toLowerCase()
    : rawPackageName.toLowerCase();

  // Minimum length guard prevents flagging legitimate short CLIs (tsx, zx, vit, bun)
  if (bare.length < 5) return null;

  const corpusSet = new Set(corpus.map((c) => c.toLowerCase()));
  if (corpusSet.has(bare)) return null;

  const bareNoDelim = stripDelimiters(bare);
  const bareSorted = sortedTokens(bare);
  const bareHomoglyph = normalizeHomoglyphs(bare);
  const bareNoSuffix = stripCommonSuffix(bare);

  for (const target of corpus) {
    const t = target.toLowerCase();
    if (t.length < 5 || bare === t) continue;

    // 1. Transposition (e.g. reqeusts -> requests, loadsh -> lodash)
    if (isSingleTransposition(bare, t)) {
      return { target: t, primitive: "transposition" };
    }
    // 2. Delimiter swap (e.g. crossenv -> cross-env, create_react_app -> create-react-app)
    if (bareNoDelim === stripDelimiters(t) && bare !== t) {
      return { target: t, primitive: "delimiter_swap" };
    }
    // 3. Word order swap (e.g. env-cross -> cross-env, server-http -> http-server)
    if (bare.includes("-") && t.includes("-") && bareSorted === sortedTokens(t) && bare !== t) {
      return { target: t, primitive: "word_order" };
    }
    // 4. Homoglyph substitution (e.g. es1int -> eslint, pr3ttier -> prettier)
    if (bareHomoglyph === normalizeHomoglyphs(t) && bare !== t) {
      return { target: t, primitive: "homoglyph" };
    }
    // 5. Suffix / brandjacking (e.g. lodash-js, eslint-official, prettier-cli)
    if (bareNoSuffix === t && bare !== t) {
      return { target: t, primitive: "suffix_brandjack" };
    }
    // 6 & 7. Omission / Repetition / 1-edit substitution (Levenshtein == 1)
    if (levenshtein(bare, t) === 1) {
      return { target: t, primitive: "omission_or_repetition" };
    }
  }

  return null;
}

export function evaluateSlopsquatAndCooldown(params: {
  package_name: string;
  created_at_iso?: string;
  version_published_at_iso?: string;
  weekly_downloads?: number;
  has_lifecycle_scripts: boolean;
  policy: PolicyConfig;
  now_ms?: number;
}): Observation[] {
  const obs: Observation[] = [];
  const now = params.now_ms ?? Date.now();

  const squat = detectTyposquatPrimitives(params.package_name);
  if (squat) {
    const lowDownloads = params.weekly_downloads !== undefined && params.weekly_downloads < 1000;
    const isYoung =
      params.created_at_iso !== undefined &&
      now - Date.parse(params.created_at_iso) < 90 * 24 * 3600 * 1000;
    const severity = lowDownloads || isYoung || params.has_lifecycle_scripts ? "CRITICAL" : "HIGH";
    obs.push({
      code: "TYPOSQUAT_OR_SLOPSQUAT_MATCH",
      severity,
      path: "<registry-metadata>",
      attack_id: "T1195.002",
      detail: `Package '${params.package_name}' matches popular target '${squat.target}' via '${squat.primitive}' mutation.`,
    });
  }

  if (params.version_published_at_iso) {
    const pubMs = Date.parse(params.version_published_at_iso);
    if (Number.isFinite(pubMs)) {
      const ageHours = (now - pubMs) / (3600 * 1000);
      if (ageHours >= 0 && ageHours < params.policy.cooldown_hours) {
        obs.push({
          code: "RELEASE_COOLDOWN_QUARANTINE",
          severity: "MEDIUM",
          path: "<registry-metadata>",
          attack_id: "T1195.002",
          detail: `Release age is ${ageHours.toFixed(1)}h, below enterprise cooldown policy (${params.policy.cooldown_hours}h).`,
        });
      }
    }
  }

  if (
    params.created_at_iso &&
    params.weekly_downloads !== undefined &&
    now - Date.parse(params.created_at_iso) < 30 * 24 * 3600 * 1000 &&
    params.weekly_downloads < 100 &&
    params.has_lifecycle_scripts
  ) {
    obs.push({
      code: "SLOPSQUAT_YOUNG_WITH_HOOKS",
      severity: "HIGH",
      path: "<registry-metadata>",
      attack_id: "T1608.001",
      detail: `Brand-new low-adoption package (<30d old, ${params.weekly_downloads} weekly downloads) defines install lifecycle scripts.`,
    });
  }

  return obs;
}
