/**
 * link-check — verifies every external evidence link on the demo pages and
 * in the repo's root markdown resolves, and every relative markdown link
 * points at a file that actually exists. Run in CI only (it needs the
 * network for the external half); `npm run verify` stays network-free.
 *
 * This exists because vercel.json sets outputDirectory: "web", so a
 * relative "../spec/..." link from a page under web/ resolves to nothing on
 * the deployed site even though it resolves locally. Links here are GitHub
 * blob URLs for exactly that reason — this script is what keeps them honest
 * as the repository moves. The relative-file check separately catches the
 * markdown equivalent — a doc linked from DPG.md/README.md that isn't
 * actually tracked (e.g. sits under a gitignored path) 404s on GitHub even
 * though it "resolves" on the author's own disk.
 */
import { execFileSync } from "node:child_process";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join, relative } from "node:path";

const ROOT_DIR = new URL("../../", import.meta.url).pathname;
const WEB_DIR = join(ROOT_DIR, "web");

// git-tracked, not just present on disk: a gitignored file (e.g. under doc/)
// can exist locally and pass a filesystem check while still 404ing on
// GitHub, which is exactly the bug this script exists to catch.
const TRACKED_FILES = new Set(
  execFileSync("git", ["ls-files"], { cwd: ROOT_DIR, encoding: "utf8" })
    .trim()
    .split("\n"),
);

const HREF_RE = /href="(https?:\/\/[^"]+)"/g;
const MD_LINK_RE = /\[[^\]]*\]\(([^)]+)\)/g;

function collectLinks(): Map<string, string[]> {
  const links = new Map<string, string[]>();
  for (const entry of readdirSync(WEB_DIR)) {
    if (!entry.endsWith(".html")) continue;
    const src = readFileSync(join(WEB_DIR, entry), "utf8");
    for (const m of src.matchAll(HREF_RE)) {
      const url = m[1]!;
      if (!links.has(url)) links.set(url, []);
      links.get(url)!.push(entry);
    }
  }
  return links;
}

function collectMarkdownFiles(): string[] {
  return readdirSync(ROOT_DIR).filter((f) => f.endsWith(".md"));
}

function checkMarkdownLinks(): {
  external: Map<string, string[]>;
  brokenRelative: string[];
} {
  const external = new Map<string, string[]>();
  const brokenRelative: string[] = [];
  for (const entry of collectMarkdownFiles()) {
    const src = readFileSync(join(ROOT_DIR, entry), "utf8");
    for (const m of src.matchAll(MD_LINK_RE)) {
      const target = m[1]!;
      if (/^https?:\/\//.test(target)) {
        if (!external.has(target)) external.set(target, []);
        external.get(target)!.push(entry);
        continue;
      }
      if (target.startsWith("#") || target.startsWith("mailto:")) continue;
      const clean = target.split("#")[0]!;
      const resolved = relative(ROOT_DIR, join(dirname(join(ROOT_DIR, entry)), clean));
      if (!TRACKED_FILES.has(resolved)) {
        brokenRelative.push(`${target} (linked from ${entry}) — not a git-tracked file`);
      }
    }
  }
  return { external, brokenRelative };
}

async function checkLink(url: string): Promise<number | string> {
  try {
    const res = await fetch(url, { method: "HEAD", redirect: "follow" });
    if (res.status === 405 || res.status === 501) {
      const getRes = await fetch(url, { method: "GET", redirect: "follow" });
      return getRes.status;
    }
    return res.status;
  } catch (err) {
    return String(err);
  }
}

const links = collectLinks();
const { external: mdExternal, brokenRelative } = checkMarkdownLinks();
for (const [url, pages] of mdExternal) {
  if (!links.has(url)) links.set(url, []);
  for (const p of pages) links.get(url)!.push(p);
}

const failures: string[] = [];

for (const [url, pages] of links) {
  const status = await checkLink(url);
  const ok = typeof status === "number" && status >= 200 && status < 400;
  console.log(`${ok ? "✔" : "✗"} ${url} — ${status} (${pages.join(", ")})`);
  if (!ok) failures.push(`${url} — ${status} (linked from ${pages.join(", ")})`);
}

for (const b of brokenRelative) {
  console.log(`✗ ${b}`);
  failures.push(b);
}

if (failures.length) {
  console.error(`\nlink-check FAILED — ${failures.length} broken link(s)`);
  for (const f of failures) console.error("  ✗ " + f);
  process.exit(1);
}
console.log(
  `\nlink-check PASSED — ${links.size} external link(s) and all markdown-relative links resolve`,
);
