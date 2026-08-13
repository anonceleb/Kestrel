/**
 * link-check — verifies every external evidence link on the demo pages
 * actually resolves. Run in CI only (it needs the network); `npm run verify`
 * stays network-free.
 *
 * This exists because vercel.json sets outputDirectory: "web", so a
 * relative "../spec/..." link from a page under web/ resolves to nothing on
 * the deployed site even though it resolves locally. Links here are GitHub
 * blob URLs for exactly that reason — this script is what keeps them honest
 * as the repository moves.
 */
import { readdirSync, readFileSync } from "node:fs";
import { join } from "node:path";

const WEB_DIR = new URL("../../web/", import.meta.url).pathname;

const HREF_RE = /href="(https?:\/\/[^"]+)"/g;

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
const failures: string[] = [];

for (const [url, pages] of links) {
  const status = await checkLink(url);
  const ok = typeof status === "number" && status >= 200 && status < 400;
  console.log(`${ok ? "✔" : "✗"} ${url} — ${status} (${pages.join(", ")})`);
  if (!ok) failures.push(`${url} — ${status} (linked from ${pages.join(", ")})`);
}

if (failures.length) {
  console.error(`\nlink-check FAILED — ${failures.length} broken link(s)`);
  for (const f of failures) console.error("  ✗ " + f);
  process.exit(1);
}
console.log(`\nlink-check PASSED — ${links.size} external link(s) all resolve`);
