#!/usr/bin/env node
// Compares two manifest.json files for content equality, ignoring
// `generatedAt` — a wall-clock timestamp that differs on every build
// regardless of source content. Used by CI's demo-freshness job so it
// fails on real drift only, never on the timestamp alone.
//
// Usage: node compare-manifest.mjs <committed.json> <freshly-built.json>
import { readFileSync } from "node:fs";

const [, , a, b] = process.argv;
if (!a || !b) {
  console.error("usage: compare-manifest.mjs <committed.json> <freshly-built.json>");
  process.exit(2);
}

function stripped(path) {
  const j = JSON.parse(readFileSync(path, "utf8"));
  delete j.generatedAt;
  return JSON.stringify(j, null, 2);
}

const left = stripped(a);
const right = stripped(b);

if (left !== right) {
  console.error(
    "web/assets/js/manifest.json content is stale (ignoring generatedAt) — run 'npm run build:web' and commit the result.",
  );
  process.exit(1);
}

console.log("manifest.json content matches (generatedAt excluded).");
