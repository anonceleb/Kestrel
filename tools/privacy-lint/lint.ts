/**
 * privacy-lint — a CI gate, not a linter suggestion.
 *
 * Four checks:
 *   1. packages/core may not import from adapters/ or services/. This is what
 *      keeps the standards-agnostic claim honest rather than aspirational.
 *   2. No PII-shaped identifier may appear in a Zone 3 (counterparty-facing)
 *      type or in any logging call.
 *   3. [Gap fix — closes web/candid-books.html gap 3, "Adapter log-hygiene coverage"] The
 *      log-hygiene scan now also walks adapters/ and profiles/, not just
 *      packages/ and services/ — closing the one directory whose code is
 *      most likely to legitimately touch plaintext.
 *   4. [New] No address-shaped identifier may appear in an `export type` /
 *      `export interface` declaration under packages/, outside profiles/.
 *      This is the structural check behind the renaming: the generic core
 *      may not smuggle address vocabulary back in through a type name.
 */
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join } from "node:path";

const ROOT = new URL("../../", import.meta.url).pathname;

// CFP_LINT_EXTRA_LOG_DIR adds one more directory to check 3's log-hygiene
// walk, outside this repository (e.g. under os.tmpdir()). This lets a test
// prove the log-hygiene scan catches a violation without ever writing a
// probe file into the tree being linted.
const EXTRA_LOG_DIR = process.env.CFP_LINT_EXTRA_LOG_DIR;

// CFP_LINT_EXTRA_TYPE_DIR does the same for check 4 (address-shaped
// identifiers in exported types), so the four evasion probes can be tested
// as fixtures without writing into packages/.
const EXTRA_TYPE_DIR = process.env.CFP_LINT_EXTRA_TYPE_DIR;

const PII_SHAPED = [
  "address", "line1", "line2", "street", "postcode", "postalcode",
  "fullname", "firstname", "lastname", "phone", "msisdn", "email",
  "nationalid", "dob", "dateofbirth", "latitude", "longitude", "geocode",
];

/** Address-shaped field/identifier names that must not appear in the generic core's exported types. */
const ADDRESS_SHAPED_FIELDS = [
  "address", "line1", "line2", "street", "postcode", "postalcode", "locality", "placename",
];

function walk(dir: string, out: string[] = []): string[] {
  for (const e of readdirSync(dir)) {
    if (e === "node_modules" || e.startsWith(".")) continue;
    const p = join(dir, e);
    if (statSync(p).isDirectory()) walk(p, out);
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

function exists(p: string): boolean {
  try {
    statSync(p);
    return true;
  } catch {
    return false;
  }
}

const failures: string[] = [];

// --- check 1: core purity -------------------------------------------------
for (const f of walk(join(ROOT, "packages/core"))) {
  const src = readFileSync(f, "utf8");
  for (const m of src.matchAll(/from\s+["']([^"']+)["']/g)) {
    const spec = m[1]!;
    if (spec.includes("adapters/") || spec.includes("services/")) {
      failures.push(`core purity: ${f} imports ${spec}`);
    }
  }
}

// --- check 2: no PII-shaped fields in Zone 3 projections ------------------
const ZONE3_TYPES: Array<{ file: string; type: string }> = [
  { file: "packages/core/src/core.ts", type: "MerchantView" },
  { file: "packages/sdk/src/client.ts", type: "GrantResult" },
  { file: "packages/webhooks/src/webhook.ts", type: "CheckoutCompletedPayload" },
];
for (const { file, type } of ZONE3_TYPES) {
  const src = readFileSync(join(ROOT, file), "utf8");
  const body = src.match(new RegExp(`export type ${type} = \\{([\\s\\S]*?)\\};`))?.[1] ?? "";
  if (!body) {
    failures.push(`zone3 check misconfigured: ${type} not found in ${file}`);
    continue;
  }
  for (const field of body.matchAll(/^\s*(\w+)\??:/gm)) {
    const name = field[1]!.toLowerCase();
    if (PII_SHAPED.some((p) => name.includes(p))) {
      failures.push(`zone3 leakage: ${type}.${field[1]} (${file}) is PII-shaped`);
    }
  }
}

// --- check 3: no raw identifiers in log statements -------------------------
// [Gap fix] Now walks packages/, services/, adapters/, and profiles/.
const logDirs = ["packages", "services", "adapters", "profiles"]
  .map((d) => join(ROOT, d))
  .filter(exists);
if (EXTRA_LOG_DIR && exists(EXTRA_LOG_DIR)) logDirs.push(EXTRA_LOG_DIR);
for (const d of logDirs) {
  for (const f of walk(d)) {
    const src = readFileSync(f, "utf8");
    for (const m of src.matchAll(/console\.(log|info|warn|error)\(([^)]*)\)/g)) {
      const args = m[2]!.toLowerCase();
      const hit = PII_SHAPED.find((p) => args.includes(p));
      if (hit) failures.push(`log leakage: ${f} logs '${hit}'`);
    }
  }
}

// --- check 4: no address-shaped identifiers in packages/'s exported types --
// (outside profiles/, which is where the address profile's concrete
// ConfidentialPayload shape is deliberately allowed to live).
const typeDirs = [join(ROOT, "packages")].filter(exists);
if (EXTRA_TYPE_DIR && exists(EXTRA_TYPE_DIR)) typeDirs.push(EXTRA_TYPE_DIR);
for (const typeDir of typeDirs) {
  for (const f of walk(typeDir)) {
    const src = readFileSync(f, "utf8");
    // Body terminator is `\}` (any whitespace before it), not `\n\}` — a
    // single-line declaration (`export type Foo = { address: string };`)
    // has no newline before its closing brace and was previously invisible
    // to this check entirely.
    for (const decl of src.matchAll(/export\s+(?:type|interface)\s+(\w+)[^{]*\{([\s\S]*?)\s*\}/g)) {
      const [, typeName, body] = decl;
      if (ADDRESS_SHAPED_FIELDS.some((p) => typeName!.toLowerCase().includes(p))) {
        failures.push(`address-shaped type name in core: ${typeName} (${f})`);
      }
      for (const field of body!.matchAll(/(\w+)\??:/g)) {
        const name = field[1]!.toLowerCase();
        // Substring match, matching check 2's PII_SHAPED behaviour — exact
        // membership let deliveryAddress, postalCode and street_name evade
        // this check entirely, single-line or not.
        if (ADDRESS_SHAPED_FIELDS.some((p) => name.includes(p))) {
          failures.push(`address-shaped identifier in core: ${typeName}.${field[1]} (${f})`);
        }
      }
    }
  }
}

if (failures.length) {
  console.error("privacy-lint FAILED");
  for (const f of failures) console.error("  ✗ " + f);
  process.exit(1);
}
console.log("privacy-lint PASSED — core is pure, zone 3 is clean, logs carry no identifiers, no address vocabulary leaked into packages/");
