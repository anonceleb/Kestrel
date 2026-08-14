/**
 * spec-check — makes the published interface note answerable to the types.
 *
 * `spec/CFP-v0.x.md` §2 prints the `Caveats` shape. It drifted twice: once on
 * `purpose` (the spec kept a `"redirect"` value no code path produced) and
 * once on `channelKind` (`"door"` against the code's `"direct"`), and the
 * drift survived several revisions because nothing compared them. An
 * integrator implementing the spec would have minted tokens this repo
 * rejects — the worst class of documentation bug, because it fails at the
 * other party's expense.
 *
 * The type is the single source of truth. This check parses both and exits
 * non-zero on any difference, so the spec cannot silently fall behind again.
 *
 * Deliberately narrow: it compares the field names and the string-literal
 * unions, not the whole grammar. A parser that understood everything would
 * itself be a thing that drifts.
 */
import { readFileSync } from "node:fs";

const ROOT = new URL("../../", import.meta.url).pathname;

function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, "").replace(/\/\/[^\n]*/g, "");
}

/** Field names, in declaration order, plus any string-literal union per field. */
type Shape = { fields: string[]; unions: Record<string, string[]> };

function parseShape(block: string): Shape {
  const fields: string[] = [];
  const unions: Record<string, string[]> = {};
  for (const raw of stripComments(block).split("\n")) {
    const line = raw.trim();
    const m = /^([A-Za-z_][A-Za-z0-9_]*)\s*:\s*(.+?),?$/.exec(line);
    if (!m) continue;
    const [, name, type] = m;
    fields.push(name!);
    const literals = [...type!.matchAll(/"([^"]+)"/g)].map((x) => x[1]!);
    if (literals.length) unions[name!] = literals.sort();
  }
  return { fields: fields.sort(), unions };
}

function between(src: string, open: string, close: string, from = 0): string {
  const a = src.indexOf(open, from);
  if (a === -1) throw new Error(`spec-check: could not find ${JSON.stringify(open)}`);
  const b = src.indexOf(close, a + open.length);
  if (b === -1) throw new Error(`spec-check: could not find ${JSON.stringify(close)} after it`);
  return src.slice(a + open.length, b);
}

const code = readFileSync(`${ROOT}packages/capability/src/capability.ts`, "utf8");
const spec = readFileSync(`${ROOT}spec/CFP-v0.x.md`, "utf8");

const fromCode = parseShape(between(code, "export type Caveats = {", "\n};"));
// §2's fenced block prints the whole grant; the caveat set is the inner brace.
const specBlock = between(spec, "## 2. Token format", "```", spec.indexOf("## 2. Token format"));
const fromSpec = parseShape(between(spec, "caveats: {", "},", spec.indexOf("## 2. Token format")));

const problems: string[] = [];

const missingFromSpec = fromCode.fields.filter((f) => !fromSpec.fields.includes(f));
const extraInSpec = fromSpec.fields.filter((f) => !fromCode.fields.includes(f));
if (missingFromSpec.length) problems.push(`spec §2 is missing caveat(s): ${missingFromSpec.join(", ")}`);
if (extraInSpec.length) problems.push(`spec §2 documents caveat(s) the type does not have: ${extraInSpec.join(", ")}`);

for (const [field, codeLiterals] of Object.entries(fromCode.unions)) {
  const specLiterals = fromSpec.unions[field];
  if (!specLiterals) continue; // spec may describe a field without enumerating it
  if (JSON.stringify(specLiterals) !== JSON.stringify(codeLiterals)) {
    problems.push(
      `caveat "${field}": type allows [${codeLiterals.join(", ")}] but spec §2 says [${specLiterals.join(", ")}]`,
    );
  }
}

if (problems.length) {
  console.error("spec-check FAILED — spec/CFP-v0.x.md §2 disagrees with packages/capability's Caveats type.");
  console.error("The type is the source of truth; update the spec.\n");
  for (const p of problems) console.error(`  • ${p}`);
  process.exit(1);
}

console.log(`spec-check passed — §2 matches Caveats (${fromCode.fields.length} fields, ${Object.keys(fromCode.unions).length} enumerated).`);
void specBlock;
