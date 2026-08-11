/**
 * tools/web-build — makes the browser demo run the real repo sources.
 *
 * No bundler, no npm dependencies. Two steps:
 *
 *  1. SELFTEST — the browser crypto shim (node-crypto-shim.js, pure JS) is
 *     verified against node:crypto itself, right here, before anything is
 *     emitted: digests compared byte-for-byte, HKDF outputs compared,
 *     ChaCha20-Poly1305 round-tripped in BOTH directions (node seals → shim
 *     opens, shim seals → node opens) plus tamper rejection, Ed25519
 *     cross-verified both ways plus DER export equality. Any mismatch
 *     aborts the build with a non-zero exit.
 *
 *  2. TRANSFORM — every .ts under packages/, services/, profiles/ and
 *     adapters/ is converted to a browser ES module using Node's own
 *     stripTypeScriptTypes (the same machinery `npm test` runs under; type
 *     positions become blanks, so code and comments are otherwise
 *     untouched), with exactly two textual rewrites:
 *       - import specifiers ending in .ts   →  .js
 *       - "node:crypto"                     →  the shim
 *     Each emitted file records the SHA-256 of the source it came from;
 *     web/assets/js/manifest.json lists all of them, so "the demo runs the
 *     repo's code" is a checkable claim, not a caption.
 */
import { readFileSync, writeFileSync, mkdirSync, rmSync, readdirSync, statSync } from "node:fs";
import { join, dirname, relative } from "node:path";
import { stripTypeScriptTypes } from "node:module";
import { createHash } from "node:crypto";
import * as nodeCrypto from "node:crypto";
import * as shim from "./node-crypto-shim.js";

const ROOT = join(import.meta.dirname, "..", "..");
const OUT = join(ROOT, "web", "assets", "js");
const SRC_DIRS = ["packages", "services", "profiles", "adapters"];

/* ------------------------------------------------------------- selftest */

let checks = 0;
function eq(name: string, a: string, b: string): void {
  checks++;
  if (a !== b) {
    console.error(`SELFTEST FAIL: ${name}\n  node: ${a}\n  shim: ${b}`);
    process.exit(1);
  }
}
function ok(name: string, cond: boolean): void {
  checks++;
  if (!cond) {
    console.error(`SELFTEST FAIL: ${name}`);
    process.exit(1);
  }
}

function selftest(): void {
  // Digests + HMAC over random inputs of awkward lengths (block boundaries).
  for (const len of [0, 1, 55, 56, 63, 64, 65, 111, 112, 127, 128, 129, 1000]) {
    const data = nodeCrypto.randomBytes(len);
    for (const alg of ["sha256", "sha512", "blake2b512"] as const) {
      eq(
        `${alg} len=${len}`,
        nodeCrypto.createHash(alg).update(data).digest("hex"),
        shim.createHash(alg).update(shim.Buffer.from(data)).digest("hex"),
      );
    }
    const key = nodeCrypto.randomBytes(37);
    eq(
      `hmac-sha256 len=${len}`,
      nodeCrypto.createHmac("sha256", key).update(data).digest("base64url"),
      shim.createHmac("sha256", shim.Buffer.from(key)).update(shim.Buffer.from(data)).digest("base64url"),
    );
  }

  // HKDF
  const ikm = nodeCrypto.randomBytes(32), salt = nodeCrypto.randomBytes(16);
  eq(
    "hkdf-sha256",
    Buffer.from(nodeCrypto.hkdfSync("sha256", ikm, salt, Buffer.from("cfp/selftest"), 32)).toString("hex"),
    shim.Buffer.from(shim.hkdfSync("sha256", shim.Buffer.from(ikm), shim.Buffer.from(salt), shim.Buffer.from("cfp/selftest"), 32)).toString("hex"),
  );

  // ChaCha20-Poly1305: node seals → shim opens
  const key = nodeCrypto.randomBytes(32), nonce = nodeCrypto.randomBytes(12);
  const aad = Buffer.from("tenant|record");
  const pt = Buffer.from("the plaintext that must round-trip exactly");
  const c1 = nodeCrypto.createCipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
  c1.setAAD(aad);
  const ct1 = Buffer.concat([c1.update(pt), c1.final()]);
  const tag1 = c1.getAuthTag();
  {
    const d = shim.createDecipheriv("chacha20-poly1305", shim.Buffer.from(key), shim.Buffer.from(nonce), { authTagLength: 16 });
    d.setAAD(shim.Buffer.from(aad));
    d.setAuthTag(shim.Buffer.from(tag1));
    d.update(shim.Buffer.from(ct1));
    eq("aead node→shim", pt.toString("hex"), d.final().toString("hex"));
  }
  // shim seals → node opens
  {
    const c2 = shim.createCipheriv("chacha20-poly1305", shim.Buffer.from(key), shim.Buffer.from(nonce), { authTagLength: 16 });
    c2.setAAD(shim.Buffer.from(aad));
    c2.update(shim.Buffer.from(pt));
    const ct2 = c2.final();
    const tag2 = c2.getAuthTag();
    eq("aead ct equality", ct1.toString("hex"), ct2.toString("hex"));
    eq("aead tag equality", tag1.toString("hex"), tag2.toString("hex"));
    const d2 = nodeCrypto.createDecipheriv("chacha20-poly1305", key, nonce, { authTagLength: 16 });
    d2.setAAD(aad);
    d2.setAuthTag(Buffer.from(tag2));
    eq("aead shim→node", pt.toString("hex"), Buffer.concat([d2.update(Buffer.from(ct2)), d2.final()]).toString("hex"));
  }
  // tamper rejection
  {
    const d = shim.createDecipheriv("chacha20-poly1305", shim.Buffer.from(key), shim.Buffer.from(nonce), { authTagLength: 16 });
    d.setAAD(shim.Buffer.from(Buffer.from("wrong|aad")));
    d.setAuthTag(shim.Buffer.from(tag1));
    d.update(shim.Buffer.from(ct1));
    let threw = false;
    try {
      d.final();
    } catch {
      threw = true;
    }
    ok("aead tamper rejected by shim", threw);
  }

  // Ed25519: node keypair → shim imports, cross-verifies both directions.
  const { publicKey, privateKey } = nodeCrypto.generateKeyPairSync("ed25519");
  const spki = publicKey.export({ type: "spki", format: "der" });
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" });
  const msg = Buffer.from("(created): 1\n(expires): 2\ndigest: BLAKE-512=abc");
  const nodeSig = nodeCrypto.sign(null, msg, privateKey);
  const shimPriv = shim.createPrivateKey({ key: shim.Buffer.from(pkcs8), type: "pkcs8", format: "der" });
  const shimPub = shim.createPublicKey({ key: shim.Buffer.from(spki), type: "spki", format: "der" });
  ok("ed25519 node-sig verifies under shim", shim.verify(null, shim.Buffer.from(msg), shimPub, shim.Buffer.from(nodeSig)));
  const shimSig = shim.sign(null, shim.Buffer.from(msg), shimPriv);
  eq("ed25519 deterministic sig equality", nodeSig.toString("hex"), shim.Buffer.from(shimSig).toString("hex"));
  ok("ed25519 shim-sig verifies under node", nodeCrypto.verify(null, msg, publicKey, Buffer.from(shimSig)));
  ok(
    "ed25519 rejects a flipped bit",
    !shim.verify(null, shim.Buffer.from(Buffer.concat([msg, Buffer.from("x")])), shimPub, shim.Buffer.from(nodeSig)),
  );
  // shim-generated keypair round-trips through node's DER parsers
  const kp = shim.generateKeyPairSync("ed25519");
  const nodePub = nodeCrypto.createPublicKey({
    key: Buffer.from(kp.publicKey.export({ type: "spki", format: "der" })),
    type: "spki",
    format: "der",
  });
  const sig2 = shim.sign(null, shim.Buffer.from(msg), kp.privateKey);
  ok("shim keypair verifies under node", nodeCrypto.verify(null, msg, nodePub, Buffer.from(sig2)));

  console.log(`selftest: ${checks} shim↔node:crypto equivalence checks passed`);
}

/* ------------------------------------------------------------ transform */

function walk(dir: string): string[] {
  const out: string[] = [];
  for (const name of readdirSync(dir)) {
    const p = join(dir, name);
    if (statSync(p).isDirectory()) out.push(...walk(p));
    else if (p.endsWith(".ts")) out.push(p);
  }
  return out;
}

function transform(): void {
  rmSync(OUT, { recursive: true, force: true });
  const manifest: { source: string; emitted: string; sourceSha256: string }[] = [];

  const files = SRC_DIRS.flatMap((d) => walk(join(ROOT, d)));
  for (const file of files) {
    const rel = relative(ROOT, file); // e.g. packages/capability/src/capability.ts
    const src = readFileSync(file, "utf8");
    const sha = createHash("sha256").update(src).digest("hex");

    let js = stripTypeScriptTypes(src, { mode: "strip" });

    const depth = rel.split("/").length - 1;
    const shimPath = "../".repeat(depth) + "node-crypto.js";
    js = js
      .replace(/(["'])node:crypto\1/g, JSON.stringify(shimPath))
      .replace(/((?:from\s*|import\s*\(\s*)["'][^"']*)\.ts(["'])/g, "$1.js$2");

    const header =
      `// GENERATED by tools/web-build/build.ts — do not edit.\n` +
      `// Source: ${rel} (sha256 ${sha})\n` +
      `// Transform: Node stripTypeScriptTypes + import-specifier rewrite (.ts→.js, node:crypto→shim). Nothing else.\n` +
      `import ${JSON.stringify(shimPath)};\n`;

    const outPath = join(OUT, rel.replace(/\.ts$/, ".js"));
    mkdirSync(dirname(outPath), { recursive: true });
    writeFileSync(outPath, header + js);
    manifest.push({ source: rel, emitted: relative(ROOT, outPath), sourceSha256: sha });
  }

  const shimSrc = readFileSync(join(import.meta.dirname, "node-crypto-shim.js"), "utf8");
  writeFileSync(join(OUT, "node-crypto.js"), shimSrc);

  writeFileSync(
    join(OUT, "manifest.json"),
    JSON.stringify(
      {
        generatedAt: new Date().toISOString(),
        selftestChecks: checks,
        note:
          "Each emitted module is the named repo source with types stripped and import specifiers rewritten. " +
          "node-crypto.js is the browser shim, verified against node:crypto by tools/web-build/build.ts before emit.",
        files: manifest,
      },
      null,
      2,
    ),
  );
  console.log(`emitted ${manifest.length} modules + shim → web/assets/js/`);
}

selftest();
transform();
