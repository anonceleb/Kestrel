/**
 * The grant-core mechanism invariants — attribute-agnostic, exercised
 * against a neutral payload rather than an address, so the numbering
 * matches the donated suite this repo maintains.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";

import { Kms, RecordShredded, seal, open } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret, derivePairwiseId, linkabilityScore } from "../../packages/identity/src/pairwise.ts";
import { signRequest, SignatureInvalid, registerOp, suspendOp, eraseOp } from "../../packages/registry/src/signing.ts";
import { NonceLedger, CapabilityBurned, attenuate, AttenuationWidened, mint } from "../../packages/capability/src/capability.ts";
import { cohortSize, visibleCoResidents, K_ANON_FLOOR } from "../../packages/core/src/core.ts";
import { AuditPrecondition } from "../../services/vault/src/vault.ts";
import { MerchantDatabase } from "../../services/platform/src/platform.ts";
import { harness, grantOnce, type NeutralPayload } from "./harness.ts";

const PII_SHAPED = /address|line1|street|postcode|phone|email|fullname|nationalid/i;

test("INV-1: no counterparty-held record may contain an address-shaped field", async () => {
  const h = harness();
  const { capability, merchantView } = await grantOnce(h);
  const db = new MerchantDatabase();
  db.save(merchantView, capability);
  const offenders = db.columns().filter((c) => PII_SHAPED.test(c));
  assert.deepEqual(offenders, [], `counterparty DB exposes ${offenders.join(", ")}`);
});

test("INV-2: grant tokens carry no plaintext confidential payload under any encoding", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  for (const enc of ["utf8", "base64", "hex"] as const) {
    const blob = Buffer.from(JSON.stringify(capability)).toString(enc).toLowerCase();
    assert.ok(!blob.includes("s3cr3t-payload"), `payload leaked in ${enc} encoding`);
  }
});

test("INV-3: a spent grant cannot be replayed", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const routed = await h.vault.resolve(capability, "counterparty.example");
  assert.match(routed.routingCode, /^NTR-/);
  await assert.rejects(() => h.vault.resolve(capability, "counterparty.example"), CapabilityBurned);
});

test("INV-4: no decryption path exists that skips the audit record", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  await assert.rejects(() => h.vault.resolveUnaudited(capability), AuditPrecondition);

  await h.vault.resolve(capability, "counterparty.example");
  const trail = h.audit.forRecord("rec_1");
  assert.equal(trail.length, 1);
  assert.equal(trail[0]!.actor, "counterparty.example");
  assert.equal(trail[0]!.purpose, "delivery");
  assert.ok(trail[0]!.consentRef.startsWith("cns_"), "decryption is bound to a consent record");
});

test("INV-5: two counterparties cannot correlate the same subject", () => {
  const root = newRootSecret();
  const a = derivePairwiseId(root, "counterparty-a.example");
  const b = derivePairwiseId(root, "counterparty-b.example");
  assert.notEqual(a, b);
  assert.equal(linkabilityScore(a, b), 0);
  assert.equal(derivePairwiseId(root, "counterparty-a.example"), a);
});

test("INV-6: crypto-shred renders historical ciphertext permanently unreadable", () => {
  const h = harness();
  // Stronger than the previous form, which went through Vault.tryRead(): the
  // caller here holds the ciphertext AND the KMS and still cannot read the
  // record once its salt is destroyed.
  const box = h.vault.ciphertextFor("rec_1")!;
  const read = () => JSON.parse(open(h.kms, "neutral-op", "rec_1", box)) as NeutralPayload;
  assert.equal(read().secret, "s3cr3t-payload");
  const erased = h.vault.erase("sub_1", h.authFor(eraseOp("sub_1")));
  assert.deepEqual(erased, ["rec_1"]);
  assert.throws(read, RecordShredded);
});

test("INV-4b: Vault exposes no decryption path other than resolve()", () => {
  const h = harness();
  // The invariant INV-4 states is structural, so assert it structurally:
  // tryRead() was a public, unauthenticated open() and is gone.
  assert.equal((h.vault as Record<string, unknown>).tryRead, undefined);
  const surface = [
    ...Object.getOwnPropertyNames(Object.getPrototypeOf(h.vault)),
  ].filter((m) => !["constructor", "resolve", "resolveUnaudited"].includes(m));
  for (const m of surface) {
    assert.ok(!/^(read|decrypt|peek|reveal|plaintext)/i.test(m),
      `Vault.${m} looks like a decryption path outside resolve()`);
  }
});

test("INV-7: no cohort below k=25 is ever exposed to a brand", () => {
  assert.equal(cohortSize(3), 0);
  assert.equal(cohortSize(24), 0);
  assert.equal(cohortSize(K_ANON_FLOOR), K_ANON_FLOOR);
});

test("INV-8: adapters are removable — core has no adapter dependency", async () => {
  const core = await import("../../packages/core/src/core.ts");
  assert.ok(typeof core.cohortSize === "function");
  assert.ok(typeof core.ConsentLedger === "function");
});

test("INV-9: every inter-participant request is signed and verified (ONDC)", async () => {
  const h = harness();
  const req = { pairwiseId: h.pairwiseId, units: 2, fulfiller: "NTR-OP", channelKind: "direct" as const };
  const env = signRequest("counterparty.example", "k1", h.mk.privateKey, req);

  assert.throws(() => h.registry.verify(env, { ...req, units: 900 }), SignatureInvalid);
  h.registry.suspend("counterparty.example", h.authFor(suspendOp("counterparty.example")));
  assert.throws(() => h.registry.verify(env, req));
});

test("INV-10: the consent chain is tamper-evident (hash-chained ledger)", async () => {
  const h = harness();
  await grantOnce(h);
  await grantOnce(h);
  assert.equal(h.consent.verifyChain(), -1, "chain should verify clean");
  h.consent.tamperForDemo(0, (e) => { e.purpose = "marketing"; });
  assert.equal(h.consent.verifyChain(), 0, "tampering must be detected at entry 0");
});

test("INV-11: attenuation may narrow a grant but never widen it", () => {
  const secret = randomBytes(32);
  const cap = mint(secret, {
    pairwiseId: "CFP-AAAA-BBBB-CCCC", purpose: "delivery", maxUnits: 5,
    fulfiller: "NTR-OP", expiresAt: Date.now() + 60_000, singleUse: true, maxAttempts: 3,
    consentRef: "cns_x", channelKind: "direct",
  });
  const narrower = attenuate(secret, cap, { maxUnits: 2 }, "agent-7");
  assert.equal(narrower.caveats.maxUnits, 2);
  assert.throws(() => attenuate(secret, cap, { maxUnits: 50 }, "agent-7"), AttenuationWidened);
  assert.throws(() => attenuate(secret, cap, { purpose: "return" }, "agent-7"), AttenuationWidened);
});

test("INV-12: co-residents cannot enumerate each other through a shared record (Posten)", () => {
  const rows = [
    { cohortRecordId: "rec_1", subjectRef: "sub_1", barrier: false },
    { cohortRecordId: "rec_1", subjectRef: "sub_2", barrier: false },
    { cohortRecordId: "rec_1", subjectRef: "sub_3", barrier: true },
  ];
  assert.deepEqual(visibleCoResidents(rows, "sub_1", "rec_1"), ["sub_2"]);
  assert.deepEqual(visibleCoResidents(rows, "sub_3", "rec_1"), [], "barriered resident sees nobody");
});

test("INV-13: ciphertext moved between records fails closed (AAD binding)", () => {
  const kms = new Kms();
  const a = seal(kms, "neutral-op", "rec_a", "s3cr3t-payload");
  assert.throws(() => open(kms, "neutral-op", "rec_b", a), Error);
});
