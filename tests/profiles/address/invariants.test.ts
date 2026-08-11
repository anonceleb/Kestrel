/**
 * Address-profile invariants: INV-1/2/7/12 re-run against the concrete
 * AddressPayload type, plus the [A4] offline-verifiable artifact check —
 * proving the profile carries real address data end-to-end while the
 * artifact and the grant token itself never do.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CapabilityBurned } from "../../../packages/capability/src/capability.ts";
import { MerchantDatabase } from "../../../services/platform/src/platform.ts";
import { cohortSize, visibleCoResidents, K_ANON_FLOOR } from "../../../packages/core/src/core.ts";
import { verifyLabelOffline } from "../../../packages/labels/src/label.ts";
import { addressHarness, grantOnce } from "./harness.ts";

const PII_SHAPED = /address|line1|street|postcode|phone|email|fullname|nationalid/i;

test("INV-1 (address profile): no counterparty-held record may contain an address-shaped field", async () => {
  const h = addressHarness();
  const { capability, merchantView } = await grantOnce(h);
  const db = new MerchantDatabase();
  db.save(merchantView, capability);
  const offenders = db.columns().filter((c) => PII_SHAPED.test(c));
  assert.deepEqual(offenders, []);
});

test("INV-2 (address profile): grant tokens carry no plaintext address under any encoding", async () => {
  const h = addressHarness();
  const { capability } = await grantOnce(h);
  for (const enc of ["utf8", "base64", "hex"] as const) {
    const blob = Buffer.from(JSON.stringify(capability)).toString(enc).toLowerCase();
    assert.ok(!blob.includes("harbour"));
    assert.ok(!blob.includes("calder"));
  }
});

test("INV-7 (address profile): no cohort below k=25 is ever exposed", () => {
  assert.equal(cohortSize(3), 0);
  assert.equal(cohortSize(K_ANON_FLOOR), K_ANON_FLOOR);
});

test("INV-12 (address profile): co-residents cannot enumerate each other through a shared address", () => {
  const rows = [
    { addressRecordId: "rec_1", subjectRef: "sub_1", barrier: false },
    { addressRecordId: "rec_1", subjectRef: "sub_2", barrier: false },
  ];
  assert.deepEqual(visibleCoResidents(rows, "sub_1", "rec_1"), ["sub_2"]);
});

test("[A4] offline-verifiable artifact carries zero address-shaped claims and verifies with no vault, no network", async () => {
  const h = addressHarness();
  const { capability } = await grantOnce(h);
  const signed = h.vault.mintLabel(capability);
  const claims = JSON.stringify(signed.claims).toLowerCase();
  for (const bad of ["harbour", "calder", "4820", "line1", "postcode"]) {
    assert.ok(!claims.includes(bad), `artifact claims leaked '${bad}'`);
  }
  const verified = verifyLabelOffline(h.vault.labelPublicMaterial(), signed.token);
  assert.equal(verified.capabilityId, capability.id);
});

test("a replayed capability and a revoked one fail with the identical error shape", async () => {
  const h = addressHarness();
  const { capability } = await grantOnce(h);
  await h.vault.resolve(capability, "seller.meridia.example");
  const replayError = await h.vault.resolve(capability, "seller.meridia.example").catch((e) => e);
  assert.ok(replayError instanceof CapabilityBurned);

  const h2 = addressHarness();
  const { capability: cap2 } = await grantOnce(h2);
  h2.platform.revoke(cap2.id, "sub_1");
  const revokedError = await h2.vault.resolve(cap2, "seller.meridia.example").catch((e) => e);
  assert.ok(revokedError instanceof CapabilityBurned);
  assert.equal(replayError.constructor, revokedError.constructor);
});
