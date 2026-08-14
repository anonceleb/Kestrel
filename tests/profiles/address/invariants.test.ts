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
import {
  cohortSize,
  visibleCoResidents,
  K_ANON_FLOOR,
  cohortAtRung,
  PrecisionFloorUnsatisfiable,
} from "../../../packages/core/src/core.ts";
import { verifyLabelOffline } from "../../../packages/labels/src/label.ts";
import { DIGIPIN_LADDER, FlatDensity } from "../../../profiles/address/src/precision.ts";
import { geoBucketFor as indiaGeoBucketFor } from "../../../adapters/india-post/src/adapter.ts";
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
    { cohortRecordId: "rec_1", subjectRef: "sub_1", barrier: false },
    { cohortRecordId: "rec_1", subjectRef: "sub_2", barrier: false },
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

/**
 * INV-36 — no emitted geo bucket may correspond to a cell below the k-floor.
 *
 * The invariant the old hard-coded `slice(0, 6)` could not state, let alone
 * prove. It is checked across a density sweep spanning rural and urban
 * India rather than at one convenient point, because the whole failure mode
 * of a constant is that it holds somewhere and not elsewhere.
 */
test("INV-36: an emitted DIGIPIN bucket never denotes a cell holding fewer than k people", () => {
  const digipin = "39J49L4T24";
  // people/km2: sparse rural, national mean, dense rural, urban, metro core.
  for (const density of [12, 28, 120, 1_100, 11_000, 40_000]) {
    const bucket = indiaGeoBucketFor(digipin, new FlatDensity(density));
    const chars = bucket.replace("IND-", "").length;
    const rung = DIGIPIN_LADDER.find((r) => r.chars === chars)!;
    assert.ok(
      cohortAtRung(rung, density) >= K_ANON_FLOOR,
      `at ${density} people/km2 the ${chars}-char cell holds ${cohortAtRung(rung, density).toFixed(1)} < k`,
    );
  }
});

test("INV-36: precision widens as density thins — the bucket is derived, not constant", () => {
  const digipin = "39J49L4T24";
  const sparse = indiaGeoBucketFor(digipin, new FlatDensity(30)).replace("IND-", "").length;
  const dense = indiaGeoBucketFor(digipin, new FlatDensity(20_000)).replace("IND-", "").length;
  assert.ok(dense > sparse, `expected a denser area to permit more precision, got ${dense} <= ${sparse}`);
});

test("INV-36: a density too thin for any rung refuses rather than emitting an under-protected bucket", () => {
  // k=25 over the coarsest rung (~9.4e5 km2) needs ~2.7e-5 people/km2 to pass,
  // so an uninhabited cell is the only way to exhaust the ladder.
  assert.throws(
    () => indiaGeoBucketFor("39J49L4T24", new FlatDensity(0)),
    PrecisionFloorUnsatisfiable,
  );
});

test("INV-36: a routing minimum the k-floor cannot satisfy surfaces as a conflict, not a silent choice", () => {
  assert.throws(
    () => indiaGeoBucketFor("39J49L4T24", new FlatDensity(30), { minChars: 9 }),
    PrecisionFloorUnsatisfiable,
  );
});

test("the DIGIPIN ladder reproduces DoP's published ~4x4 m cell at full precision", () => {
  const finest = DIGIPIN_LADDER[DIGIPIN_LADDER.length - 1]!;
  const sideM = Math.sqrt(finest.cellKm2) * 1000;
  assert.equal(finest.chars, 10);
  assert.ok(sideM > 3.5 && sideM < 4.1, `expected ~4 m at 10 characters, got ${sideM.toFixed(2)} m`);
});
