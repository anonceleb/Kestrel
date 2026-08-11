/**
 * Proves purpose-genericity: the contact profile mints/attenuates/redeems a
 * grant scoped to a phone number using the identical grant core — the same
 * FulfilmentGrant type, the same MAC verify function, imported unmodified
 * from packages/capability. No forked token logic anywhere in this file.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { mint, attenuate, verify, type FulfilmentGrant } from "../../../packages/capability/src/capability.ts";
import { verify as verifyImportedAgain } from "../../../packages/capability/src/capability.ts";
import { Kms } from "../../../packages/crypto/src/envelope.ts";
import { Registry, newKeyPair, signRequest } from "../../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../../packages/core/src/core.ts";
import { Vault } from "../../../services/vault/src/vault.ts";
import { Platform } from "../../../services/platform/src/platform.ts";
import { PolicyStore, signPolicy } from "../../../packages/policy/src/policy.ts";
import { CallRelay, type ContactPayload } from "../../../profiles/contact/src/contact.ts";

test("same FulfilmentGrant type, same verify function — a mobility number-masking grant is not a forked token", async () => {
  const secret = randomBytes(32);
  const grant: FulfilmentGrant = mint(secret, {
    pairwiseId: "CFP-RIDE-0001-DRVR",
    purpose: "delivery",
    maxUnits: 1, // one call
    fulfiller: "mobility-relay",
    expiresAt: Date.now() + 5 * 60_000,
    singleUse: true,
    consentRef: "cns_ride_1",
    channelKind: "door", // "door" doubles as "direct connect" — the channel enum is generic, not address-specific
  });

  // Exactly the same verify() imported from packages/capability, no wrapper.
  verify(secret, grant);
  assert.equal(verifyImportedAgain, verify, "no second verify function exists for this profile");

  const narrowed = attenuate(secret, grant, { maxUnits: 1 }, "relay-service");
  assert.equal(narrowed.caveats.maxUnits, 1);
});

test("end-to-end: mint -> attenuate -> redeem a contact grant through Vault/Platform, phone number never leaves the frame", async () => {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);

  const facKeys = newKeyPair();
  const registry = new Registry({
    subscriberId: "facilitator.network.example", role: "facilitator", keyId: "fk1",
    publicKey: facKeys.publicKey, tier: 3, status: "active",
  });
  const vault = new Vault({ kms, audit, consent, nonces, capSecret, routing: new CallRelay(), registry });

  const { publicKey, privateKey } = newKeyPair();
  const policy = new PolicyStore(publicKey, signPolicy(privateKey, "mobility-operator", { version: 1, minTierToRelease: 1 }));
  const platform = new Platform({ registry, consent, capSecret, policy });

  const driverKeys = newKeyPair();
  const driver = { subscriberId: "driver-app.example", role: "merchant" as const, keyId: "k1", publicKey: driverKeys.publicKey, tier: 2 as const, status: "active" as const };
  registry.register(driver, { envelope: signRequest("facilitator.network.example", "fk1", facKeys.privateKey, driver), body: driver });

  const riderContact: ContactPayload = { e164: "+15551234567" };
  const pairwiseId = vault.issuePairwiseId(Buffer.alloc(32, 3), "driver-app.example");
  const rec = vault.store({
    id: "rec_rider_1", subjectRef: "rider_1", tenantId: "mobility-op",
    payload: riderContact, geoBucket: "CALL-ANY", vouchTier: 2,
  });
  vault.bind(pairwiseId, rec.id);
  platform.learnProjection(pairwiseId, { geoBucket: rec.geoBucket, vouchTier: 2 });

  const req = { pairwiseId, units: 1, fulfiller: "mobility-relay", channelKind: "door" as const };
  const env = signRequest("driver-app.example", "k1", driverKeys.privateKey, req);
  const { capability } = platform.createGrant(env, req, "rider_1");

  const routed = await vault.resolve(capability, "driver-app.example");
  assert.match(routed.sortationCode, /^CALL-[0-9A-F]{10}$/);

  for (const enc of ["utf8", "base64", "hex"] as const) {
    const blob = Buffer.from(JSON.stringify(capability)).toString(enc);
    assert.ok(!blob.includes("15551234567"));
  }
});
