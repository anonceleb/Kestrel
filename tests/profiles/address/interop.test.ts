/**
 * The interop claim, extended to three operators: the exchange layer
 * (packages/core, services/vault, services/platform) is not hard-coded to
 * any one operator's address shape. Swaps postal-meridia, dakhil-post, and
 * india-post into Vault/Platform with zero core changes and checks all
 * three operators' outputs never collide.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { randomBytes } from "node:crypto";
import { Kms } from "../../../packages/crypto/src/envelope.ts";
import { Registry, newKeyPair, signRequest } from "../../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../../packages/core/src/core.ts";
import { Vault } from "../../../services/vault/src/vault.ts";
import { Platform } from "../../../services/platform/src/platform.ts";
import type { AddressPayload } from "../../../profiles/address/src/address.ts";
import { MeridiaSortation, geoBucketFor as meridiaGeoBucketFor } from "../../../adapters/postal-meridia/src/adapter.ts";
import { DakhilSortation, DakhilIdentity, NoCustodyKey, geoBucketFor as dakhilGeoBucketFor } from "../../../adapters/dakhil-post/src/adapter.ts";
import { IndiaPostRouting, IndiaPostIdentity, IndiaPostNoCustodyKey, geoBucketFor as indiaGeoBucketFor } from "../../../adapters/india-post/src/adapter.ts";
import { operatorPolicy } from "./harness.ts";

function opHarness(routing: { route(p: unknown, s: string): Promise<{ sortationCode: string }> }) {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const registry = new Registry();
  const vault = new Vault({ kms, audit, consent, nonces, capSecret, routing: routing as never, registry });
  const platform = new Platform({ registry, consent, capSecret, policy: operatorPolicy() });
  return { kms, audit, consent, nonces, capSecret, registry, vault, platform };
}

test("interop: core builds unmodified against dakhil-post's different address format", async () => {
  const h = opHarness(new DakhilSortation());
  // No reliable postcode — this operator routes off landmark/locality instead.
  const address: AddressPayload = { line1: "Near Hanuman Mandir", locality: "Kotra Sadatganj", postcode: "", placeName: "Ratanpur" };
  const rec = h.vault.store({
    id: "rec_dkh_1", subjectRef: "sub_dkh_1", tenantId: "dakhil-post",
    payload: address, geoBucket: dakhilGeoBucketFor(address), vouchTier: 2,
  });
  const projection = h.vault.publicProjection(rec.id);
  assert.equal(projection?.geoBucket, "DKH-RA");
  assert.notEqual(projection?.geoBucket, meridiaGeoBucketFor("4820"));
});

test("interop: core builds unmodified against india-post's DIGIPIN routing", async () => {
  const h = opHarness(new IndiaPostRouting());
  const address: AddressPayload = { line1: "Plot 7", locality: "Sector 12", postcode: "110001", digipin: "39J438TJC7" };
  const rec = h.vault.store({
    id: "rec_ind_1", subjectRef: "sub_ind_1", tenantId: "india-post",
    payload: address, geoBucket: indiaGeoBucketFor(address.digipin!), vouchTier: 2,
  });
  const projection = h.vault.publicProjection(rec.id);
  assert.equal(projection?.geoBucket, "IND-39J438");
});

test("interop: no sortation-code or geo-bucket collisions across all three operators", async () => {
  const meridia = new MeridiaSortation();
  const dakhil = new DakhilSortation();
  const india = new IndiaPostRouting();
  const address: AddressPayload = { line1: "x", locality: "Calder", postcode: "4820", digipin: "39J438TJC7" };

  const m = await meridia.route(address, "standard");
  const d = await dakhil.route(address, "standard");
  const i = await india.route(address, "standard");

  assert.match(m.sortationCode, /^MRD-/);
  assert.match(d.sortationCode, /^DKH-/);
  assert.match(i.sortationCode, /^IND-/);
  const codes = new Set([m.sortationCode, d.sortationCode, i.sortationCode]);
  assert.equal(codes.size, 3, "no two operators may ever emit the same sortation code");

  const buckets = new Set([
    meridiaGeoBucketFor("4820"),
    dakhilGeoBucketFor(address),
    indiaGeoBucketFor(address.digipin!),
  ]);
  assert.equal(buckets.size, 3, "no two operators may ever emit the same geo bucket");
});

test("interop: dakhil-post and india-post both refuse a bare self-asserted identity claim", async () => {
  const registry = new Registry();
  const dakhilIdentity = new DakhilIdentity(registry);
  const indiaIdentity = new IndiaPostIdentity(registry);
  await assert.rejects(() => dakhilIdentity.proof("sub_1", { nationalId: "DKH-1", vouched: true }), NoCustodyKey);
  await assert.rejects(() => indiaIdentity.proof("sub_1", { nationalId: "IND-1", vouched: true }), IndiaPostNoCustodyKey);
});

test("interop: india-post proofs only against a signed registry attestation, capped at the attester's own tier", async () => {
  const facKeys = newKeyPair();
  const registry = new Registry({
    participantId: "facilitator.network.example", role: "facilitator", keyId: "fk1",
    publicKey: facKeys.publicKey, tier: 3, status: "active",
  });
  const identity = new IndiaPostIdentity(registry);
  const issuer = newKeyPair();
  const issuerParticipant = { participantId: "issuer.gramin-dak-sevak.example", role: "operator" as const, keyId: "k1", publicKey: issuer.publicKey, tier: 2 as const, status: "active" as const };
  registry.register(issuerParticipant, {
    envelope: signRequest("facilitator.network.example", "fk1", facKeys.privateKey, issuerParticipant),
    body: issuerParticipant,
  });
  const body = { subjectRef: "sub_1", claim: "vouched-in-person" };
  const envelope = signRequest("issuer.gramin-dak-sevak.example", "k1", issuer.privateKey, body);
  const tier = await identity.proof("sub_1", { envelope, body, requestedTier: 3 });
  assert.equal(tier, 2);
});
