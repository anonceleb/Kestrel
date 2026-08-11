import { randomBytes } from "node:crypto";
import { Kms } from "../../../packages/crypto/src/envelope.ts";
import { Registry, newKeyPair, signRequest, type WriteAuth } from "../../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../../packages/core/src/core.ts";
import { Vault } from "../../../services/vault/src/vault.ts";
import { Platform } from "../../../services/platform/src/platform.ts";
import { PolicyStore, signPolicy } from "../../../packages/policy/src/policy.ts";
import { MeridiaSortation, geoBucketFor } from "../../../adapters/postal-meridia/src/adapter.ts";
import type { AddressPayload } from "../../../profiles/address/src/address.ts";

export function operatorPolicy(): PolicyStore {
  const { publicKey, privateKey } = newKeyPair();
  const initial = signPolicy(privateKey, "operator-network-authority", { version: 1, minTierToRelease: 2 });
  return new PolicyStore(publicKey, initial);
}

export function addressHarness() {
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
  function authFor(body: unknown): WriteAuth {
    return { envelope: signRequest("facilitator.network.example", "fk1", facKeys.privateKey, body), body };
  }

  const vault = new Vault({ kms, audit, consent, nonces, capSecret, routing: new MeridiaSortation(), registry });
  const platform = new Platform({ registry, consent, capSecret, policy: operatorPolicy() });

  const mk = newKeyPair();
  const participant = {
    subscriberId: "seller.meridia.example", role: "merchant" as const, keyId: "k1",
    publicKey: mk.publicKey, tier: 2 as const, status: "active" as const,
  };
  registry.register(participant, authFor(participant));

  const address: AddressPayload = { line1: "14 Harbour Lane", locality: "Calder", postcode: "4820" };
  const pairwiseId = vault.issuePairwiseId(Buffer.alloc(32, 7), "seller.meridia.example");
  const rec = vault.store({
    id: "rec_1", subjectRef: "sub_1", tenantId: "meridia-post",
    payload: address, geoBucket: geoBucketFor(address.postcode), vouchTier: 2,
  });
  vault.bind(pairwiseId, rec.id);
  platform.learnProjection(pairwiseId, { geoBucket: rec.geoBucket, vouchTier: 2 });

  return { kms, audit, consent, nonces, capSecret, registry, vault, platform, pairwiseId, mk, authFor, address };
}

export async function grantOnce(h: ReturnType<typeof addressHarness>) {
  const req = { pairwiseId: h.pairwiseId, units: 2, fulfiller: "MER-POST", channelKind: "door" as const };
  const env = signRequest("seller.meridia.example", "k1", h.mk.privateKey, req);
  return h.platform.createGrant(env, req, "sub_1");
}
