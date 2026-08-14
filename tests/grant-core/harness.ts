/**
 * Shared harness for the grant-core suite. Deliberately attribute-agnostic:
 * the confidential payload here is a neutral `{ secret: string }` shape,
 * not an address — this suite proves the mechanism, not any one profile.
 */
import { randomBytes } from "node:crypto";
import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest, registerOp, type WriteAuth } from "../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger, type ConfidentialPayload, type RoutingPort } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform } from "../../services/platform/src/platform.ts";
import { PolicyStore, signPolicy } from "../../packages/policy/src/policy.ts";

export type NeutralPayload = { secret: string };

export class NeutralRouting implements RoutingPort {
  async route(payload: ConfidentialPayload, service: string) {
    const p = payload as NeutralPayload;
    return { routingCode: `NTR-${p.secret.length}-${service}` };
  }
}

/** Registers a genesis facilitator and returns its keypair alongside a WriteAuth-signer helper. */
export function genesisRegistry() {
  const facKeys = newKeyPair();
  const registry = new Registry({
    subscriberId: "facilitator.network.example",
    role: "facilitator",
    keyId: "fk1",
    publicKey: facKeys.publicKey,
    tier: 3,
    status: "active",
  });
  function authFor(body: unknown): WriteAuth {
    const envelope = signRequest("facilitator.network.example", "fk1", facKeys.privateKey, body);
    return { envelope, body };
  }
  return { registry, facKeys, authFor };
}

export function operatorPolicy(acceptableAssurance: string[] = ["tier-2", "tier-3"]): PolicyStore {
  const { publicKey, privateKey } = newKeyPair();
  const initial = signPolicy(privateKey, "operator-network-authority", { version: 1, acceptableAssurance });
  return new PolicyStore(publicKey, initial);
}

export function harness() {
  const kms = new Kms();
  const audit = new AuditLog();
  const consent = new ConsentLedger();
  const nonces = new NonceLedger();
  const capSecret = randomBytes(32);
  const { registry, authFor } = genesisRegistry();
  const vault = new Vault({ kms, audit, consent, nonces, capSecret, routing: new NeutralRouting(), registry });
  const platform = new Platform({ registry, consent, capSecret, policy: operatorPolicy() });

  const mk = newKeyPair();
  const counterparty = {
    subscriberId: "counterparty.example",
    role: "merchant",
    keyId: "k1",
    publicKey: mk.publicKey,
    tier: 2,
    status: "active",
  } as const;
  registry.register(counterparty, authFor(registerOp(counterparty)));

  const root = newRootSecret();
  const pairwiseId = vault.issuePairwiseId(root, "counterparty.example");
  const rec = vault.store({
    id: "rec_1",
    subjectRef: "sub_1",
    tenantId: "neutral-op",
    payload: { secret: "s3cr3t-payload" } satisfies NeutralPayload,
    geoBucket: "BKT-1",
    assurance: "tier-2",
  });
  vault.bind(pairwiseId, rec.id);
  platform.learnProjection(pairwiseId, { geoBucket: rec.geoBucket, assurance: "tier-2" });

  return { kms, audit, consent, nonces, capSecret, registry, vault, platform, root, pairwiseId, mk, authFor };
}

export async function grantOnce(h: ReturnType<typeof harness>) {
  const req = { pairwiseId: h.pairwiseId, units: 2, fulfiller: "NTR-OP", channelKind: "direct" as const };
  const env = signRequest("counterparty.example", "k1", h.mk.privateKey, req);
  return h.platform.createGrant(env, req, "sub_1");
}
