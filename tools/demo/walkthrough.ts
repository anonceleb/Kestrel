/**
 * A narrated end-to-end run of the generic grant lifecycle, address profile.
 * `npm run demo` — no network, no database, no cloud account.
 */
import { randomBytes } from "node:crypto";
import { Kms } from "../../packages/crypto/src/envelope.ts";
import { newRootSecret } from "../../packages/identity/src/pairwise.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../packages/capability/src/capability.ts";
import { AuditLog, ConsentLedger } from "../../packages/core/src/core.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { Platform, MerchantDatabase } from "../../services/platform/src/platform.ts";
import { MeridiaSortation, geoBucketFor } from "../../adapters/postal-meridia/src/adapter.ts";
import { verifyLabelOffline } from "../../packages/labels/src/label.ts";
import { PolicyStore, signPolicy } from "../../packages/policy/src/policy.ts";
import type { AddressPayload } from "../../profiles/address/src/address.ts";

const line = (s = "") => console.log(s);
const step = (n: number, s: string) => console.log(`\n[${n}] ${s}`);

const kms = new Kms();
const audit = new AuditLog();
const consent = new ConsentLedger();
const nonces = new NonceLedger();
const capSecret = randomBytes(32);

step(0, "A facilitator seeds the registry. Every register()/suspend() write from here on must carry its signature.");
const facilitatorKeys = newKeyPair();
const registry = new Registry({
  participantId: "facilitator.network.example", role: "facilitator", keyId: "fk1",
  publicKey: facilitatorKeys.publicKey, tier: 3, status: "active",
});
function facilitatorAuth(body: unknown) {
  return { envelope: signRequest("facilitator.network.example", "fk1", facilitatorKeys.privateKey, body), body };
}

step(0.5, "The operator signs its own disclosure policy — no self-signed Platform default in this build.");
const operatorKeys = newKeyPair();
const policy = new PolicyStore(
  operatorKeys.publicKey,
  signPolicy(operatorKeys.privateKey, "operator-network-authority", { version: 1, minTierToRelease: 2 }),
);

const vault = new Vault({ kms, audit, consent, nonces, capSecret, routing: new MeridiaSortation(), registry });
const platform = new Platform({ registry, consent, capSecret, policy });

step(1, "Two counterparties join the network. Each publishes an Ed25519 key, admitted by the facilitator.");
const privateKeys: Record<string, string> = {};
for (const id of ["alba-goods.example", "corvid-tools.example"]) {
  const kp = newKeyPair();
  const p = { participantId: id, role: "merchant" as const, keyId: "k1", publicKey: kp.publicKey, tier: 2 as const, status: "active" as const };
  registry.register(p, facilitatorAuth(p));
  privateKeys[id] = kp.privateKey;
  line(`    registered ${id}`);
}

step(2, "A subject is vouched by the operator and their address is sealed in Zone 1. Platform never sees it.");
const root = newRootSecret();
const address: AddressPayload = { line1: "14 Harbour Lane", locality: "Calder", postcode: "4820" };
const rec = vault.store({
  id: "rec_1", subjectRef: "sub_1", tenantId: "meridia-post",
  payload: address, geoBucket: geoBucketFor(address.postcode), vouchTier: 2,
});
line(`    sealed. ciphertext=${rec.ciphertext.ct.slice(0, 24)}...  geoBucket=${rec.geoBucket}`);

step(3, "The same subject gets a DIFFERENT pairwise identifier at each counterparty — issued by Vault, never Platform.");
const idA = vault.issuePairwiseId(root, "alba-goods.example");
const idB = vault.issuePairwiseId(root, "corvid-tools.example");
vault.bind(idA, rec.id);
vault.bind(idB, rec.id);
platform.learnProjection(idA, { geoBucket: rec.geoBucket, vouchTier: 2 });
line(`    alba-goods sees   ${idA}`);
line(`    corvid-tools sees ${idB}`);
line(`    -> no join key. The two databases cannot be merged on this person.`);
line(`    -> and Vault.issuePairwiseId is the only place this codebase derives an id from the root secret.`);

step(4, "Counterparty signs a fulfilment request; platform verifies and mints a grant.");
const req = { pairwiseId: idA, units: 2, fulfiller: "MER-POST", channelKind: "locker" as const };
const env = signRequest("alba-goods.example", "k1", privateKeys["alba-goods.example"]!, req);
const { capability, merchantView } = platform.createGrant(env, req, "sub_1"); // subjectRef would itself be pairwise in production
line(`    grant ${capability.id}`);
line(`    caveats: ${JSON.stringify(capability.caveats, null, 2).split("\n").join("\n    ")}`);

step(5, "The counterparty stores exactly this shape, nothing more.");
const db = new MerchantDatabase();
db.save(merchantView, capability);
line(`    columns: ${db.columns().join(", ")}`);

step(6, "An offline-verifiable COSE artifact is minted for the last-mile handoff. No address in it.");
const signedLabel = vault.mintLabel(capability);
line(`    artifact claims: ${JSON.stringify(signedLabel.claims)}`);
const verified = verifyLabelOffline(vault.labelPublicMaterial(), signedLabel.token);
line(`    verified OFFLINE with no vault, no network: capabilityId=${verified.capabilityId}`);

step(7, "The vault resolves the grant exactly once — audited before plaintext exists.");
const routed = await vault.resolve(capability, "alba-goods.example");
line(`    routed -> ${routed.sortationCode}`);
try {
  await vault.resolve(capability, "alba-goods.example");
} catch (err) {
  line(`    replay attempt correctly rejected: ${(err as Error).constructor.name}`);
}

line("\nDone. No address ever reached the counterparty, no root secret ever reached Platform.");
