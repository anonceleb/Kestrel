/**
 * INV-35 — the DeDi-shaped directory port (packages/directory/src/directory.ts)
 * is actually exercised, not just defined: a label-key rotation, a
 * subscriber suspension, a capability revocation, and a policy reload are
 * each independently verifiable by reading back through the same
 * `DeDiDirectoryPort` interface a third party would query — not through
 * any of the originating classes' own state.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { InProcessDirectory } from "../../packages/directory/src/directory.ts";
import { OperatorKeyring } from "../../packages/labels/src/keyring.ts";
import { Registry, newKeyPair, signRequest } from "../../packages/registry/src/signing.ts";
import { NonceLedger } from "../../packages/capability/src/capability.ts";
import { PolicyStore, signPolicy } from "../../packages/policy/src/policy.ts";
import { digestOf } from "../../packages/registry/src/signing.ts";

test("INV-35: OperatorKeyring.rotate() publishes the new public key through the directory", () => {
  const directory = new InProcessDirectory();
  const keyring = new OperatorKeyring({ directory, ownerId: "op-1" });

  const key = keyring.rotate();

  // A third party reading only the directory — not the keyring — can see it.
  const entry = directory.lookupKey("op-1", key.kid);
  assert.ok(entry);
  assert.equal(entry!.publicKey, key.publicKey);
  assert.equal(entry!.kid, key.kid);
  // The private key never appears on the directory-shaped entry type at all.
  assert.equal((entry as unknown as { privateKey?: string }).privateKey, undefined);
});

test("INV-35: Registry.suspend() publishes a subscriber revocation through the directory", () => {
  const directory = new InProcessDirectory();
  const facKeys = newKeyPair();
  const registry = new Registry(
    { subscriberId: "facilitator.dir.example", role: "facilitator", keyId: "fk1", publicKey: facKeys.publicKey, tier: 3, status: "active" },
    directory,
  );
  function authFor(body: unknown) {
    const envelope = signRequest("facilitator.dir.example", "fk1", facKeys.privateKey, body);
    return { envelope, body };
  }

  const mk = newKeyPair();
  const merchant = { subscriberId: "merchant.dir.example", role: "merchant" as const, keyId: "k1", publicKey: mk.publicKey, tier: 2 as const, status: "active" as const };
  registry.register(merchant, authFor(merchant));

  registry.suspend("merchant.dir.example", authFor({ subscriberId: "merchant.dir.example" }));

  const revocations = directory.lookupRevocations("subscriber");
  assert.ok(revocations.some((r) => r.subject === "merchant.dir.example"));
});

test("INV-35: NonceLedger.revoke() publishes a capability revocation through the directory", () => {
  const directory = new InProcessDirectory();
  const nonces = new NonceLedger({ directory });

  nonces.revoke("cap_abc123");

  const revocations = directory.lookupRevocations("capability");
  assert.equal(revocations.length, 1);
  assert.equal(revocations[0].subject, "cap_abc123");
});

test("INV-35: PolicyStore.reload() publishes the newly active policy through the directory", () => {
  const directory = new InProcessDirectory();
  const { publicKey, privateKey } = newKeyPair();
  const initial = signPolicy(privateKey, "op-signer", { version: 1, acceptableAssurance: ["tier-2", "tier-3"] });
  const store = new PolicyStore(publicKey, initial, directory);

  // Genesis policy is not published — only reload()s are (per the plan's wiring note).
  assert.equal(directory.lookupPolicy(initial.hash), undefined);

  const next = signPolicy(privateKey, "op-signer", { version: 2, acceptableAssurance: ["tier-3"] });
  store.reload(next);

  const published = directory.lookupPolicy(next.hash);
  assert.ok(published);
  assert.equal(published!.version, 2);
  assert.equal(published!.policyHash, digestOf(next.policy));
  assert.equal(store.active().policy.version, 2);
});
