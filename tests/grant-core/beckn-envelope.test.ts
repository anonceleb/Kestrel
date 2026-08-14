/**
 * INV-34 — the registry's signed envelope matches Beckn's real wire
 * convention, not a self-minted approximation: keyId is
 * `{subscriberId}|{keyId}|ed25519`-shaped, the digest is verifiably a
 * BLAKE2b-512 hash (not SHA-256) of the canonical body, and both a
 * tampered body and a tampered digest fail verification.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { Registry, newKeyPair, signRequest, digestOf, canonical, SignatureInvalid, registerOp, authorizationHeader } from "../../packages/registry/src/signing.ts";
import { genesisRegistry } from "./harness.ts";

test("INV-34: the emitted Authorization header carries Beckn's {subscriberId}|{keyId}|ed25519 composite", () => {
  const { registry, authFor } = genesisRegistry();
  const mk = newKeyPair();
  const body = { subscriberId: "merchant.example", role: "merchant" as const, keyId: "k1", publicKey: mk.publicKey, tier: 2 as const, status: "active" as const };
  registry.register(body, authFor(registerOp(body)));

  const req = { hello: "world" };
  const env = signRequest("merchant.example", "k1", mk.privateKey, req);

  assert.equal(env.subscriberId, "merchant.example");
  assert.equal(env.keyId, "k1");
  // Assert the header this package EMITS, not one the test assembles: the
  // composite keyId is produced by authorizationHeader(), so this invariant
  // is about the shipped wire format rather than about the test's own string.
  const header = authorizationHeader(env);
  assert.match(header, /^Signature keyId="merchant\.example\|k1\|ed25519",algorithm="ed25519",/);
  assert.match(header, /headers="\(created\) \(expires\) digest"/);
  assert.ok(header.includes(`created=${env.created}`) && header.includes(`expires=${env.expires}`));

  // A registry that only knows this envelope's fields must be able to verify it.
  registry.verify(env, req);
});

test("INV-34: digest is a BLAKE2b-512 hash of the canonical body, not SHA-256", () => {
  const body = { z: 1, a: 2 };
  const digest = digestOf(body);

  const expectedBlake = createHash("blake2b512").update(canonical(body)).digest("base64");
  const wrongSha256 = createHash("sha256").update(canonical(body)).digest("base64");

  assert.equal(digest, expectedBlake);
  assert.notEqual(digest, wrongSha256);
  // BLAKE2b-512 digests are 64 bytes -> 88 base64 chars (with padding); SHA-256's are 32 bytes -> 44.
  assert.equal(Buffer.from(digest, "base64").length, 64);
});

test("INV-34: a tampered request body fails verification", () => {
  const { registry, authFor } = genesisRegistry();
  const mk = newKeyPair();
  const p = { subscriberId: "merchant.tamper.example", role: "merchant" as const, keyId: "k1", publicKey: mk.publicKey, tier: 2 as const, status: "active" as const };
  registry.register(p, authFor(registerOp(p)));

  const req = { units: 1 };
  const env = signRequest("merchant.tamper.example", "k1", mk.privateKey, req);

  assert.throws(() => registry.verify(env, { units: 999 }), SignatureInvalid);
});

test("INV-34: a tampered digest fails verification even against the original body", () => {
  const { registry, authFor } = genesisRegistry();
  const mk = newKeyPair();
  const p = { subscriberId: "merchant.tamper2.example", role: "merchant" as const, keyId: "k1", publicKey: mk.publicKey, tier: 2 as const, status: "active" as const };
  registry.register(p, authFor(registerOp(p)));

  const req = { units: 1 };
  const env = signRequest("merchant.tamper2.example", "k1", mk.privateKey, req);
  const tampered = { ...env, digest: digestOf({ units: 2 }) };

  assert.throws(() => registry.verify(tampered, req), SignatureInvalid);
});
