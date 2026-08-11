/**
 * One invariant per closed threat-model gap. See THREAT_MODEL.md (lineage
 * repo) §1, §2 items 1/4/5/7 and §4 for the admitted holes these close.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFileSync, unlinkSync, mkdirSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { Registry, newKeyPair, signRequest, WriteNotAuthorized } from "../../packages/registry/src/signing.ts";
import { demoOnlyInsecurePolicyStore, DemoPolicyNotAllowed } from "../../packages/policy/src/policy.ts";
import { Platform } from "../../services/platform/src/platform.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { newRootSecret, derivePairwiseId, linkabilityScore } from "../../packages/identity/src/pairwise.ts";
import { harness, grantOnce } from "./harness.ts";

const REPO_ROOT = join(dirname(fileURLToPath(import.meta.url)), "../..");

test("INV-29: Registry.register()/suspend() require a facilitator-signed credential", () => {
  const genesis = newKeyPair();
  const registry = new Registry({
    subscriberId: "facilitator.a.example", role: "facilitator", keyId: "k1",
    publicKey: genesis.publicKey, tier: 3, status: "active",
  });

  const newParticipant = {
    subscriberId: "merchant.rogue.example", role: "merchant" as const, keyId: "k1",
    publicKey: newKeyPair().publicKey, tier: 3 as const, status: "active" as const,
  };

  // No credential at all — rejected.
  // @ts-expect-error — deliberately calling without the required auth argument
  assert.throws(() => registry.register(newParticipant, undefined), WriteNotAuthorized);

  // A credential signed by a non-facilitator (even if registered) is rejected.
  const impostorKeys = newKeyPair();
  registry.register(
    { subscriberId: "merchant.impostor.example", role: "merchant", keyId: "k1", publicKey: impostorKeys.publicKey, tier: 3, status: "active" },
    { envelope: signRequest("facilitator.a.example", "k1", genesis.privateKey, newParticipant), body: newParticipant },
  );
  const impostorEnv = signRequest("merchant.impostor.example", "k1", impostorKeys.privateKey, newParticipant);
  assert.throws(
    () => registry.register(newParticipant, { envelope: impostorEnv, body: newParticipant }),
    WriteNotAuthorized,
  );

  // A genuine facilitator-signed credential succeeds.
  const env = signRequest("facilitator.a.example", "k1", genesis.privateKey, newParticipant);
  registry.register(newParticipant, { envelope: env, body: newParticipant });
  assert.equal(registry.lookup("merchant.rogue.example").status, "active");

  // suspend() is gated the same way.
  const suspendBody = { subscriberId: "merchant.rogue.example" };
  assert.throws(
    () => registry.suspend("merchant.rogue.example", { envelope: signRequest("merchant.impostor.example", "k1", impostorKeys.privateKey, suspendBody), body: suspendBody }),
    WriteNotAuthorized,
  );
  registry.suspend("merchant.rogue.example", { envelope: signRequest("facilitator.a.example", "k1", genesis.privateKey, suspendBody), body: suspendBody });
  assert.equal(registry.lookup("merchant.rogue.example").status, "suspended");
});

test("INV-29b: Vault.erase() requires the same facilitator-signed credential", () => {
  const h = harness();
  assert.throws(() => h.vault.erase("sub_1", undefined as never), WriteNotAuthorized);
  const erased = h.vault.erase("sub_1", h.authFor({ subjectRef: "sub_1" }));
  assert.deepEqual(erased, ["rec_1"]);
});

test("INV-30: the demo-only default policy is loudly gated behind CFP_ALLOW_DEMO_POLICY", () => {
  const prev = process.env.CFP_ALLOW_DEMO_POLICY;
  delete process.env.CFP_ALLOW_DEMO_POLICY;
  try {
    assert.throws(() => demoOnlyInsecurePolicyStore(), DemoPolicyNotAllowed);
    process.env.CFP_ALLOW_DEMO_POLICY = "1";
    const store = demoOnlyInsecurePolicyStore();
    assert.equal(store.active().policy.minTierToRelease, 2);
  } finally {
    if (prev === undefined) delete process.env.CFP_ALLOW_DEMO_POLICY;
    else process.env.CFP_ALLOW_DEMO_POLICY = prev;
  }
});

test("INV-30b: Platform constructed without an explicit policy inherits the same gate", () => {
  const prev = process.env.CFP_ALLOW_DEMO_POLICY;
  delete process.env.CFP_ALLOW_DEMO_POLICY;
  try {
    const h = harness();
    assert.throws(
      () => new Platform({ registry: h.registry, consent: h.consent, capSecret: h.capSecret }),
      DemoPolicyNotAllowed,
    );
  } finally {
    if (prev === undefined) delete process.env.CFP_ALLOW_DEMO_POLICY;
    else process.env.CFP_ALLOW_DEMO_POLICY = prev;
  }
});

test("INV-31: privacy-lint's log-hygiene scan covers adapters/ and profiles/, not just packages/ and services/", () => {
  // Baseline: the real repo passes.
  execFileSync("node", ["--experimental-strip-types", "tools/privacy-lint/lint.ts"], { cwd: REPO_ROOT });

  // Inject a PII-shaped log call into a scratch adapter directory and prove lint catches it.
  const scratchDir = join(REPO_ROOT, "adapters", "__lint_probe__", "src");
  mkdirSync(scratchDir, { recursive: true });
  const scratchFile = join(scratchDir, "probe.ts");
  writeFileSync(scratchFile, `console.log("customer address: 14 Harbour Lane");\n`);
  try {
    assert.throws(() => execFileSync("node", ["--experimental-strip-types", "tools/privacy-lint/lint.ts"], { cwd: REPO_ROOT, stdio: "pipe" }));
  } finally {
    rmSync(join(REPO_ROOT, "adapters", "__lint_probe__"), { recursive: true, force: true });
  }
});

test("INV-32: pairwise-ID issuance is unreachable from Platform's public surface", () => {
  const proto = Platform.prototype as unknown as Record<string, unknown>;
  assert.equal("issueS2ID" in proto, false);
  assert.equal("issuePairwiseId" in proto, false);
  // It exists exactly once, on Vault — the class the root secret must never leave.
  assert.equal(typeof (Vault.prototype as unknown as Record<string, unknown>).issuePairwiseId, "function");
});

test("INV-33: the consent ledger is keyed by pairwise reference — Platform cannot correlate a subject across counterparties by comparing `subject`", async () => {
  const h = harness();

  // Register a second counterparty under the same harness's registry/vault.
  const mk2 = newKeyPair();
  h.registry.register(
    { subscriberId: "counterparty-two.example", role: "merchant", keyId: "k1", publicKey: mk2.publicKey, tier: 2, status: "active" },
    h.authFor({ subscriberId: "counterparty-two.example", role: "merchant", keyId: "k1", publicKey: mk2.publicKey, tier: 2, status: "active" }),
  );

  const root = newRootSecret();
  // The *subject-side* pairwise reference each grant is filed under — derived
  // per counterparty, exactly as packages/identity's anti-correlation
  // guarantee requires, and exactly what belongs in ConsentEntry.subject.
  const subjectRefA = derivePairwiseId(root, "counterparty.example", "SUBJ");
  const subjectRefB = derivePairwiseId(root, "counterparty-two.example", "SUBJ");
  assert.notEqual(subjectRefA, subjectRefB);
  assert.equal(linkabilityScore(subjectRefA, subjectRefB), 0);

  const reqA = { pairwiseId: h.pairwiseId, units: 1, fulfiller: "NTR-OP", channelKind: "door" as const };
  const envA = signRequest("counterparty.example", "k1", h.mk.privateKey, reqA);
  const { capability: capA } = h.platform.createGrant(envA, reqA, subjectRefA);

  h.platform.learnProjection(h.pairwiseId, { geoBucket: "BKT-1", vouchTier: 2 });
  const reqB = { pairwiseId: h.pairwiseId, units: 1, fulfiller: "NTR-OP", channelKind: "door" as const };
  const envB = signRequest("counterparty-two.example", "k1", mk2.privateKey, reqB);
  const { capability: capB } = h.platform.createGrant(envB, reqB, subjectRefB);

  const entryA = h.consent.find(capA.caveats.consentRef)!;
  const entryB = h.consent.find(capB.caveats.consentRef)!;
  assert.notEqual(entryA.subject, entryB.subject, "Platform's own ledger must not see a shared subject value across counterparties");
});
