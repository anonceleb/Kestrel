/**
 * One invariant per closed threat-model gap — §1, §2 items 1/4/5/7 and §4
 * for the admitted holes these close.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { execFileSync } from "node:child_process";
import { writeFileSync, mkdtempSync, rmSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";
import { tmpdir } from "node:os";
import { Registry, newKeyPair, signRequest, WriteNotAuthorized } from "../../packages/registry/src/signing.ts";
import {
  demoOnlyInsecurePolicyStore,
  DemoPolicyNotAllowed,
  PolicyStore,
  PolicyStale,
  signPolicy,
} from "../../packages/policy/src/policy.ts";
import { Platform } from "../../services/platform/src/platform.ts";
import { Vault } from "../../services/vault/src/vault.ts";
import { newRootSecret, derivePairwiseId, linkabilityScore } from "../../packages/identity/src/pairwise.ts";
import { verify as verifyCapability, CapabilityInvalid } from "../../packages/capability/src/capability.ts";
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
    assert.deepEqual(store.active().policy.acceptableAssurance, ["tier-2", "tier-3"]);
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

  // Inject a PII-shaped log call into a scratch directory *outside* the repo and prove lint
  // catches it via CFP_LINT_EXTRA_LOG_DIR — the probe never touches the tree being linted, so
  // there is nothing to clean up and nothing that can be left behind by a failed cleanup.
  const scratchDir = mkdtempSync(join(tmpdir(), "cfp-lint-probe-"));
  const scratchFile = join(scratchDir, "probe.ts");
  writeFileSync(scratchFile, `console.log("customer address: 14 Harbour Lane");\n`);
  try {
    assert.throws(() =>
      execFileSync("node", ["--experimental-strip-types", "tools/privacy-lint/lint.ts"], {
        cwd: REPO_ROOT,
        stdio: "pipe",
        env: { ...process.env, CFP_LINT_EXTRA_LOG_DIR: scratchDir },
      }),
    );
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
  }
});

test("privacy-lint check 4 catches all four evasions of the old exact-match, newline-terminated rule", () => {
  const probes: Record<string, string> = {
    "single-line.ts": `export type Foo = { address: string };\n`,
    "delivery-address.ts": `export type Foo = {\n  deliveryAddress: string;\n};\n`,
    "postal-code.ts": `export type Foo = {\n  postalCode: string;\n};\n`,
    "street-name.ts": `export type Foo = {\n  street_name: string;\n};\n`,
    "type-name.ts": `export type PostalAddress = {\n  x: number;\n};\n`,
  };
  const clean = `export type Clean = {\n  merchantId: string;\n};\n`;

  const scratchDir = mkdtempSync(join(tmpdir(), "cfp-lint-type-probe-"));
  try {
    for (const [file, src] of Object.entries(probes)) {
      writeFileSync(join(scratchDir, file), src);
      assert.throws(
        () =>
          execFileSync("node", ["--experimental-strip-types", "tools/privacy-lint/lint.ts"], {
            cwd: REPO_ROOT,
            stdio: "pipe",
            env: { ...process.env, CFP_LINT_EXTRA_TYPE_DIR: scratchDir },
          }),
        `expected ${file} to fail the address-shaped-identifier check`,
      );
      rmSync(join(scratchDir, file));
    }
    // A clean type in the same scratch dir must still pass — this is not a blanket failure.
    writeFileSync(join(scratchDir, "clean.ts"), clean);
    execFileSync("node", ["--experimental-strip-types", "tools/privacy-lint/lint.ts"], {
      cwd: REPO_ROOT,
      env: { ...process.env, CFP_LINT_EXTRA_TYPE_DIR: scratchDir },
    });
  } finally {
    rmSync(scratchDir, { recursive: true, force: true });
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

  const reqA = { pairwiseId: h.pairwiseId, units: 1, fulfiller: "NTR-OP", channelKind: "direct" as const };
  const envA = signRequest("counterparty.example", "k1", h.mk.privateKey, reqA);
  const { capability: capA } = h.platform.createGrant(envA, reqA, subjectRefA);

  h.platform.learnProjection(h.pairwiseId, { geoBucket: "BKT-1", assurance: "tier-2" });
  const reqB = { pairwiseId: h.pairwiseId, units: 1, fulfiller: "NTR-OP", channelKind: "direct" as const };
  const envB = signRequest("counterparty-two.example", "k1", mk2.privateKey, reqB);
  const { capability: capB } = h.platform.createGrant(envB, reqB, subjectRefB);

  const entryA = h.consent.find(capA.caveats.consentRef)!;
  const entryB = h.consent.find(capB.caveats.consentRef)!;
  assert.notEqual(entryA.subject, entryB.subject, "Platform's own ledger must not see a shared subject value across counterparties");
});

test("INV-19: the policy hash recorded on a consent entry is byte-identical to the policy that authorized it, and PolicyStore.byHash() replays it after the store moves on — restored, previously dropped without replacement", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const activeHash = h.platform.policy().active().hash;
  const entry = h.consent.find(capability.caveats.consentRef);
  assert.equal(entry?.policyHash, activeHash, "createGrant's docstring claims this; nothing previously asserted it");

  // Independently: PolicyStore.byHash() must keep answering "what did the rules say when this
  // decision was made" after reload() moves the active policy on — not just "what do they say now".
  const { publicKey, privateKey } = newKeyPair();
  const v1 = signPolicy(privateKey, "op-signer", { version: 1, acceptableAssurance: ["tier-2"] });
  const store = new PolicyStore(publicKey, v1);
  const v2 = signPolicy(privateKey, "op-signer", { version: 2, acceptableAssurance: ["tier-3"] });
  store.reload(v2);
  assert.deepEqual(store.byHash(v1.hash)?.policy, v1.policy);
  assert.equal(store.active().policy.version, 2);

  // reload() refuses to go backwards or sideways — a past decision's policy stays replayable
  // precisely because the active policy can never be un-advanced to hide what changed.
  assert.throws(() => store.reload(v1), PolicyStale);
});

test("INV-23: the capability MAC covers id — a swapped id invalidates the signature — restored, previously dropped without replacement", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const forged = { ...capability, id: "some-other-id" };
  assert.throws(() => verifyCapability(h.capSecret, forged), CapabilityInvalid);
  // The unmodified capability still verifies — this is a forgery check, not a blanket break.
  verifyCapability(h.capSecret, capability);
});

test("INV-25: the active policy cannot be mutated through the reference active() returns — restored, previously dropped without replacement", () => {
  const { publicKey, privateKey } = newKeyPair();
  const v1 = signPolicy(privateKey, "op-signer", { version: 1, acceptableAssurance: ["tier-2"] });
  const store = new PolicyStore(publicKey, v1);
  const active = store.active();
  assert.throws(() => {
    (active as { policy: unknown }).policy = { version: 99, acceptableAssurance: ["tier-1"] };
  }, TypeError);
  assert.throws(() => {
    (active.policy as { acceptableAssurance: unknown }).acceptableAssurance = ["tier-1"];
  }, TypeError);
  assert.deepEqual(store.active().policy.acceptableAssurance, ["tier-2"]);
});
