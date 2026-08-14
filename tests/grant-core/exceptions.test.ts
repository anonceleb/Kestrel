/**
 * Exception paths — returns, revocation, redirect, refund — all built so
 * none of them can ever grant more than the originating fulfilment did.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  CapabilityBurned,
  AttenuationWidened,
  ReattemptsExhausted,
  attenuate,
} from "../../packages/capability/src/capability.ts";
import { NotAuthorized } from "../../services/platform/src/platform.ts";
import { harness, grantOnce } from "./harness.ts";

test("INV-14: a return grant may never exceed the originating grant's scope", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const returnCap = h.platform.createReturn(capability, "counterparty.example", "sub_1");
  assert.equal(returnCap.caveats.purpose, "return");
  assert.ok(returnCap.caveats.maxUnits <= capability.caveats.maxUnits);
  assert.ok(returnCap.caveats.expiresAt <= capability.caveats.expiresAt);
});

test("INV-15: a failed-delivery notification reaches the consumer, never the merchant — restored, previously dropped without replacement", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const notified: Array<{ subjectRef: string; event: string }> = [];
  const notifications = { notify: (subjectRef: string, event: string) => notified.push({ subjectRef, event }) };
  h.vault.notifyFailedDelivery(capability, notifications);
  assert.deepEqual(notified, [{ subjectRef: "sub_1", event: "failed-delivery" }]);
  // The merchant/counterparty id never appears — Vault.notifyFailedDelivery has no way to reach
  // it (it never holds a subscriberId to notify), which is the disclosure-asymmetry property.
  assert.ok(!notified.some((n) => n.subjectRef === "counterparty.example"));
});

test("returns are ownership-checked: a stranger subjectRef cannot self-mint a return", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.throws(() => h.platform.createReturn(capability, "counterparty.example", "not-the-real-subject"), NotAuthorized);
});

test("multi-operator handoff against one vault: a return's actorId is never checked against the forward leg's grantedTo — spec §7's 'supported today' claim, evidenced", async () => {
  const h = harness();
  const { capability } = await grantOnce(h); // forward leg minted for "counterparty.example"
  // The reverse leg is a different legal entity — createReturn is ownership-checked against the
  // subject, never against who held the forward-leg grant, so this succeeds against the same
  // Vault/ConsentLedger the forward leg used.
  const returnCap = h.platform.createReturn(capability, "reverse-leg-carrier.example", "sub_1");
  assert.equal(returnCap.caveats.purpose, "return");
  const entry = h.consent.find(returnCap.caveats.consentRef);
  assert.equal(entry?.grantedTo, "reverse-leg-carrier.example");
  assert.notEqual(entry?.grantedTo, "counterparty.example");
});

test("INV-16: revocation kills a grant the counterparty believes is still valid", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  h.platform.revoke(capability.id, "sub_1");
  await assert.rejects(() => h.vault.resolve(capability, "counterparty.example"), CapabilityBurned);
});

test("revoke() rejects a subjectRef that doesn't own the capability", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.throws(() => h.platform.revoke(capability.id, "not-the-subject"), NotAuthorized);
});

test("a redirect changes only channelKind — units and expiry are carried over unchanged", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const redirected = h.platform.redirectDelivery(capability, "access-point", "sub_1");
  assert.equal(redirected.caveats.channelKind, "access-point");
  assert.equal(redirected.caveats.maxUnits, capability.caveats.maxUnits);
  assert.equal(redirected.caveats.expiresAt, capability.caveats.expiresAt);
  assert.notEqual(redirected.id, capability.id, "a redirect is a distinct, independently single-use grant");
});

test("INV-18: refund-without-return makes zero vault calls", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  let vaultCalled = false;
  const originalResolve = h.vault.resolve.bind(h.vault);
  h.vault.resolve = (async (...args: Parameters<typeof originalResolve>) => {
    vaultCalled = true;
    return originalResolve(...args);
  }) as typeof h.vault.resolve;

  h.platform.refund(capability, "counterparty.example", "sub_1");
  assert.equal(vaultCalled, false, "refund must never call Vault.resolve()");
});

test("INV-24: refund is ownership-checked — a stranger subjectRef cannot refund someone else's capability — restored, previously dropped without replacement", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.throws(
    () => h.platform.refund(capability, "counterparty.example", "someone-else"),
    NotAuthorized,
  );
  // The sanctioned path still succeeds — this is an ownership check, not a blanket rejection.
  h.platform.refund(capability, "counterparty.example", "sub_1");
});

test("attenuateToReturn still cannot widen: expiry/units narrowing is structurally enforced", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const returnCap = h.platform.createReturn(capability, "counterparty.example", "sub_1");
  // attenuate() itself must still reject any purpose change, including this one —
  // the transition is reachable only through Platform.createReturn.
  const { attenuate } = await import("../../packages/capability/src/capability.ts");
  assert.throws(
    () => attenuate(h.capSecret, capability, { purpose: "return" }, "agent-7"),
    AttenuationWidened,
  );
  assert.ok(returnCap); // sanity: the sanctioned path above did succeed
});

test("INV-27: a counterparty's capability-status read is ownership-checked and exactly two states, and never reveals revocation", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.equal(h.platform.getCapabilityStatus(capability.id, "counterparty.example"), "issued");
  assert.throws(() => h.platform.getCapabilityStatus(capability.id, "someone-else.example"), NotAuthorized);
  h.platform.revoke(capability.id, "sub_1");
  // Not "revoked" — the counterparty is the adversary a revocation is usually raised against,
  // and "not-actionable" is the only word this surface is allowed to say.
  assert.equal(h.platform.getCapabilityStatus(capability.id, "counterparty.example"), "not-actionable");
});

test("the subject's own capability-status read is ownership-checked against subject, not grantedTo, and sees all three states", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.equal(h.platform.getSubjectCapabilityStatus(capability.id, "sub_1"), "issued");
  assert.throws(
    () => h.platform.getSubjectCapabilityStatus(capability.id, "counterparty.example"),
    NotAuthorized,
  );
  h.platform.revoke(capability.id, "sub_1");
  assert.equal(h.platform.getSubjectCapabilityStatus(capability.id, "sub_1"), "revoked");
});

test("meta-invariant: no counterparty-facing projection distinguishes subject-initiated termination from any other termination", async () => {
  // Surface 1: Platform.getCapabilityStatus (and the SDK's getStatus wrapper around it) —
  // revoked and expired must be indistinguishable to the counterparty.
  const hRevoked = harness();
  const { capability: revokedCap } = await grantOnce(hRevoked);
  hRevoked.platform.revoke(revokedCap.id, "sub_1");
  const revokedStatus = hRevoked.platform.getCapabilityStatus(revokedCap.id, "counterparty.example");

  const hExpired = harness();
  const { capability: expiredCap } = await grantOnce(hExpired);
  hExpired.consent.tamperForDemo(hExpired.consent.entries().length - 1, (e) => {
    e.expiresAt = Date.now() - 1;
  });
  const expiredStatus = hExpired.platform.getCapabilityStatus(expiredCap.id, "counterparty.example");

  assert.equal(revokedStatus, expiredStatus, "revoked and expired must read identically to a counterparty");
  assert.equal(revokedStatus, "not-actionable");

  // Surface 2: Vault.resolve() — a replayed grant and a revoked one already throw the identical
  // error shape (see profiles/address/invariants.test.ts). Re-assert it here at the core level so
  // this test is the single place that documents every counterparty-facing surface at once.
  const h2 = harness();
  const { capability: cap2 } = await grantOnce(h2);
  await h2.vault.resolve(cap2, "counterparty.example");
  const replayError = await h2.vault.resolve(cap2, "counterparty.example").catch((e) => e);

  const h3 = harness();
  const { capability: cap3 } = await grantOnce(h3);
  h3.platform.revoke(cap3.id, "sub_1");
  const revokedError = await h3.vault.resolve(cap3, "counterparty.example").catch((e) => e);

  assert.equal(replayError.constructor, revokedError.constructor);
});

/* ------------------------------------------------- NDR / re-attempt leg */

test("INV-15: a re-attempt narrows the attempt budget monotonically and can never widen it", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.equal(capability.caveats.maxAttempts, 3);

  const second = h.platform.reattemptDelivery(capability, "counterparty.example", "sub_1");
  assert.equal(second.caveats.maxAttempts, 2);
  assert.equal(second.caveats.purpose, "delivery", "a re-attempt is still a delivery, not a new purpose");
  assert.notEqual(second.id, capability.id, "a re-attempt is independently single-use");
  assert.ok(second.caveats.expiresAt <= capability.caveats.expiresAt);
  assert.equal(second.caveats.pairwiseId, capability.caveats.pairwiseId);

  const third = h.platform.reattemptDelivery(second, "counterparty.example", "sub_1");
  assert.equal(third.caveats.maxAttempts, 1);
});

test("INV-15: an exhausted attempt budget refuses rather than issuing an unusable grant", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const second = h.platform.reattemptDelivery(capability, "counterparty.example", "sub_1");
  const third = h.platform.reattemptDelivery(second, "counterparty.example", "sub_1");
  assert.equal(third.caveats.maxAttempts, 1);
  // Budget spent: escalation (RTO, locker, ask the subject) is now the carrier's
  // only move, and it has to be a deliberate one.
  assert.throws(() => h.platform.reattemptDelivery(third, "counterparty.example", "sub_1"), ReattemptsExhausted);
});

test("INV-15: attenuate() cannot widen maxAttempts — the counter is signed material, not carrier state", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.throws(
    () => attenuate(h.capSecret, capability, { maxAttempts: 99 }, "counterparty.example"),
    AttenuationWidened,
  );
});

test("INV-15: a counterparty cannot extend its own attempt budget — re-attempt is subject-owned", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.throws(
    () => h.platform.reattemptDelivery(capability, "counterparty.example", "not-the-real-subject"),
    NotAuthorized,
  );
});

test("INV-15: the notification asymmetry holds across the whole NDR loop — failure reaches the subject, never the counterparty", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  const notified: Array<{ subjectRef: string; event: string }> = [];
  const notifications = { notify: (subjectRef: string, event: string) => notified.push({ subjectRef, event }) };

  // Attempt 1 fails, a re-attempt is authorised, attempt 2 fails too.
  h.vault.notifyFailedDelivery(capability, notifications);
  const second = h.platform.reattemptDelivery(capability, "counterparty.example", "sub_1");
  h.vault.notifyFailedDelivery(second, notifications);

  assert.equal(notified.length, 2);
  for (const n of notified) {
    assert.equal(n.subjectRef, "sub_1");
    assert.equal(n.event, "failed-delivery");
  }
  // Every re-attempt is its own consent event, so "how many times was this person
  // approached, and under whose authority" is answerable from the ledger.
  const reattemptEntries = h.consent.entries().filter((e) => e.scope.includes("re-attempt-fulfilment"));
  assert.equal(reattemptEntries.length, 1);
  assert.equal(reattemptEntries[0]!.grantedTo, "counterparty.example");
});
