/**
 * Exception paths — returns, revocation, redirect, refund — all built so
 * none of them can ever grant more than the originating fulfilment did.
 * Ported from the prior implementation's exceptions*.test.ts with neutral
 * fixtures.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { CapabilityBurned, AttenuationWidened } from "../../packages/capability/src/capability.ts";
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

test("returns are ownership-checked: a stranger subjectRef cannot self-mint a return", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.throws(() => h.platform.createReturn(capability, "counterparty.example", "not-the-real-subject"), NotAuthorized);
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

test("INV-27: a counterparty's capability-status read is ownership-checked and exactly three states", async () => {
  const h = harness();
  const { capability } = await grantOnce(h);
  assert.equal(h.platform.getCapabilityStatus(capability.id, "counterparty.example"), "issued");
  assert.throws(() => h.platform.getCapabilityStatus(capability.id, "someone-else.example"), NotAuthorized);
  h.platform.revoke(capability.id, "sub_1");
  assert.equal(h.platform.getCapabilityStatus(capability.id, "counterparty.example"), "revoked");
});
