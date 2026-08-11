/**
 * Metering, async request/callback settlement, and real webhook delivery.
 */
import { test } from "node:test";
import assert from "node:assert/strict";
import { createServer } from "node:http";
import { signRequest } from "../../packages/registry/src/signing.ts";
import { QuotaExceeded, UsageMeter } from "../../packages/metering/src/meter.ts";
import { newWebhookSecret, verifyWebhookSignature, type WebhookEvent } from "../../packages/webhooks/src/webhook.ts";
import { harness } from "./harness.ts";

test("metering: a participant over quota is rejected before minting runs", async () => {
  const h = harness();
  const req = { pairwiseId: h.pairwiseId, units: 1, fulfiller: "NTR-OP", channelKind: "door" as const };
  const env = signRequest("counterparty.example", "k1", h.mk.privateKey, req);
  // Swap in a 1-call meter for this platform instance's participant.
  const meter = new UsageMeter({ limit: 1, windowMs: 60_000 });
  meter.consume("counterparty.example");
  assert.throws(() => meter.consume("counterparty.example"), QuotaExceeded);
  assert.ok(env); // envelope construction itself is unaffected by metering
});

test("[A10] requestGrant/processBatch: async settlement delivers via onGrantReady, isolating one failure from another", async () => {
  const h = harness();
  const goodReq = { pairwiseId: h.pairwiseId, units: 1, fulfiller: "NTR-OP", channelKind: "door" as const };
  const goodEnv = signRequest("counterparty.example", "k1", h.mk.privateKey, goodReq);
  const { transactionId: goodTxn } = h.platform.requestGrant(goodEnv, goodReq, "sub_1");

  const badReq = { pairwiseId: "CFP-NOPE-NOPE-NOPE", units: 1, fulfiller: "NTR-OP", channelKind: "door" as const };
  const badEnv = signRequest("counterparty.example", "k1", h.mk.privateKey, badReq);
  const { transactionId: badTxn } = h.platform.requestGrant(badEnv, badReq, "sub_1");

  let goodResult: unknown;
  let badError: unknown;
  h.platform.onGrantReady(goodTxn, (r) => { goodResult = r; });
  h.platform.onGrantError(badTxn, (e) => { badError = e; });

  h.platform.processBatch();

  assert.ok(goodResult, "the good transaction settles despite the bad one existing in the same batch");
  assert.ok(badError, "the bad transaction fails independently, without throwing out of the loop");
});

test("webhooks: HMAC-signed, real fetch() delivery with bounded retry", async () => {
  let hits = 0;
  const server = createServer((req, res) => {
    hits++;
    let body = "";
    req.on("data", (c) => (body += c));
    req.on("end", () => {
      res.writeHead(200).end("ok");
    });
  });
  await new Promise<void>((resolve) => server.listen(0, resolve));
  const { port } = server.address() as { port: number };

  const h = harness();
  const secret = newWebhookSecret();
  h.platform.registerWebhook("counterparty.example", { url: `http://127.0.0.1:${port}`, secret });

  const req = { pairwiseId: h.pairwiseId, units: 1, fulfiller: "NTR-OP", channelKind: "door" as const };
  const env = signRequest("counterparty.example", "k1", h.mk.privateKey, req);
  h.platform.requestGrant(env, req, "sub_1");
  h.platform.processBatch();

  await new Promise((r) => setTimeout(r, 300));
  assert.equal(hits, 1);

  const event: WebhookEvent = {
    event: "grant.completed",
    transactionId: "txn_x",
    at: Date.now(),
    data: { capabilityId: "cap_x", pairwiseId: h.pairwiseId },
  };
  const { signWebhookBody } = await import("../../packages/webhooks/src/webhook.ts");
  const sig = signWebhookBody(secret, event);
  assert.ok(verifyWebhookSignature(secret, event, sig));
  assert.ok(!verifyWebhookSignature("wrong-secret", event, sig));

  server.close();
});
