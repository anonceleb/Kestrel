/**
 * ZONE 2 — the platform. Orchestrates, mints grants, records consent.
 *
 * Structurally unable to betray the subject: it holds ciphertext and has no
 * key material, so "the operator becomes a honeypot" is answerable rather
 * than deniable. The honeypot is Zone 1: one service, one job, one audited
 * exit.
 *
 * [Gap fix — THREAT_MODEL.md §1, §2 item 2] `issuePairwiseId` does not
 * exist on this class at all — a Zone-2 method that accepted a `RootSecret`
 * as a plain argument would have no enforced boundary stopping it from
 * being reachable over a network from a consumer wallet. Pairwise-ID
 * issuance instead lives exclusively on
 * `services/vault`'s `Vault.issuePairwiseId` — there is no method anywhere
 * on `Platform`'s public surface that accepts a `RootSecret`, so a root
 * secret cannot reach Zone 2's API by construction, not by discipline.
 *
 * [Gap fix — THREAT_MODEL.md §2 item 4] No self-signed default policy. A
 * caller that doesn't supply a `PolicyStore` gets
 * `demoOnlyInsecurePolicyStore()` from packages/policy, which throws unless
 * `CFP_ALLOW_DEMO_POLICY=1` — every real construction path must hand
 * Platform an operator-signed policy explicitly.
 */
import { randomUUID } from "node:crypto";
import {
  attenuate,
  attenuateToReturn,
  attenuateToReattempt,
  DEFAULT_MAX_ATTEMPTS,
  mint,
  NonceLedger,
  type Capability,
  type Caveats,
} from "../../../packages/capability/src/capability.ts";
import { ConsentLedger, type MerchantView } from "../../../packages/core/src/core.ts";
import { Registry, type SignedEnvelope } from "../../../packages/registry/src/signing.ts";
import { PolicyStore, demoOnlyInsecurePolicyStore } from "../../../packages/policy/src/policy.ts";
import { AsyncExchange } from "../../../packages/network/src/exchange.ts";
import { UsageMeter } from "../../../packages/metering/src/meter.ts";
import {
  WebhookDispatcher,
  type WebhookConfig,
  type WebhookEvent,
  type DeliveryAttempt,
} from "../../../packages/webhooks/src/webhook.ts";

export class AssuranceNotAccepted extends Error {}
export class UnknownCapability extends Error {}
export class NotAuthorized extends Error {}

/**
 * The counterparty is the adversary in this threat model — the same
 * adversary a revocation is usually raised against. A counterparty-facing
 * status read may therefore never distinguish "the subject revoked this"
 * from "this expired" from any other reason a grant stopped being usable:
 * that distinction is exactly the information a revoking subject needs kept
 * from the counterparty. Two states, no more.
 */
export type CounterpartyCapabilityStatus = "issued" | "not-actionable";

/**
 * The subject polling the status of their own grant — a pull, never a
 * push. Deliberately three states, no more: "issued" does not mean "in
 * transit" or "out for delivery". Platform shares a ConsentLedger with
 * Vault but not a nonce store — it genuinely has no way to know whether
 * Vault has redeemed this grant.
 */
export type SubjectCapabilityStatus = "issued" | "revoked" | "expired";

export type FulfilmentRequest = {
  pairwiseId: string;
  units: number;
  fulfiller: string;
  channelKind: Caveats["channelKind"];
  /** Attempt budget for this fulfilment. Omitted means the network-policy default. */
  maxAttempts?: number;
};

export type GrantReady = { capability: Capability; merchantView: MerchantView };

/**
 * Generous enough that no existing caller notices it — 1000 createGrant
 * calls per participant per minute — but real, so a Platform that receives
 * no explicit `meter` still enforces a quota rather than silently having
 * none.
 */
function defaultUsageMeter(): UsageMeter {
  return new UsageMeter({ limit: 1000, windowMs: 60_000 });
}

export class Platform {
  #registry: Registry;
  #consent: ConsentLedger;
  #capSecret: Buffer;
  /**
   * Own copy, not shared with Vault's — Platform and Vault are different
   * zones/services and in a real deployment would reach a common nonce
   * store (Redis) over the network, not a shared JS reference.
   */
  #nonces: NonceLedger;
  /** Only what Zone 1 chose to project. No ciphertext keys, no confidential payloads. */
  #projections = new Map<string, { geoBucket: string; assurance: string }>();
  /** capabilityId -> the consentRef it was minted against. */
  #capabilityConsent = new Map<string, string>();
  /** Signed, versioned, hot-reloadable disclosure rules. See packages/policy/src/policy.ts. */
  #policy: PolicyStore;
  /** The create-grant action/on_action pair. See packages/network/src/exchange.ts. */
  #grants = new AsyncExchange<GrantReady>();
  #pendingGrants = new Map<string, { env: SignedEnvelope; req: FulfilmentRequest; subjectRef: string }>();
  /** Metered API. See packages/metering/src/meter.ts. */
  #meter: UsageMeter;
  /** subscriberId -> registered webhook endpoint. See packages/webhooks/src/webhook.ts. */
  #webhooks = new Map<string, WebhookConfig>();
  #webhookDispatcher: WebhookDispatcher;

  constructor(opts: {
    registry: Registry;
    consent: ConsentLedger;
    capSecret: Buffer;
    nonces?: NonceLedger;
    policy?: PolicyStore;
    meter?: UsageMeter;
    webhookDispatcher?: WebhookDispatcher;
  }) {
    this.#registry = opts.registry;
    this.#consent = opts.consent;
    this.#capSecret = opts.capSecret;
    this.#nonces = opts.nonces ?? new NonceLedger();
    this.#policy = opts.policy ?? demoOnlyInsecurePolicyStore();
    this.#meter = opts.meter ?? defaultUsageMeter();
    this.#webhookDispatcher = opts.webhookDispatcher ?? new WebhookDispatcher();
  }

  /** The signed policy artifact currently gating createGrant. */
  policy(): PolicyStore {
    return this.#policy;
  }

  /**
   * See the CounterpartyCapabilityStatus docstring above for why this is
   * exactly two states. Ownership-checked against consent.grantedTo.
   */
  getCapabilityStatus(capabilityId: string, subscriberId: string): CounterpartyCapabilityStatus {
    const consentRef = this.#capabilityConsent.get(capabilityId);
    if (!consentRef) throw new UnknownCapability(capabilityId);
    const entry = this.#consent.find(consentRef);
    if (!entry || entry.grantedTo !== subscriberId) {
      throw new NotAuthorized(`capability ${capabilityId} does not belong to participant ${subscriberId}`);
    }
    const actionable = !this.#consent.isRevoked(consentRef) && Date.now() <= entry.expiresAt;
    return actionable ? "issued" : "not-actionable";
  }

  /**
   * See the SubjectCapabilityStatus docstring above for why this is exactly
   * three states. Ownership-checked against consent.subject, not
   * consent.grantedTo — only the subject who granted this capability may
   * see why it stopped being actionable.
   */
  getSubjectCapabilityStatus(capabilityId: string, subjectRef: string): SubjectCapabilityStatus {
    const consentRef = this.#capabilityConsent.get(capabilityId);
    if (!consentRef) throw new UnknownCapability(capabilityId);
    const entry = this.#consent.find(consentRef);
    if (!entry || entry.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${capabilityId} does not belong to subject ${subjectRef}`);
    }
    if (this.#consent.isRevoked(consentRef)) return "revoked";
    if (Date.now() > entry.expiresAt) return "expired";
    return "issued";
  }

  registerWebhook(subscriberId: string, config: WebhookConfig): void {
    this.#webhooks.set(subscriberId, config);
  }

  webhookHistory(): readonly DeliveryAttempt[] {
    return this.#webhookDispatcher.history();
  }

  #fireWebhook(subscriberId: string, event: WebhookEvent): void {
    const config = this.#webhooks.get(subscriberId);
    if (!config) return;
    void this.#webhookDispatcher.deliver(config, event).catch(() => {});
  }

  learnProjection(pairwiseId: string, p: { geoBucket: string; assurance: string }): void {
    this.#projections.set(pairwiseId, p);
  }

  /**
   * Every grant is minted against a fresh, per-event consent record.
   * Standing consent is not representable in this API — by design.
   *
   * Which proofing-assurance labels are acceptable is read off
   * `this.#policy.active()`, a signed artifact, and that policy's hash
   * rides along on the consent entry so this exact decision stays
   * replayable against the rules that were actually in force. The check
   * below is list membership, not an ordinal comparison — the protocol
   * does not interpret what an assurance label means, only whether the
   * signed policy currently accepts it.
   *
   * [Gap fix — §2 item 7] The consent entry's `subject` is `subjectRef` as
   * passed by the caller, which by convention in this codebase is already a
   * pairwise reference (see profiles/*'s call sites and
   * tests/grant-core/gap-fixes.test.ts) — never the stable root identity.
   */
  createGrant(
    env: SignedEnvelope,
    req: FulfilmentRequest,
    subjectRef: string,
  ): { capability: Capability; merchantView: MerchantView } {
    const merchant = this.#registry.verify(env, req);
    this.#meter.consume(merchant.subscriberId);
    const proj = this.#projections.get(req.pairwiseId);
    if (!proj) throw new Error("unknown pairwiseId");
    const activePolicy = this.#policy.active();
    if (!activePolicy.policy.acceptableAssurance.includes(proj.assurance)) {
      throw new AssuranceNotAccepted(`assurance '${proj.assurance}' not in policy's acceptable set`);
    }

    const consent = this.#consent.append({
      subject: subjectRef,
      grantedTo: merchant.subscriberId,
      purpose: "delivery",
      scope: ["route-fulfilment"],
      at: Date.now(),
      expiresAt: Date.now() + 7 * 24 * 3600 * 1000,
      policyHash: activePolicy.hash,
    });

    const capability = mint(this.#capSecret, {
      pairwiseId: req.pairwiseId,
      purpose: "delivery",
      maxUnits: req.units,
      fulfiller: req.fulfiller,
      expiresAt: Date.now() + 14 * 24 * 3600 * 1000,
      singleUse: true,
      consentRef: consent.ref,
      channelKind: req.channelKind,
      maxAttempts: req.maxAttempts ?? DEFAULT_MAX_ATTEMPTS,
    });
    this.#capabilityConsent.set(capability.id, consent.ref);

    return {
      capability,
      merchantView: {
        pairwiseId: req.pairwiseId,
        geoBucket: proj.geoBucket,
        verifiedAssurance: proj.assurance,
        serviceLevel: "standard",
        estimatedDelivery: "3-5 days",
      },
    };
  }

  /**
   * The request half of create-grant as an action/on_action pair, after
   * Beckn's confirm/on_confirm. The synchronous return is an ack that the
   * request was accepted for processing — not the grant. Minting is
   * deferred to processBatch(), because a real operator settles these on
   * its own schedule.
   */
  requestGrant(env: SignedEnvelope, req: FulfilmentRequest, subjectRef: string): { transactionId: string } {
    const merchant = this.#registry.verify(env, req);
    this.#meter.consume(merchant.subscriberId);
    const transactionId = this.#grants.begin();
    this.#pendingGrants.set(transactionId, { env, req, subjectRef });
    return { transactionId };
  }

  onGrantReady(transactionId: string, handler: (result: GrantReady) => void): void {
    this.#grants.onCallback(transactionId, handler);
  }

  onGrantError(transactionId: string, handler: (error: unknown) => void): void {
    this.#grants.onError(transactionId, handler);
  }

  /**
   * Settles every grant request queued since the last run — the stand-in
   * for the operator's own batch cycle. Each transaction is settled
   * independently: one participant's rejection does not throw out of the
   * loop and does not touch any other participant's pending transaction.
   * Also fires the counterparty's registered webhook, if any.
   */
  processBatch(): void {
    for (const [transactionId, pending] of [...this.#pendingGrants]) {
      this.#pendingGrants.delete(transactionId);
      const subscriberId = pending.env.subscriberId;
      try {
        const result = this.createGrant(pending.env, pending.req, pending.subjectRef);
        this.#grants.callback(transactionId, result);
        this.#fireWebhook(subscriberId, {
          event: "grant.completed",
          transactionId,
          at: Date.now(),
          data: { capabilityId: result.capability.id, pairwiseId: result.merchantView.pairwiseId },
        });
      } catch (err) {
        this.#grants.fail(transactionId, err);
        this.#fireWebhook(subscriberId, {
          event: "grant.failed",
          transactionId,
          at: Date.now(),
          data: { reason: (err as Error).message },
        });
      }
    }
  }

  /**
   * Consumer-initiated return: a single-use, 72-hour, return-direction
   * grant. Minted via attenuateToReturn() — never mint() — so a return
   * structurally cannot exceed the originating grant's units or outlive its
   * validity window.
   */
  createReturn(originatingCap: Capability, actorId: string, subjectRef: string): Capability {
    const original = this.#consent.find(originatingCap.caveats.consentRef);
    if (!original) throw new UnknownCapability("no consent record for the originating grant");
    if (original.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${originatingCap.id} does not belong to subject ${subjectRef}`);
    }

    const returnWindowMs = 72 * 3600 * 1000;
    const consent = this.#consent.append({
      subject: original.subject,
      grantedTo: actorId,
      purpose: "return",
      scope: ["return-fulfilment"],
      at: Date.now(),
      expiresAt: Date.now() + returnWindowMs,
    });

    const returnCap = attenuateToReturn(
      this.#capSecret,
      originatingCap,
      {
        expiresAt: Math.min(originatingCap.caveats.expiresAt, Date.now() + returnWindowMs),
        consentRef: consent.ref,
      },
      actorId,
    );
    this.#capabilityConsent.set(returnCap.id, consent.ref);
    return returnCap;
  }

  /**
   * The NDR leg: authorise one more delivery attempt after a failed one.
   *
   * Ownership-checked against the *subject*, exactly as `createReturn` is —
   * a counterparty cannot extend its own attempt budget by asking, which is
   * the whole point of the counter living in signed caveats rather than in
   * the carrier's own system. Each re-attempt is its own consent event with
   * its own ledger entry, so "how many times did anyone try to reach this
   * person, and under what authority" is answerable from the ledger rather
   * than from a carrier's logs.
   *
   * Note what this method cannot do: it never learns the address, and it
   * never notifies the counterparty that an attempt failed. Failure reaches
   * the *subject*, through `Vault.notifyFailedDelivery` — Platform holds no
   * `subjectRef` to notify and no address to disclose. That asymmetry is
   * INV-15.
   */
  reattemptDelivery(originatingCap: Capability, actorId: string, subjectRef: string): Capability {
    const original = this.#consent.find(originatingCap.caveats.consentRef);
    if (!original) throw new UnknownCapability("no consent record for the originating grant");
    if (original.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${originatingCap.id} does not belong to subject ${subjectRef}`);
    }

    const consent = this.#consent.append({
      subject: original.subject,
      grantedTo: actorId,
      purpose: "delivery",
      scope: ["re-attempt-fulfilment"],
      at: Date.now(),
      expiresAt: original.expiresAt,
    });

    const reattemptCap = attenuateToReattempt(
      this.#capSecret,
      originatingCap,
      { expiresAt: Math.min(originatingCap.caveats.expiresAt, original.expiresAt), consentRef: consent.ref },
      actorId,
    );
    this.#capabilityConsent.set(reattemptCap.id, consent.ref);
    return reattemptCap;
  }

  /**
   * Revocation: the subject taps once and the token is dead mid-flight.
   * Burns the nonce and revokes the consent record — the latter is what
   * actually makes Vault.resolve() reject, via the same isValidFor() check
   * every resolution already runs.
   */
  revoke(capabilityId: string, subjectRef: string): void {
    const consentRef = this.#capabilityConsent.get(capabilityId);
    if (!consentRef) throw new UnknownCapability(capabilityId);
    const entry = this.#consent.find(consentRef);
    if (!entry || entry.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${capabilityId} does not belong to subject ${subjectRef}`);
    }
    this.#nonces.revoke(capabilityId);
    this.#consent.revoke(consentRef);
  }

  /**
   * Failed-fulfilment redirect: issues a fresh grant to a different
   * channel; the counterparty is never told the destination changed.
   * channelKind is the one field this path is allowed to change — units
   * and expiry are carried over unchanged.
   */
  redirectDelivery(cap: Capability, newChannelKind: Caveats["channelKind"], subjectRef: string): Capability {
    const original = this.#consent.find(cap.caveats.consentRef);
    if (!original) throw new UnknownCapability("no consent record for this capability");
    if (original.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${cap.id} does not belong to subject ${subjectRef}`);
    }

    const consent = this.#consent.append({
      subject: original.subject,
      grantedTo: original.grantedTo,
      purpose: cap.caveats.purpose,
      scope: ["redirect-fulfilment"],
      at: Date.now(),
      expiresAt: cap.caveats.expiresAt,
    });

    const redirected = attenuate(
      this.#capSecret,
      cap,
      { channelKind: newChannelKind, consentRef: consent.ref },
      subjectRef,
      { newId: randomUUID() },
    );
    this.#capabilityConsent.set(redirected.id, consent.ref);
    return redirected;
  }

  /**
   * Refund without return: zero vault calls. Settlement is a Zone 2/billing
   * concern; nothing here calls Vault.resolve() or reads a confidential
   * record.
   */
  refund(cap: Capability, actorId: string, subjectRef: string): void {
    const consentRef = this.#capabilityConsent.get(cap.id) ?? cap.caveats.consentRef;
    const original = this.#consent.find(consentRef);
    if (!original || original.subject !== subjectRef) {
      throw new NotAuthorized(`capability ${cap.id} does not belong to subject ${subjectRef}`);
    }
    this.#nonces.revoke(cap.id);
    this.#consent.append({
      subject: original.subject,
      grantedTo: actorId,
      purpose: "refund",
      scope: ["refund"],
      at: Date.now(),
      expiresAt: Date.now(),
    });
  }
}

/**
 * Zone 3 storage, as a counterparty would actually keep it. The invariant
 * suite introspects this shape and fails the build if a PII-shaped column
 * appears.
 */
export class MerchantDatabase {
  customers: MerchantView[] = [];
  orders: { orderId: string; pairwiseId: string; capabilityId: string }[] = [];

  save(view: MerchantView, capability: Capability): void {
    if (!this.customers.find((c) => c.pairwiseId === view.pairwiseId)) this.customers.push(view);
    this.orders.push({
      orderId: randomUUID(),
      pairwiseId: view.pairwiseId,
      capabilityId: capability.id,
    });
  }

  columns(): string[] {
    return [
      ...new Set([
        ...this.customers.flatMap((c) => Object.keys(c)),
        ...this.orders.flatMap((o) => Object.keys(o)),
      ]),
    ];
  }
}
