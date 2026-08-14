/**
 * ZONE 1 — the vault. The only component in the system that can decrypt.
 *
 * Small on purpose. Everything it does not do is deliberate: it does not
 * serve counterparties, does not render UI, does not hold business logic.
 * It resolves a grant into a routing code and writes an audit record first.
 *
 * [Gap fix — closes web/candid-books.html gap 4, "Root-secret placement"] Pairwise-ID issuance lives
 * here, not on Platform. A Zone-2 method that took a `RootSecret` as a
 * plain argument would leave nothing in the type system or module boundary
 * to stop it being wired to a live network endpoint reachable from a
 * consumer's wallet, at which point the root secret crosses a zone
 * boundary the spec says it shouldn't.
 * `issuePairwiseId` exists only on `Vault`; `Platform` has no method
 * that accepts a `RootSecret` at all, so there is no code path by which a
 * root secret can reach Zone 2's public API surface — see
 * tests/grant-core/gap-fixes.test.ts (INV-32).
 *
 * [Gap fix — the same accountability shape as web/candid-books.html gap 1, "Registry write authorization"] `erase()` used to be callable
 * by anyone holding a `Vault` reference, with no caller-identity check. It
 * now requires a facilitator-signed `WriteAuth`, verified against the same
 * `Registry` that gates `Registry.register()`/`suspend()` — a consumer
 * erasure request must be countersigned by a facilitator's key, the same
 * accountability shape as every other registry-gated write in this system.
 */
import {
  Kms,
  open,
  seal,
  type Ciphertext,
} from "../../../packages/crypto/src/envelope.ts";
import {
  verify as verifyCap,
  CapabilityBurned,
  NonceLedger,
  type Capability,
} from "../../../packages/capability/src/capability.ts";
import {
  AuditLog,
  ConsentLedger,
  type ConfidentialPayload,
  type NotificationPort,
  type RoutingPort,
} from "../../../packages/core/src/core.ts";
import { OperatorKeyring, type OperatorPublicKey } from "../../../packages/labels/src/keyring.ts";
import { mintLabel, type SignedLabel } from "../../../packages/labels/src/label.ts";
import { derivePairwiseId, type RootSecret } from "../../../packages/identity/src/pairwise.ts";
import {
  Registry,
  WriteNotAuthorized,
  ParticipantSuspended,
  assertAuthorizesOperation,
  eraseOp,
  type WriteAuth,
  type WriteOperation,
} from "../../../packages/registry/src/signing.ts";

export class AuditPrecondition extends Error {}
export class PurposeMismatch extends Error {}

export type ConfidentialRecord = {
  id: string;
  subjectRef: string;
  tenantId: string;
  ciphertext: Ciphertext;
  geoBucket: string;
  assurance: string;
  status: "active" | "superseded" | "revoked";
};

export class Vault {
  #kms: Kms;
  #audit: AuditLog;
  #consent: ConsentLedger;
  #nonces: NonceLedger;
  #capSecret: Buffer;
  #routing: RoutingPort;
  #labelKeyring: OperatorKeyring;
  #registry: Registry;
  #records = new Map<string, ConfidentialRecord>();
  /** pairwiseId -> confidential record. Resolution table. Never leaves this service. */
  #bindings = new Map<string, string>();

  constructor(opts: {
    kms: Kms;
    audit: AuditLog;
    consent: ConsentLedger;
    nonces: NonceLedger;
    capSecret: Buffer;
    routing: RoutingPort;
    registry: Registry;
    /** Operator's rotating label-signing keys. Defaults to a fresh keyring. */
    labelKeyring?: OperatorKeyring;
  }) {
    this.#kms = opts.kms;
    this.#audit = opts.audit;
    this.#consent = opts.consent;
    this.#nonces = opts.nonces;
    this.#capSecret = opts.capSecret;
    this.#routing = opts.routing;
    this.#registry = opts.registry;
    this.#labelKeyring = opts.labelKeyring ?? new OperatorKeyring();
  }

  /**
   * [Gap fix] Pairwise-ID issuance — the sole place this system derives a
   * PairwiseId from a RootSecret. In-process only: there is no wire
   * protocol, no serializer, nothing exposing `RootSecret` past this method
   * signature. A consumer wallet in a real deployment would call the
   * equivalent of this method locally on-device, never over a network to
   * Zone 2 — see the class docstring above.
   */
  issuePairwiseId(root: RootSecret, counterpartyId: string): string {
    this.#registry.lookup(counterpartyId); // unknown participants get nothing
    return derivePairwiseId(root, counterpartyId);
  }

  store(rec: {
    id: string;
    subjectRef: string;
    tenantId: string;
    payload: ConfidentialPayload;
    geoBucket: string;
    assurance: string;
  }): ConfidentialRecord {
    const ciphertext = seal(this.#kms, rec.tenantId, rec.id, JSON.stringify(rec.payload));
    const record: ConfidentialRecord = {
      id: rec.id,
      subjectRef: rec.subjectRef,
      tenantId: rec.tenantId,
      ciphertext,
      geoBucket: rec.geoBucket,
      assurance: rec.assurance,
      status: "active",
    };
    this.#records.set(rec.id, record);
    return record;
  }

  bind(pairwiseId: string, recordId: string): void {
    this.#bindings.set(pairwiseId, recordId);
  }

  /** What Zone 2 may see. Ciphertext and a coarse bucket — nothing decryptable. */
  publicProjection(recordId: string) {
    const r = this.#records.get(recordId);
    if (!r) return undefined;
    return { id: r.id, geoBucket: r.geoBucket, assurance: r.assurance, status: r.status };
  }

  /**
   * THE INVARIANT: the audit write is a precondition of decryption, in the
   * same call, before plaintext exists. A decryption that cannot be
   * attributed to an actor, a purpose, and a consent reference is not a
   * policy violation — it is a crash.
   */
  async resolve(cap: Capability, actor: string): Promise<{ routingCode: string }> {
    verifyCap(this.#capSecret, cap);
    /**
     * [Gap fix — P0-5a] `lookup()` finds the participant but does not check
     * `status`. Spec §3 step 2 says "known, *active* registry participant";
     * the code previously enforced only "known," so a suspended participant
     * — one a facilitator had deliberately cut off — could still redeem.
     * `status` is checked here rather than switched to `registry.verify()`,
     * because verify() also demands a signed envelope, which resolve()'s
     * actor argument has never carried; that's the fulfiller-binding
     * question in spec §9 and is not conflated with this fix.
     */
    const participant = this.#registry.lookup(actor);
    if (participant.status !== "active") throw new ParticipantSuspended(actor);

    /**
     * Authorize BEFORE burning. The previous order — burn, then check
     * consent — meant any registered participant holding a valid grant
     * could permanently destroy it by attempting to redeem it: the burn
     * landed, the consent check then failed, and the *consented*
     * counterparty was left holding a grant the nonce ledger had already
     * spent. That is a denial-of-service against the subject's fulfilment,
     * reachable by anyone the grant legitimately passed through.
     *
     * Found by the turn loop on web/agentic-flow.html, which hands a
     * narrowed grant to a courier and then expects the merchant's own
     * redemption to still work.
     *
     * The burn stays the linearization point immediately before decryption,
     * so single-use enforcement under concurrency is unchanged: whichever
     * caller wins the burn is the one that proceeds (in a real deployment,
     * an atomic compare-and-set). Only unauthorized callers now leave the
     * ledger untouched.
     *
     * The indistinguishability property is preserved: a revoked grant and a
     * replayed one both raise CapabilityBurned, from paths a counterparty
     * cannot tell apart.
     */
    if (!this.#consent.isValidFor(cap.caveats.consentRef, cap.caveats.purpose, actor)) {
      throw new CapabilityBurned(cap.id);
    }

    /**
     * [Gap fix — P0-5c] Previously unconditional, which meant `singleUse:
     * false` was decorative: `burn()` recorded the id regardless, so a
     * caveat promising re-redemption silently became single-use anyway. No
     * caller mints `singleUse: false` today — every `mint()` call site
     * passes `true` — so this changes no shipped behaviour; it makes the
     * caveat's own meaning hold if a caller ever does.
     */
    if (cap.caveats.singleUse) this.#nonces.burn(cap.id); // replay dies here — CapabilityBurned

    const recordId = this.#bindings.get(cap.caveats.pairwiseId);
    if (!recordId) throw new Error("no binding for pairwiseId");
    const rec = this.#records.get(recordId)!;

    // Audit BEFORE plaintext. Not after.
    this.#audit.write({
      actor,
      purpose: cap.caveats.purpose,
      consentRef: cap.caveats.consentRef,
      recordId,
    });

    const payload = JSON.parse(
      open(this.#kms, rec.tenantId, recordId, rec.ciphertext),
    ) as ConfidentialPayload;

    const routed = await this.#routing.route(payload, cap.caveats.fulfiller);
    return routed; // routing code only — the payload does not leave this frame
  }

  /**
   * Deliberately unaudited path, present only so the invariant suite can
   * prove it is unreachable. It throws rather than decrypting.
   */
  async resolveUnaudited(_cap: Capability): Promise<never> {
    throw new AuditPrecondition("decryption without a prior audit record is not a supported path");
  }

  /**
   * [Gap fix] Right to erasure — now requires a facilitator-signed
   * `WriteAuth` over `{ subjectRef }`, verified against `Registry` exactly
   * the way `Registry.register()`/`suspend()` are. Destroys the shred salt;
   * every derived ciphertext dies with it.
   */
  erase(subjectRef: string, auth: WriteAuth): string[] {
    this.#requireFacilitator(auth, eraseOp(subjectRef));
    const erased: string[] = [];
    for (const [id, r] of this.#records) {
      if (r.subjectRef === subjectRef) {
        this.#kms.shred(id);
        erased.push(id);
      }
    }
    return erased;
  }

  #requireFacilitator(auth: WriteAuth, expected: WriteOperation): void {
    if (!auth) throw new WriteNotAuthorized("vault write requires a facilitator-signed credential");
    assertAuthorizesOperation(auth, expected);
    const signer = this.#registry.verify(auth.envelope, auth.body);
    if (signer.role !== "facilitator") {
      throw new WriteNotAuthorized(`signer ${signer.subscriberId} is not a facilitator`);
    }
  }

  /**
   * Failed-fulfilment notification: notifies the *consumer*, never the
   * counterparty. Deliberately a vault method — the counterparty-facing
   * platform never gets a subjectRef to notify, because it never holds one.
   */
  notifyFailedDelivery(cap: Capability, notifications: NotificationPort, event = "failed-delivery"): void {
    verifyCap(this.#capSecret, cap);
    const recordId = this.#bindings.get(cap.caveats.pairwiseId);
    if (!recordId) throw new Error("no binding for pairwiseId");
    const rec = this.#records.get(recordId)!;
    notifications.notify(rec.subjectRef, event);
  }



  /**
   * Ciphertext for a record — never plaintext, and no key material.
   *
   * [Gap fix — P0-4] This replaces `tryRead()`, which was a public,
   * unauthenticated `open()`: no grant, no actor, no audit record. Its
   * existence made INV-4 ("no decryption path exists that skips the audit
   * record") false as stated, because the invariant's test only proved
   * `resolveUnaudited()` throws.
   *
   * Handing back ciphertext discloses nothing Zone 2 is not already
   * entitled to hold, and it lets erasure be demonstrated the stronger way:
   * a caller holding both the ciphertext *and* the KMS still cannot read a
   * shredded record, because the per-record salt is gone.
   */
  ciphertextFor(recordId: string): Ciphertext | undefined {
    return this.#records.get(recordId)?.ciphertext;
  }

  /**
   * Mints a COSE-signed, offline-verifiable artifact for a grant — what
   * actually gets printed on the parcel (or handed to a call relay) as a
   * QR/token. Signed inside Zone 1; verifying it needs no vault, no
   * network, no key held here.
   */
  mintLabel(cap: Capability, opts: { contactChannel?: string } = {}): SignedLabel {
    return mintLabel(this.#capSecret, this.#labelKeyring, cap, opts);
  }

  /** What ships to a handheld scanner ahead of time. Public keys only, never private. */
  labelPublicMaterial(): OperatorPublicKey[] {
    return this.#labelKeyring.publicMaterial();
  }

  /** Rotates the label-signing key. Artifacts already printed keep verifying until they expire. */
  rotateLabelKey() {
    return this.#labelKeyring.rotate();
  }
}
