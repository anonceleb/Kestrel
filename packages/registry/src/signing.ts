/**
 * A Beckn-convention signing layer over a stub registry — not a Beckn
 * network-registry client. `Registry` is an in-process `Map` with its own
 * genesis facilitator as trust anchor; nothing here is a client of, or
 * synced with, any real Beckn/ONDC network registry. What *is* Beckn's is
 * the envelope wire format below (verified against the published spec) and
 * the FQDN-shaped `subscriberId` convention. What is *not* Beckn's:
 * `ParticipantRole` (`merchant | operator | brand | platform |
 * facilitator`) is a locally-defined vocabulary that occupies the slot
 * where Beckn's `subscriber_type` (`BAP | BPP | BG`) belongs, and `tier` is
 * a locally-defined accreditation ordinal, not a Beckn concept. See
 * `Participant.subscriberType` below for the two vocabularies kept
 * separate rather than conflated.
 *
 * `Registry` here **simulates the wire protocol of a real Beckn network
 * registry's subscribe/lookup surface, in-process.** A real deployment
 * swaps the in-memory `#participants` Map for HTTP calls to the network's
 * actual registry (e.g. the ONDC/Beckn gateway registry, or a DeDi-hosted
 * one) — the envelope generation/verification code below does not change
 * at all when that swap happens; only where `lookup()`/`register()`/
 * `suspend()` persist state changes.
 *
 * Every request between subscribers is signed with the sender's Ed25519 key
 * and verified against a public key published in the registry. Two
 * properties this buys that mTLS alone does not:
 *
 *   1. Non-repudiation. A signed request is evidence, not just an authenticated
 *      channel — it survives past the connection that carried it.
 *   2. Subscriber identity is a network fact, not a deployment fact. Onboarding
 *      a subscriber is a registry entry, not a firewall change.
 *
 * Signature envelope follows Beckn's real wire format (verified against
 * developers.becknprotocol.io/docs/infrastructure-layer-specification/authentication/subscriber-signing/):
 *
 *   Signature keyId="{subscriberId}|{uniqueKeyId}|ed25519",algorithm="ed25519",
 *     created={created},expires={expires},headers="(created) (expires) digest",
 *     signature={signature}
 *
 * signed over the exact string:
 *
 *   (created): {createdValue}
 *   (expires): {expiresValue}
 *   digest: BLAKE-512={base64Digest}
 *
 * where the digest is a BLAKE2b-512 hash of the canonical request body,
 * base64-encoded (`digestOf` below).
 *
 * Beckn's scheme name is "XEd25519" (XEdDSA over Curve25519), which is
 * usually described as a signature scheme derived from an X25519
 * (Diffie-Hellman) key. But for a key pair generated directly as Ed25519
 * — never derived from/converted to an X25519 key — XEdDSA and standard
 * EdDSA produce identical signatures: XEdDSA's extra step exists only to
 * make an X25519 key usable for signing, and is a no-op when the key was
 * already an Ed25519 signing key to begin with. That's the genesis-key
 * case this demo (and most real Beckn/ONDC deployments, which mint
 * Ed25519 keys directly for subscribers) uses, so Node's native
 * `sign`/`verify` with `ed25519` KeyObjects is a faithful implementation
 * here — this file does NOT claim to implement the general
 * X25519-key-conversion case of XEdDSA.
 *
 * [Gap fix — THREAT_MODEL.md §2 item 5] `register()`/`suspend()` used to be
 * unauthenticated method calls: anyone holding a `Registry` reference could
 * admit or suspend any subscriber. Both now require a signed credential
 * from an already-registered, active `role: "facilitator"` subscriber — the
 * same Ed25519 envelope shape every other inter-subscriber request uses.
 * The registry itself must be seeded with a first facilitator at
 * construction time (`new Registry(genesisFacilitator)`), the same way a
 * root CA is a trust anchor accepted out-of-band rather than proven by a
 * signature from something that doesn't exist yet. This refactor changes
 * identity shape (subscriberId -> subscriberId) and the digest algorithm
 * (SHA-256 -> BLAKE2b-512) — it does not touch that authorization model.
 */
import {
  createHash,
  generateKeyPairSync,
  sign as edSign,
  verify as edVerify,
  createPublicKey,
  createPrivateKey,
  type KeyObject,
} from "node:crypto";
import type { DeDiDirectoryPort } from "../../directory/src/directory.ts";

/** Locally-defined CFP role vocabulary — not Beckn's subscriber_type. See Participant.subscriberType. */
export type ParticipantRole = "merchant" | "operator" | "brand" | "platform" | "facilitator";

/** Beckn's own network-participant vocabulary, per the Beckn protocol spec. */
export type BecknSubscriberType = "BAP" | "BPP" | "BG";

export type Participant = {
  /** FQDN-shaped, per Beckn's subscriber_id convention (e.g. "merchant.example.org"). */
  subscriberId: string;
  role: ParticipantRole;
  /**
   * Beckn's own subscriber_type, carried as a distinct, optional field —
   * deliberately not derived from `role`. The two vocabularies answer
   * different questions (CFP's local grant-scope role vs. Beckn's
   * network-participant class) and asserting a mapping between them here
   * would be exactly the self-minted-vocabulary problem this field exists
   * to avoid. Left unset in this demo; a real deployment sets it from the
   * network registry it actually joins.
   */
  subscriberType?: BecknSubscriberType;
  keyId: string;
  publicKey: string; // base64 raw SPKI
  /**
   * A locally-defined accreditation ordinal, after UIDAI's AUA/KUA
   * licensing model — informational registry metadata about the
   * participant. It does not gate grant issuance: that decision is made by
   * `DisclosurePolicy.acceptableAssurance`, an opaque label the subject's
   * proofing evidence is checked against, kept deliberately separate from
   * this field so a network with no accreditation regime can still use the
   * grant grammar.
   */
  tier: 1 | 2 | 3;
  status: "active" | "suspended";
};

export type SignedEnvelope = {
  subscriberId: string;
  keyId: string;
  created: number;
  expires: number;
  digest: string;
  signature: string;
};

export class SignatureInvalid extends Error {}
export class ParticipantUnknown extends Error {}
export class ParticipantSuspended extends Error {}
/** [Gap fix] Thrown when a registry write is attempted without a valid facilitator-signed credential. */
export class WriteNotAuthorized extends Error {}

export function newKeyPair(): { publicKey: string; privateKey: string } {
  const { publicKey, privateKey } = generateKeyPairSync("ed25519");
  return {
    publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
    privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
  };
}

function pub(b64: string): KeyObject {
  return createPublicKey({ key: Buffer.from(b64, "base64"), type: "spki", format: "der" });
}
function priv(b64: string): KeyObject {
  return createPrivateKey({ key: Buffer.from(b64, "base64"), type: "pkcs8", format: "der" });
}

/** BLAKE2b-512 digest of the canonical request body, base64-encoded — Beckn's "BLAKE-512" convention. */
export function digestOf(body: unknown): string {
  return createHash("blake2b512").update(canonical(body)).digest("base64");
}

/** Deterministic JSON. Signature stability depends on key order being fixed. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}

/**
 * Beckn's exact signing-string shape — verified against
 * developers.becknprotocol.io/docs/infrastructure-layer-specification/authentication/subscriber-signing/.
 * Not an approximation: three fixed lines, `\n`-joined, no trailing newline.
 */
function signingString(e: Omit<SignedEnvelope, "signature">): string {
  return `(created): ${e.created}\n(expires): ${e.expires}\ndigest: BLAKE-512=${e.digest}`;
}

/**
 * The exact `Authorization` header value Beckn puts on the wire.
 *
 * [Gap fix] INV-34 used to assemble this string inside the test, which meant
 * the invariant proved the *test* could build Beckn's keyId shape, not that
 * this package emits it. The composite lives here now, so the wire format is
 * a shipped artifact with a test pointed at it rather than the other way
 * round. `SignedEnvelope` keeps `subscriberId` and `keyId` as separate
 * fields because that is what verification needs; this is the projection.
 */
export function authorizationHeader(e: SignedEnvelope): string {
  return (
    `Signature keyId="${e.subscriberId}|${e.keyId}|ed25519",algorithm="ed25519",` +
    `created=${e.created},expires=${e.expires},headers="(created) (expires) digest",` +
    `signature="${e.signature}"`
  );
}

export function signRequest(
  subscriberId: string,
  keyId: string,
  privateKeyB64: string,
  body: unknown,
  ttlSeconds = 300,
): SignedEnvelope {
  const created = Math.floor(Date.now() / 1000);
  const base = {
    subscriberId,
    keyId,
    created,
    expires: created + ttlSeconds,
    digest: digestOf(body),
  };
  const signature = edSign(null, Buffer.from(signingString(base)), priv(privateKeyB64));
  return { ...base, signature: signature.toString("base64") };
}

/**
 * The privileged operations a facilitator credential can authorize.
 *
 * [Gap fix] These exist because `#requireFacilitator` used to verify only
 * that *some* facilitator had signed *something*. The envelope's digest was
 * checked against `auth.body`, but nothing checked that `auth.body` was the
 * thing being written — so a leftover credential signed over one
 * participant could admit an entirely different one, including admitting an
 * attacker as a `facilitator` and thereby compromising every other
 * registry-gated control, `Vault.erase()` included.
 *
 * The `op` discriminator is part of the signed body on purpose. Without it,
 * a credential signed to suspend `x` could be replayed to *register* a
 * participant `{ subscriberId: "x" }`, since the bodies would match.
 * Authority is now bound to both the verb and the object.
 */
export type WriteOperation =
  | { op: "register"; participant: Participant }
  | { op: "suspend"; subscriberId: string }
  | { op: "erase"; subjectRef: string };

export const registerOp = (participant: Participant): WriteOperation => ({ op: "register", participant });
export const suspendOp = (subscriberId: string): WriteOperation => ({ op: "suspend", subscriberId });
export const eraseOp = (subjectRef: string): WriteOperation => ({ op: "erase", subjectRef });

/** Registry write credential: a signed envelope from a facilitator, over the exact operation being performed. */
export type WriteAuth = { envelope: SignedEnvelope; body: unknown };

/** Throws unless `auth.body` is byte-identical to the operation actually being performed. */
export function assertAuthorizesOperation(auth: WriteAuth, expected: WriteOperation): void {
  if (canonical(auth.body) !== canonical(expected)) {
    throw new WriteNotAuthorized(
      `credential is signed over a different operation than the one requested (expected ${expected.op})`,
    );
  }
}

export class Registry {
  #participants = new Map<string, Participant>();
  #directory: DeDiDirectoryPort | undefined;

  /**
   * [Gap fix] `genesisFacilitator` seeds the trust anchor — accepted
   * out-of-band, the same way a root CA certificate is, because nothing
   * already in the registry could sign a credential for the first entry.
   * Every subsequent register()/suspend() call must present a WriteAuth
   * signed by a facilitator this chain of trust already admits.
   *
   * `directory`, when supplied, is a `DeDiDirectoryPort` (see
   * packages/directory/src/directory.ts) that `suspend()` publishes
   * revocations through, so a third party can independently verify a
   * subscriber's suspended status by querying the directory rather than
   * trusting this registry's own `lookup()`.
   */
  constructor(genesisFacilitator?: Participant, directory?: DeDiDirectoryPort) {
    if (genesisFacilitator) this.#participants.set(genesisFacilitator.subscriberId, genesisFacilitator);
    this.#directory = directory;
  }

  #verifySignature(p: Participant, env: SignedEnvelope, body: unknown, now: number): void {
    if (p.keyId !== env.keyId) throw new SignatureInvalid("unknown key id for participant");
    if (now > env.expires) throw new SignatureInvalid("signature expired");
    if (digestOf(body) !== env.digest) throw new SignatureInvalid("body digest mismatch");
    const ok = edVerify(
      null,
      Buffer.from(signingString(env)),
      pub(p.publicKey),
      Buffer.from(env.signature, "base64"),
    );
    if (!ok) throw new SignatureInvalid("bad ed25519 signature");
  }

  /** Requires a signed credential from an active facilitator. Throws WriteNotAuthorized otherwise. */
  #requireFacilitator(auth: WriteAuth, expected: WriteOperation, now = Math.floor(Date.now() / 1000)): Participant {
    if (!auth) throw new WriteNotAuthorized("registry write requires a facilitator-signed credential");
    assertAuthorizesOperation(auth, expected);
    const signer = this.#participants.get(auth.envelope.subscriberId);
    if (!signer) throw new WriteNotAuthorized(`unknown signer ${auth.envelope.subscriberId}`);
    if (signer.status !== "active") throw new WriteNotAuthorized(`signer ${signer.subscriberId} is suspended`);
    if (signer.role !== "facilitator") {
      throw new WriteNotAuthorized(`signer ${signer.subscriberId} is not a facilitator`);
    }
    this.#verifySignature(signer, auth.envelope, auth.body, now);
    return signer;
  }

  /** [Gap fix] Now requires a facilitator-signed WriteAuth over `p`. */
  register(p: Participant, auth: WriteAuth): void {
    this.#requireFacilitator(auth, registerOp(p));
    this.#participants.set(p.subscriberId, p);
  }

  lookup(subscriberId: string): Participant {
    const p = this.#participants.get(subscriberId);
    if (!p) throw new ParticipantUnknown(subscriberId);
    return p;
  }

  /** [Gap fix] Now requires a facilitator-signed WriteAuth over `{ subscriberId }`. */
  suspend(subscriberId: string, auth: WriteAuth): void {
    this.#requireFacilitator(auth, suspendOp(subscriberId));
    const p = this.lookup(subscriberId);
    this.#participants.set(subscriberId, { ...p, status: "suspended" });
    this.#directory?.publishRevocation({
      subject: subscriberId,
      kind: "subscriber",
      publishedAt: Date.now(),
    });
  }

  all(): Participant[] {
    return [...this.#participants.values()];
  }

  /** Verifies signature, freshness, body integrity, and participant standing. */
  verify(env: SignedEnvelope, body: unknown, now = Math.floor(Date.now() / 1000)): Participant {
    const p = this.lookup(env.subscriberId);
    if (p.status !== "active") throw new ParticipantSuspended(env.subscriberId);
    this.#verifySignature(p, env, body, now);
    return p;
  }
}
