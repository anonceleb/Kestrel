/**
 * Network participant registry + request signing.
 *
 * Lifted from ONDC/Beckn: every request between participants is signed with the
 * sender's Ed25519 key and verified against a public key published in a shared
 * registry. Two properties this buys that mTLS alone does not:
 *
 *   1. Non-repudiation. A signed request is evidence, not just an authenticated
 *      channel — it survives past the connection that carried it.
 *   2. Participant identity is a network fact, not a deployment fact. Onboarding
 *      a participant is a registry entry, not a firewall change.
 *
 * Signature envelope follows the Beckn shape:
 *   keyId="<participant_id>|<key_id>|ed25519", created, expires, digest
 *
 * [Gap fix — THREAT_MODEL.md §2 item 5] `register()`/`suspend()` used to be
 * unauthenticated method calls: anyone holding a `Registry` reference could
 * admit or suspend any participant. Both now require a signed credential
 * from an already-registered, active `role: "facilitator"` participant — the
 * same Ed25519 envelope shape every other inter-participant request uses.
 * The registry itself must be seeded with a first facilitator at
 * construction time (`new Registry(genesisFacilitator)`), the same way a
 * root CA is a trust anchor accepted out-of-band rather than proven by a
 * signature from something that doesn't exist yet.
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

export type ParticipantRole = "merchant" | "operator" | "brand" | "platform" | "facilitator";

export type Participant = {
  participantId: string;
  role: ParticipantRole;
  keyId: string;
  publicKey: string; // base64 raw SPKI
  /** Accreditation tier, after UIDAI's AUA/KUA licensing model. Gates grant scope. */
  tier: 1 | 2 | 3;
  status: "active" | "suspended";
};

export type SignedEnvelope = {
  participantId: string;
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

export function digestOf(body: unknown): string {
  return createHash("sha256").update(canonical(body)).digest("base64");
}

/** Deterministic JSON. Signature stability depends on key order being fixed. */
export function canonical(value: unknown): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value);
  if (Array.isArray(value)) return `[${value.map(canonical).join(",")}]`;
  const obj = value as Record<string, unknown>;
  const keys = Object.keys(obj).sort();
  return `{${keys.map((k) => `${JSON.stringify(k)}:${canonical(obj[k])}`).join(",")}}`;
}

function signingString(e: Omit<SignedEnvelope, "signature">): string {
  return `(created): ${e.created}\n(expires): ${e.expires}\ndigest: ${e.digest}`;
}

export function signRequest(
  participantId: string,
  keyId: string,
  privateKeyB64: string,
  body: unknown,
  ttlSeconds = 300,
): SignedEnvelope {
  const created = Math.floor(Date.now() / 1000);
  const base = {
    participantId,
    keyId,
    created,
    expires: created + ttlSeconds,
    digest: digestOf(body),
  };
  const signature = edSign(null, Buffer.from(signingString(base)), priv(privateKeyB64));
  return { ...base, signature: signature.toString("base64") };
}

/** Registry write credential: a signed envelope from a facilitator, over the body being written. */
export type WriteAuth = { envelope: SignedEnvelope; body: unknown };

export class Registry {
  #participants = new Map<string, Participant>();

  /**
   * [Gap fix] `genesisFacilitator` seeds the trust anchor — accepted
   * out-of-band, the same way a root CA certificate is, because nothing
   * already in the registry could sign a credential for the first entry.
   * Every subsequent register()/suspend() call must present a WriteAuth
   * signed by a facilitator this chain of trust already admits.
   */
  constructor(genesisFacilitator?: Participant) {
    if (genesisFacilitator) this.#participants.set(genesisFacilitator.participantId, genesisFacilitator);
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
  #requireFacilitator(auth: WriteAuth, now = Math.floor(Date.now() / 1000)): Participant {
    if (!auth) throw new WriteNotAuthorized("registry write requires a facilitator-signed credential");
    const signer = this.#participants.get(auth.envelope.participantId);
    if (!signer) throw new WriteNotAuthorized(`unknown signer ${auth.envelope.participantId}`);
    if (signer.status !== "active") throw new WriteNotAuthorized(`signer ${signer.participantId} is suspended`);
    if (signer.role !== "facilitator") {
      throw new WriteNotAuthorized(`signer ${signer.participantId} is not a facilitator`);
    }
    this.#verifySignature(signer, auth.envelope, auth.body, now);
    return signer;
  }

  /** [Gap fix] Now requires a facilitator-signed WriteAuth over `p`. */
  register(p: Participant, auth: WriteAuth): void {
    this.#requireFacilitator(auth);
    this.#participants.set(p.participantId, p);
  }

  lookup(participantId: string): Participant {
    const p = this.#participants.get(participantId);
    if (!p) throw new ParticipantUnknown(participantId);
    return p;
  }

  /** [Gap fix] Now requires a facilitator-signed WriteAuth over `{ participantId }`. */
  suspend(participantId: string, auth: WriteAuth): void {
    this.#requireFacilitator(auth);
    const p = this.lookup(participantId);
    this.#participants.set(participantId, { ...p, status: "suspended" });
  }

  all(): Participant[] {
    return [...this.#participants.values()];
  }

  /** Verifies signature, freshness, body integrity, and participant standing. */
  verify(env: SignedEnvelope, body: unknown, now = Math.floor(Date.now() / 1000)): Participant {
    const p = this.lookup(env.participantId);
    if (p.status !== "active") throw new ParticipantSuspended(env.participantId);
    this.#verifySignature(p, env, body, now);
    return p;
  }
}
