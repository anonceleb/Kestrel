/**
 * COSE-signed, offline-verifiable redemption artifacts.
 *
 * "The label QR is a COSE-signed compact token, offline-verifiable by a
 * handheld scanner with no network. The confidential attribute appears
 * nowhere in the printed artifact."
 *
 * An artifact is a COSE_Sign1 structure (RFC 8152 §4.2), Ed25519-signed by
 * the operator's current rotating key, wrapping claims derived from an
 * already-verified grant. It is minted inside Zone 1 — the vault is the
 * only thing with access to the signing keys — but verifying it needs
 * nothing from Zone 1 at all: a scanner holding only public key material
 * synced ahead of time can check authenticity, freshness, and origin with no
 * network call. That split is the offline-verifiable property.
 *
 * Never present: the underlying attribute, a name, a phone number. Where a
 * contact channel is relevant, only its hash travels — the Aadhaar
 * offline-eKYC pattern of "a hash of the registered mobile number", never
 * the number itself. Generalized from Ship2MyID's `LabelClaims` (address
 * vocabulary: s2id/maxWeightKg/carrier/destinationKind) to `ArtifactClaims`
 * (pairwiseId/maxUnits/fulfiller/channelKind) — this file has no opinion on
 * whether the fulfilled action is a parcel or a phone call.
 */
import { createHash, createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { Tagged, decodeCBOR, encodeCBOR } from "./cbor.ts";
import type { OperatorKeyring, OperatorPublicKey } from "./keyring.ts";
import { verify as verifyCap, type Capability } from "../../capability/src/capability.ts";

export class LabelInvalid extends Error {}
export class LabelExpired extends Error {}
export class LabelKeyUnknown extends Error {}

/** COSE algorithm identifier for EdDSA (IANA COSE Algorithms registry). */
const ALG_EDDSA = -8;
/** COSE header labels (RFC 8152 §3.1). */
const HDR_ALG = 1;
const HDR_KID = 4;
/** COSE_Sign1 CBOR tag (RFC 8152 §4.2). */
const COSE_SIGN1_TAG = 18;

/** Claim keys inside the artifact payload. Small ints, CWT-style — not IANA-registered, this is our own compact private format. */
const CLAIM_PAIRWISE_ID = 1;
const CLAIM_PURPOSE = 2;
const CLAIM_MAX_UNITS = 3;
const CLAIM_FULFILLER = 4;
const CLAIM_CHANNEL_KIND = 5;
const CLAIM_EXPIRES_AT = 6; // epoch seconds
const CLAIM_CAPABILITY_ID = 7;
const CLAIM_CONTACT_CHANNEL_HASH = 8; // sha256 digest bytes — never the channel itself

export type ArtifactClaims = {
  pairwiseId: string;
  purpose: string;
  maxUnits: number;
  fulfiller: string;
  channelKind: string;
  expiresAt: number; // epoch seconds
  capabilityId: string;
  /** sha256 hex of a contact channel (phone/email). The channel itself is never carried. */
  contactChannelHash?: string;
};

export type SignedLabel = {
  /** Base64url COSE_Sign1 bytes — what actually goes into the printed QR. */
  token: string;
  claims: ArtifactClaims;
  kid: string;
};

export function hashContactChannel(channel: string): string {
  return createHash("sha256").update(channel).digest("hex");
}

function privKeyObj(base64Pkcs8: string) {
  return createPrivateKey({ key: Buffer.from(base64Pkcs8, "base64"), type: "pkcs8", format: "der" });
}
function pubKeyObj(base64Spki: string) {
  return createPublicKey({ key: Buffer.from(base64Spki, "base64"), type: "spki", format: "der" });
}

function claimsToMap(c: ArtifactClaims): Map<number, unknown> {
  const m = new Map<number, unknown>();
  m.set(CLAIM_PAIRWISE_ID, c.pairwiseId);
  m.set(CLAIM_PURPOSE, c.purpose);
  m.set(CLAIM_MAX_UNITS, c.maxUnits);
  m.set(CLAIM_FULFILLER, c.fulfiller);
  m.set(CLAIM_CHANNEL_KIND, c.channelKind);
  m.set(CLAIM_EXPIRES_AT, c.expiresAt);
  m.set(CLAIM_CAPABILITY_ID, c.capabilityId);
  if (c.contactChannelHash) m.set(CLAIM_CONTACT_CHANNEL_HASH, Buffer.from(c.contactChannelHash, "hex"));
  return m;
}

function mapToClaims(m: Map<unknown, unknown>): ArtifactClaims {
  const contactHash = m.get(CLAIM_CONTACT_CHANNEL_HASH) as Buffer | undefined;
  return {
    pairwiseId: m.get(CLAIM_PAIRWISE_ID) as string,
    purpose: m.get(CLAIM_PURPOSE) as string,
    maxUnits: m.get(CLAIM_MAX_UNITS) as number,
    fulfiller: m.get(CLAIM_FULFILLER) as string,
    channelKind: m.get(CLAIM_CHANNEL_KIND) as string,
    expiresAt: m.get(CLAIM_EXPIRES_AT) as number,
    capabilityId: m.get(CLAIM_CAPABILITY_ID) as string,
    ...(contactHash ? { contactChannelHash: contactHash.toString("hex") } : {}),
  };
}

/** RFC 8152 §4.4 Sig_structure for a COSE_Sign1 ("Signature1"). */
function sigStructure(protectedBytes: Buffer, payloadBytes: Buffer): Buffer {
  return encodeCBOR(["Signature1", protectedBytes, Buffer.alloc(0), payloadBytes]);
}

/**
 * Mints a COSE_Sign1 artifact from an already-verified grant. Refuses to
 * print an artifact for a grant that doesn't check out — a forged or
 * expired grant never gets a legitimate-looking artifact.
 */
export function mintLabel(
  capSecret: Buffer,
  keyring: OperatorKeyring,
  cap: Capability,
  opts: { contactChannel?: string } = {},
): SignedLabel {
  verifyCap(capSecret, cap);

  const key = keyring.current();
  const claims: ArtifactClaims = {
    pairwiseId: cap.caveats.pairwiseId,
    purpose: cap.caveats.purpose,
    maxUnits: cap.caveats.maxUnits,
    fulfiller: cap.caveats.fulfiller,
    channelKind: cap.caveats.channelKind,
    expiresAt: Math.floor(cap.caveats.expiresAt / 1000),
    capabilityId: cap.id,
    ...(opts.contactChannel ? { contactChannelHash: hashContactChannel(opts.contactChannel) } : {}),
  };

  const protectedHeader = encodeCBOR(
    new Map<number, unknown>([
      [HDR_ALG, ALG_EDDSA],
      [HDR_KID, Buffer.from(key.kid, "utf8")],
    ]),
  );
  const payload = encodeCBOR(claimsToMap(claims));
  const signature = edSign(null, sigStructure(protectedHeader, payload), privKeyObj(key.privateKey));

  const message = new Tagged(COSE_SIGN1_TAG, [protectedHeader, new Map(), payload, signature]);
  const token = encodeCBOR(message).toString("base64url");
  return { token, claims, kid: key.kid };
}

/**
 * Offline verification. Takes only public key material a scanner cached
 * ahead of time — no vault reference, no consent lookup, no network call.
 * This proves the artifact is authentic and fresh; it is deliberately not
 * the same check as `Vault.resolve()`, which is the audited, online,
 * single-use redemption path.
 */
export function verifyLabelOffline(
  publicKeys: OperatorPublicKey[],
  token: string,
  now = Date.now(),
): ArtifactClaims {
  let decoded: unknown;
  try {
    decoded = decodeCBOR(Buffer.from(token, "base64url"));
  } catch {
    throw new LabelInvalid("not a well-formed COSE artifact");
  }
  if (!(decoded instanceof Tagged) || decoded.tag !== COSE_SIGN1_TAG) {
    throw new LabelInvalid("not a COSE_Sign1 structure");
  }
  const parts = decoded.value;
  if (!Array.isArray(parts) || parts.length !== 4) {
    throw new LabelInvalid("malformed COSE_Sign1 array");
  }
  const [protectedBytes, , payloadBytes, signature] = parts as [Buffer, Map<unknown, unknown>, Buffer, Buffer];

  const header = decodeCBOR(protectedBytes) as Map<unknown, unknown>;
  if (header.get(HDR_ALG) !== ALG_EDDSA) throw new LabelInvalid("unsupported or missing algorithm");
  const kidBytes = header.get(HDR_KID) as Buffer | undefined;
  if (!kidBytes) throw new LabelInvalid("missing key id");
  const kid = kidBytes.toString("utf8");

  const key = publicKeys.find((k) => k.kid === kid);
  if (!key) throw new LabelKeyUnknown(`no cached public key for kid ${kid}`);
  if (now < key.notBefore || now > key.notAfter) {
    throw new LabelKeyUnknown(`key ${kid} is outside its validity window`);
  }

  const ok = edVerify(null, sigStructure(protectedBytes, payloadBytes), pubKeyObj(key.publicKey), signature);
  if (!ok) throw new LabelInvalid("signature verification failed");

  const claims = mapToClaims(decodeCBOR(payloadBytes) as Map<unknown, unknown>);
  if (now > claims.expiresAt * 1000) throw new LabelExpired(claims.capabilityId);
  return claims;
}
