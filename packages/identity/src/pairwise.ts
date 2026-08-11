/**
 * Pairwise identifiers — the anti-correlation primitive.
 *
 * Modelled on UIDAI's UID Token: an identifier that is *stable for a given
 * (subject, counterparty) pair* but carries no join key across counterparties.
 * Two counterparties holding an identifier for the same subject cannot
 * discover that fact by comparing databases.
 *
 * Stability matters as much as unlinkability: a counterparty must be able to
 * recognise a returning subject, or the privacy design costs them the
 * continuity data they would otherwise refuse to give up.
 *
 * Generic on purpose: nothing here is address-shaped. `deriveEphemeralId` is
 * used by whichever attribute profile needs a single-use handle (e.g.
 * gifting in the address profile); this package has no opinion on why.
 */
import { createHmac, randomBytes } from "node:crypto";

const ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"; // Crockford base32: no I/L/O/U

export type RootSecret = Buffer;

export function newRootSecret(): RootSecret {
  return randomBytes(32);
}

function base32(buf: Buffer, chars: number): string {
  let out = "";
  for (let i = 0; i < chars; i++) out += ALPHABET[buf[i]! % ALPHABET.length];
  return out;
}

/**
 * PairwiseId = base32(HMAC-SHA256(root_secret, counterparty_id))
 * Deterministic, so no storage is required; irreversible, so possession of a
 * PairwiseId reveals nothing about the root identity.
 */
export function derivePairwiseId(root: RootSecret, counterpartyId: string, prefix = "CFP"): string {
  const mac = createHmac("sha256", root).update(`cfp/pairwise/${counterpartyId}`).digest();
  const body = base32(mac, 12);
  return `${prefix}-${body.slice(0, 4)}-${body.slice(4, 8)}-${body.slice(8, 12)}`;
}

/**
 * Single-use identifiers, for flows where the grantor must be able to
 * address someone with no standing relationship and must learn nothing
 * reusable in the process (e.g. gift delivery in the address profile).
 */
export function deriveEphemeralId(root: RootSecret, nonce: string, prefix = "GFT"): string {
  return derivePairwiseId(root, `ephemeral/${nonce}`, prefix);
}

/**
 * Linkability oracle used by the invariant suite. Returns 0 when two
 * identifiers for the same subject share no exploitable structure.
 * Deliberately crude — it exists to fail loudly if someone "optimises"
 * derivation into a shared prefix, not to be a formal unlinkability proof.
 */
export function linkabilityScore(a: string, b: string): number {
  if (a === b) return 1;
  const sa = a.replace(/-/g, "").slice(3);
  const sb = b.replace(/-/g, "").slice(3);
  let shared = 0;
  for (let i = 0; i < Math.min(sa.length, sb.length); i++) {
    if (sa[i] === sb[i]) shared++;
    else break;
  }
  return shared >= 4 ? shared / sa.length : 0;
}
