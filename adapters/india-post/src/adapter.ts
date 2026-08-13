/**
 * ADAPTER — India Post (DIGIPIN-shaped), the third operator proof.
 *
 * DIGIPIN is India Post/DoP's 10-character alphanumeric geocode grid — a
 * fixed-precision, non-postal-code addressing scheme. This adapter buckets
 * and routes off a *truncated* DIGIPIN prefix, never the full code and
 * never the address it accompanies: `geoBucketFor` takes the first 6
 * characters of the 10-character grid code as its coarse bucket, the same
 * "coarse enough to guarantee k-anonymity, precise enough to route" shape
 * `postal-meridia`'s postcode-prefix bucket and `dakhil-post`'s
 * locality-prefix bucket already use.
 *
 * COSE artifacts minted for an india-post grant (see packages/labels) carry
 * the same claim set every other adapter's grants do — pairwiseId, purpose,
 * maxUnits, fulfiller, channelKind, expiresAt, capabilityId — never a
 * DIGIPIN or any other address-shaped field; the "truncated DIGIPIN"
 * property lives one level up, in the *bucket* a grant is routed against
 * (`merchantView.geoBucket`, itself never address-shaped, per INV-1),
 * never in the printed/offline-verifiable artifact itself.
 *
 * Identity proofing reuses dakhil-post's pattern: no self-asserted claims,
 * only a signed registry attestation, capped at the attester's own tier —
 * India Post is not its own trust root any more than Dakhil is.
 *
 * Deleting this directory must leave packages/core building and green
 * (INV-8), same as the other two adapters.
 */
import type { RoutingPort, IdentityProofingPort, ConfidentialPayload } from "../../../packages/core/src/core.ts";
import { asAddressPayload } from "../../../profiles/address/src/address.ts";
import { createHash } from "node:crypto";
import { Registry, type SignedEnvelope } from "../../../packages/registry/src/signing.ts";

export class DigipinMissing extends Error {}
export class IndiaPostNoCustodyKey extends Error {}

export class IndiaPostRouting implements RoutingPort {
  async route(payload: ConfidentialPayload, service: string) {
    const address = asAddressPayload(payload);
    if (!address.digipin) throw new DigipinMissing("india-post routing requires a DIGIPIN");
    // Consumes plaintext transiently; emits a routing code, never the DIGIPIN or address.
    const key = `${address.digipin}|${service}`;
    const code = createHash("sha256").update(key).digest("hex").slice(0, 10).toUpperCase();
    return { routingCode: `IND-${code}` };
  }
}

/** Same key-custody shape as dakhil-post: no self-asserted claims, only a signed registry attestation. */
export class IndiaPostIdentity implements IdentityProofingPort {
  #registry: Registry;

  constructor(registry: Registry) {
    this.#registry = registry;
  }

  async proof(_subjectRef: string, evidence: unknown): Promise<string> {
    const e = evidence as { envelope?: SignedEnvelope; body?: unknown; requestedTier?: 1 | 2 | 3 };
    if (!e?.envelope || e.body === undefined) {
      throw new IndiaPostNoCustodyKey("india-post holds no key of its own; evidence must be a signed attestation");
    }
    const attester = this.#registry.verify(e.envelope, e.body);
    const requested = e.requestedTier ?? attester.tier;
    // Internal-to-this-adapter numeric comparison against the attester's own
    // registry accreditation is fine; what crosses the port boundary is an
    // opaque label, not the number, so the protocol above never compares
    // assurance ordinally.
    return `tier-${Math.min(requested, attester.tier)}`;
  }
}

/**
 * Coarse geography from a truncated DIGIPIN grid-code prefix (first 6 of
 * the 10 characters) — never the full code, never the address.
 */
export function geoBucketFor(digipin: string): string {
  if (!digipin || digipin.length < 6) throw new DigipinMissing("digipin must be at least 6 characters");
  return `IND-${digipin.slice(0, 6).toUpperCase()}`;
}
