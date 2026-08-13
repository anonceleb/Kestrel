/**
 * ADAPTER — Dakhil Post, fictional South Asian last-mile operator.
 *
 * Exists to prove the exchange layer isn't hard-coded to postal-meridia's
 * shape, in two structural ways:
 *
 *  1. Address format. Meridia buckets by postcode prefix. Dakhil serves
 *     addresses where the postcode is frequently absent or unreliable —
 *     last-mile delivery is landmark- and locality-led. Its geoBucket is
 *     derived from placeName/locality first and falls back to postcode
 *     only when neither is present.
 *  2. Key custody. Meridia's IdentityProofingPort trusts a self-asserted
 *     evidence string directly. Dakhil holds no signing key of its own: it
 *     can only raise a subject's tier by verifying a signed attestation
 *     from a participant already registered in packages/registry, capped
 *     at that attester's own accreditation tier.
 *
 * Deleting this directory must leave packages/core building and green
 * (INV-8), same as postal-meridia.
 */
import type { RoutingPort, IdentityProofingPort, ConfidentialPayload } from "../../../packages/core/src/core.ts";
import { asAddressPayload } from "../../../profiles/address/src/address.ts";
import { createHash } from "node:crypto";
import { Registry, type SignedEnvelope } from "../../../packages/registry/src/signing.ts";

export class DakhilSortation implements RoutingPort {
  async route(payload: ConfidentialPayload, service: string) {
    const address = asAddressPayload(payload);
    const geo = address.placeName || address.locality || address.postcode;
    const key = `${geo}|${service}`;
    const code = createHash("sha256").update(key).digest("hex").slice(0, 10).toUpperCase();
    return { routingCode: `DKH-${code}` };
  }
}

export class NoCustodyKey extends Error {}

/**
 * Holds no signing key of its own — see module docstring. `evidence` must
 * carry a signed envelope from a participant the shared registry already
 * trusts; a bare claim is refused outright rather than evaluated.
 */
export class DakhilIdentity implements IdentityProofingPort {
  #registry: Registry;

  constructor(registry: Registry) {
    this.#registry = registry;
  }

  async proof(_subjectRef: string, evidence: unknown): Promise<string> {
    const e = evidence as { envelope?: SignedEnvelope; body?: unknown; requestedTier?: 1 | 2 | 3 };
    if (!e?.envelope || e.body === undefined) {
      throw new NoCustodyKey("dakhil holds no key of its own; evidence must be a signed attestation");
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

/** Coarse geography from locality/placeName, not postcode structure. */
export function geoBucketFor(address: { locality: string; placeName?: string; postcode: string }): string {
  const geo = address.placeName || address.locality || address.postcode;
  return `DKH-${geo.slice(0, 2).toUpperCase()}`;
}
