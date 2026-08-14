/**
 * ADAPTER — India Post (DIGIPIN-shaped), the third operator proof.
 *
 * DIGIPIN is India Post/DoP's 10-character alphanumeric geocode grid — a
 * fixed-precision, non-postal-code addressing scheme. This adapter buckets
 * and routes off a *truncated* DIGIPIN prefix, never the full code and
 * never the address it accompanies: `geoBucketFor` discloses the finest
 * prefix whose cell still holds `K_ANON_FLOOR` people at the deployment's
 * own density figure, so the truncation length is a computed consequence
 * of the core's k-floor rather than a constant with a claim attached to
 * it. `postal-meridia`'s postcode-prefix and `dakhil-post`'s
 * locality-prefix buckets remain fixed-width: neither grid has a published
 * cell geometry to derive a ladder from, and inventing one to match this
 * adapter would be the same unearned claim in a new place.
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
import type { RoutingPort, IdentityProofingPort, ConfidentialPayload, DensityPort } from "../../../packages/core/src/core.ts";
import { K_ANON_FLOOR, rungMeetingFloor } from "../../../packages/core/src/core.ts";
import { asAddressPayload } from "../../../profiles/address/src/address.ts";
import { DIGIPIN_LADDER } from "../../../profiles/address/src/precision.ts";
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
 * Coarse geography from a truncated DIGIPIN grid-code prefix — never the
 * full code, never the address.
 *
 * How many characters is **derived, not chosen.** The prefix length is the
 * finest rung of `DIGIPIN_LADDER` whose cell still holds at least `k`
 * people at the density this deployment can defend, per
 * `rungMeetingFloor`. `k` defaults to the core's `K_ANON_FLOOR` — the same
 * constant that governs brand-cohort visibility, so there is exactly one
 * k-floor in this codebase rather than a geographic claim floating free of
 * the enforced one.
 *
 * This replaces a hard-coded `slice(0, 6)` whose docstring asserted it was
 * "coarse enough to guarantee k-anonymity." Nothing computed that. At
 * k=25 a 6-character cell (~0.90 km²) needs ~28 people/km² to hold, which
 * large parts of rural India fall below — so the old constant was not
 * merely underived, it was wrong wherever density was thin. Now the
 * sparse case widens the cell instead of silently under-protecting, and
 * `PrecisionFloorUnsatisfiable` surfaces the case where no rung works at
 * all. See `spec/CFP-v0.x.md` §6a for the published ladder and the
 * concession the table forces.
 *
 * `minChars` lets an operator declare the precision its sortation actually
 * requires. Supplying it converts a silent privacy/utility trade into an
 * explicit conflict when the two cannot both be satisfied.
 */
export function geoBucketFor(
  digipin: string,
  density: DensityPort,
  opts: { k?: number; minChars?: number } = {},
): string {
  if (!digipin) throw new DigipinMissing("digipin is required");
  const rung = rungMeetingFloor(
    DIGIPIN_LADDER,
    density.peoplePerKm2(digipin),
    opts.k ?? K_ANON_FLOOR,
    opts.minChars ?? 0,
  );
  if (digipin.length < rung.chars) {
    throw new DigipinMissing(`digipin must be at least ${rung.chars} characters at this density`);
  }
  return `IND-${digipin.slice(0, rung.chars).toUpperCase()}`;
}
