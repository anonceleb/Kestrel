/**
 * ADAPTER — Republic of Meridia postal operator (fictional).
 *
 * Deliberately fictional so the seams where a real operator plugs in are
 * visible rather than assumed. Deleting this directory must leave
 * packages/core building and green (INV-8).
 */
import type { RoutingPort, IdentityProofingPort, ConfidentialPayload } from "../../../packages/core/src/core.ts";
import { asAddressPayload } from "../../../profiles/address/src/address.ts";
import { createHash } from "node:crypto";

export class MeridiaSortation implements RoutingPort {
  async route(payload: ConfidentialPayload, service: string) {
    const address = asAddressPayload(payload);
    // Consumes plaintext transiently; emits a routing code, never the address.
    const key = `${address.postcode}|${address.locality}|${service}`;
    const code = createHash("sha256").update(key).digest("hex").slice(0, 10).toUpperCase();
    return { routingCode: `MRD-${code}` };
  }
}

export class MeridiaIdentity implements IdentityProofingPort {
  async proof(_subjectRef: string, evidence: unknown): Promise<string> {
    const e = evidence as { nationalId?: string; vouched?: boolean; delivered?: boolean };
    if (e?.delivered) return "tier-3";
    if (e?.vouched) return "tier-2";
    if (e?.nationalId?.startsWith("MRD-")) return "tier-1";
    throw new Error("insufficient evidence");
  }
}

/** Coarse geography: guaranteed k>=50 residents per bucket. */
export function geoBucketFor(postcode: string): string {
  return `MRD-${postcode.slice(0, 2)}`;
}
