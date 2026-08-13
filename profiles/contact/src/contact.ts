/**
 * profiles/contact — the contact/phone attribute profile.
 *
 * Proves purpose-genericity: this profile reuses `packages/capability`'s
 * mint/attenuate/verify unmodified — the same `FulfilmentGrant` type, the
 * same MAC — to grant "connect this call" instead of "route this parcel".
 * `ConfidentialPayload` here is `{ e164 }`: a phone number, never returned
 * to either party. `RoutingPort` becomes a call-relay: a driver "calls" a
 * rider through a grant, and both numbers stay vault-side.
 */
import type { ConfidentialPayload, RoutingPort } from "../../../packages/core/src/core.ts";

export type ContactPayload = {
  e164: string;
};

export function asContactPayload(payload: ConfidentialPayload): ContactPayload {
  return payload as ContactPayload;
}

export type ContactRoutingPort = RoutingPort;

/**
 * A call-relay routing port: "routes" a masked-number connection instead of
 * a parcel. Emits a connection code (never the phone number) the same way
 * a postal RoutingPort emits a sortation code.
 */
export class CallRelay implements RoutingPort {
  async route(payload: ConfidentialPayload, service: string): Promise<{ routingCode: string }> {
    const contact = asContactPayload(payload);
    const { createHash } = await import("node:crypto");
    const code = createHash("sha256")
      .update(`${contact.e164}|${service}`)
      .digest("hex")
      .slice(0, 10)
      .toUpperCase();
    return { routingCode: `CALL-${code}` };
  }
}
