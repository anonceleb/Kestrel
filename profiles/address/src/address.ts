/**
 * profiles/address — the address attribute profile.
 *
 * The concrete `ConfidentialPayload` shape for postal fulfilment: this is
 * where `tools/privacy-lint`'s address-shaped-identifier check is
 * deliberately allowed to live, because this file's entire job is to be
 * address-shaped. `packages/core` never imports this — profiles sit above
 * the generic core, wrapping its ports for one concrete use case.
 */
import type { ConfidentialPayload, RoutingPort } from "../../../packages/core/src/core.ts";

export type AddressPayload = {
  line1: string;
  line2?: string;
  locality: string;
  postcode: string;
  /** Nordic-style place-name addressing: no street, and that must not be an error. */
  placeName?: string;
  /** India Post DIGIPIN grid code (10-char alphanumeric), where the operator supports it. */
  digipin?: string;
};

/** Narrows the generic port's `unknown` payload to this profile's concrete shape. */
export function asAddressPayload(payload: ConfidentialPayload): AddressPayload {
  return payload as AddressPayload;
}

export type AddressRoutingPort = RoutingPort;
