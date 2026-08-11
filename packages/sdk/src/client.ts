/**
 * The integrator-facing SDK.
 *
 * "Done when a third party integrates from the published SDK without
 * talking to us." This file is the one thing an integration is meant to
 * import. Registry, Platform, the capability and policy primitives
 * underneath it are implementation detail. What matters: no attribute-shaped
 * field, no name, no phone, ever crosses this surface.
 *
 * Renamed from the prior implementation's MerchantClient/CheckoutResult to
 * keep the naming generic: FulfilmentClient/GrantResult.
 */
import { signRequest } from "../../registry/src/signing.ts";
import {
  Platform,
  TierTooLow,
  type FulfilmentRequest,
  type CapabilityStatus,
} from "../../../services/platform/src/platform.ts";
import { QuotaExceeded } from "../../metering/src/meter.ts";
import type { WebhookConfig } from "../../webhooks/src/webhook.ts";

export { TierTooLow, QuotaExceeded };
export type { FulfilmentRequest, CapabilityStatus, WebhookConfig };

/**
 * What an integration actually receives — deliberately not the internal
 * `MerchantView`. `verifiedHuman` is the "worth more than attribute data"
 * signal: a counterparty that only wants to know "is this a real, distinct,
 * tier-checked subject" never needs to think about tier numbers at all.
 */
export type GrantResult = {
  pairwiseId: string;
  capabilityId: string;
  geoBucket: string;
  serviceLevel: string;
  estimatedDelivery: string;
  verifiedHuman: boolean;
};

export function isVerifiedHuman(tier: 1 | 2 | 3): boolean {
  return tier >= 1;
}

/**
 * A counterparty's one credential-bearing handle onto the network.
 * Constructed once per integration with the participant's own signing key —
 * every subsequent call signs its own request.
 */
export class FulfilmentClient {
  #platform: Platform;
  #participantId: string;
  #keyId: string;
  #privateKey: string;

  constructor(opts: { platform: Platform; participantId: string; keyId: string; privateKey: string }) {
    this.#platform = opts.platform;
    this.#participantId = opts.participantId;
    this.#keyId = opts.keyId;
    this.#privateKey = opts.privateKey;
  }

  /** Drop-in replacement for a plaintext-attribute form: sign, submit, get back a routable, attribute-free result. */
  requestGrantSync(req: FulfilmentRequest, subjectRef: string): GrantResult {
    const env = signRequest(this.#participantId, this.#keyId, this.#privateKey, req);
    const { capability, merchantView } = this.#platform.createGrant(env, req, subjectRef);
    return {
      pairwiseId: merchantView.pairwiseId,
      capabilityId: capability.id,
      geoBucket: merchantView.geoBucket,
      serviceLevel: merchantView.serviceLevel,
      estimatedDelivery: merchantView.estimatedDelivery,
      verifiedHuman: isVerifiedHuman(merchantView.verifiedTier),
    };
  }

  /** The same grant, as the request half of the action/on_action pair — for integrations that can't block on a synchronous mint. */
  requestGrant(req: FulfilmentRequest, subjectRef: string): { transactionId: string } {
    const env = signRequest(this.#participantId, this.#keyId, this.#privateKey, req);
    return this.#platform.requestGrant(env, req, subjectRef);
  }

  /** Subscribes to the on_action callback for a transaction requestGrant() began, curated to the same GrantResult shape as requestGrantSync(). */
  onGrantReady(transactionId: string, handler: (result: GrantResult) => void): void {
    this.#platform.onGrantReady(transactionId, (r) => {
      handler({
        pairwiseId: r.merchantView.pairwiseId,
        capabilityId: r.capability.id,
        geoBucket: r.merchantView.geoBucket,
        serviceLevel: r.merchantView.serviceLevel,
        estimatedDelivery: r.merchantView.estimatedDelivery,
        verifiedHuman: isVerifiedHuman(r.merchantView.verifiedTier),
      });
    });
  }

  /** Subscribes to the on_action nack — fires if settlement rejects the request. */
  onGrantError(transactionId: string, handler: (error: unknown) => void): void {
    this.#platform.onGrantError(transactionId, handler);
  }

  /** A pull, not a push: this integration asking about a grant it already holds. */
  getStatus(capabilityId: string): { status: CapabilityStatus } {
    return { status: this.#platform.getCapabilityStatus(capabilityId, this.#participantId) };
  }

  /** Registers this integration's webhook endpoint. */
  registerWebhook(config: WebhookConfig): void {
    this.#platform.registerWebhook(this.#participantId, config);
  }
}
