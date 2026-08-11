/**
 * [Phase 3] Metered API — "metered API" is one of the four things that make
 * the platform tier a commerce feature, not just a privacy feature. A
 * merchant integration that can call createGrant an unbounded number of
 * times is a cost and abuse surface, not a product.
 *
 * Fixed-window quota per participant. A real deployment backs this with
 * Redis (the same parity note NonceLedger's docstring makes elsewhere) —
 * this is the in-process shape that call site must satisfy.
 */
export class QuotaExceeded extends Error {}

export class UsageMeter {
  #limit: number;
  #windowMs: number;
  #windows = new Map<string, { windowStart: number; count: number }>();

  constructor(opts: { limit: number; windowMs: number }) {
    this.#limit = opts.limit;
    this.#windowMs = opts.windowMs;
  }

  /**
   * Records one call against `subscriberId`'s current window, starting a
   * fresh window if the previous one has elapsed. Throws QuotaExceeded
   * rather than silently letting the call through once the limit is hit.
   */
  consume(subscriberId: string, now = Date.now()): void {
    const w = this.#windows.get(subscriberId);
    if (!w || now - w.windowStart >= this.#windowMs) {
      this.#windows.set(subscriberId, { windowStart: now, count: 1 });
      return;
    }
    if (w.count >= this.#limit) {
      throw new QuotaExceeded(`participant ${subscriberId} exceeded ${this.#limit} calls per ${this.#windowMs}ms window`);
    }
    w.count += 1;
  }

  /** Calls left in the participant's current window — 0 means the next consume() throws. */
  remaining(subscriberId: string, now = Date.now()): number {
    const w = this.#windows.get(subscriberId);
    if (!w || now - w.windowStart >= this.#windowMs) return this.#limit;
    return Math.max(0, this.#limit - w.count);
  }
}
