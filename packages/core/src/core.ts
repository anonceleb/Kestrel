/**
 * Zone-agnostic domain core.
 *
 * HARD RULE: this file may not import from ../../adapters/** or from any
 * service. tools/privacy-lint enforces it in CI. When the core still builds
 * and tests green with every adapter deleted, the standards-agnostic claim
 * is true; when it doesn't, it isn't.
 *
 * The confidential attribute is `ConfidentialPayload` — a generic port
 * type; the address profile supplies its concrete shape. Routing is
 * `RoutingPort` — attribute-agnostic by construction.
 */
import { createHash, randomUUID } from "node:crypto";

/* ------------------------------------------------------------------ consent */

export type ConsentEntry = {
  seq: number;
  ref: string;
  /**
   * [Gap fix — closes web/candid-books.html gap 5, "Platform-side cross-merchant correlation"] A *pairwise* reference,
   * derived per-counterparty via packages/identity's derivePairwiseId, never
   * a stable root identity reference. A stable reference visible to Platform
   * across every consent entry regardless of which merchant it was granted
   * to would let Platform itself correlate a subject across counterparties
   * by comparing
   * `subject` values, exactly the correlation the pairwise-ID scheme exists
   * to prevent for merchants. Keying the ledger by the same per-counterparty
   * pairwise reference closes that hole for Platform's own view too: two
   * entries with different `grantedTo` never share a comparable `subject`
   * value for the same real-world subject.
   */
  subject: string;
  grantedTo: string; // counterparty id
  purpose: string;
  scope: string[];
  at: number;
  expiresAt: number;
  /** Hash of the disclosure policy in force when this grant was decided — see packages/policy/src/policy.ts. Not every append() is a disclosure decision, so this is optional. */
  policyHash?: string;
  prevHash: string;
  hash: string;
};

/**
 * Append-only, hash-chained consent ledger. Tamper-evidence without a
 * blockchain: rewriting any entry invalidates every hash after it.
 *
 * Consent is per-event and never standing — the record exists so that a
 * later decryption can be attributed to a purpose the subject actually
 * agreed to.
 */
export class ConsentLedger {
  #entries: ConsentEntry[] = [];
  #revoked = new Set<string>();

  append(e: Omit<ConsentEntry, "seq" | "ref" | "prevHash" | "hash">): ConsentEntry {
    const prevHash = this.#entries.at(-1)?.hash ?? "genesis";
    const seq = this.#entries.length;
    const ref = `cns_${randomUUID().replace(/-/g, "").slice(0, 20)}`;
    const body = { seq, ref, ...e, prevHash };
    const hash = createHash("sha256").update(JSON.stringify(body)).digest("hex");
    const entry: ConsentEntry = { ...body, hash };
    this.#entries.push(entry);
    return entry;
  }

  find(ref: string): ConsentEntry | undefined {
    return this.#entries.find((x) => x.ref === ref);
  }

  /** Consumer-initiated revocation, effective mid-flight — the consent-side twin of NonceLedger.revoke(). */
  revoke(ref: string): void {
    this.#revoked.add(ref);
  }

  isRevoked(ref: string): boolean {
    return this.#revoked.has(ref);
  }

  isValidFor(ref: string, purpose: string, participantId: string, now = Date.now()): boolean {
    const e = this.find(ref);
    return (
      !!e &&
      !this.#revoked.has(ref) &&
      e.purpose === purpose &&
      e.grantedTo === participantId &&
      now <= e.expiresAt
    );
  }

  /** Returns the index of the first broken link, or -1 when the chain is intact. */
  verifyChain(): number {
    let prevHash = "genesis";
    for (const e of this.#entries) {
      const { hash, ...body } = e;
      const expected = createHash("sha256")
        .update(JSON.stringify({ ...body, prevHash }))
        .digest("hex");
      if (expected !== hash || e.prevHash !== prevHash) return e.seq;
      prevHash = hash;
    }
    return -1;
  }

  /** Test-only seam so the Inspector can demonstrate the chain failing. */
  tamperForDemo(seq: number, mutate: (e: ConsentEntry) => void): void {
    const e = this.#entries[seq];
    if (e) mutate(e);
  }

  entries(): readonly ConsentEntry[] {
    return this.#entries;
  }
}

/* -------------------------------------------------------------------- audit */

export type AuditRecord = {
  id: string;
  actor: string;
  purpose: string;
  consentRef: string;
  recordId: string;
  at: number;
};

export class AuditLog {
  #records: AuditRecord[] = [];
  write(r: Omit<AuditRecord, "id" | "at">): AuditRecord {
    const rec: AuditRecord = { id: randomUUID(), at: Date.now(), ...r };
    this.#records.push(rec);
    return rec;
  }
  forRecord(recordId: string): AuditRecord[] {
    return this.#records.filter((r) => r.recordId === recordId);
  }
  all(): readonly AuditRecord[] {
    return this.#records;
  }
}

/* ------------------------------------------------------------------- ports */

/**
 * The generic confidential-payload port. This file has no opinion on what
 * the payload actually is; `profiles/address` and `profiles/contact` each supply their
 * own concrete shape (an address record; `{ e164 }`). Left as `unknown` in
 * the core so no attribute-shaped field can leak in here — the whole point
 * of splitting core from profile.
 */
export type ConfidentialPayload = unknown;

export type GeoBucket = string;

export type IdentityProofingPort = {
  /**
   * Returns an opaque assurance label, never the underlying credential.
   * Deliberately `string`, not a numeric ordinal: what a label means, and
   * whether labels are even ordered, is for the signed disclosure policy to
   * interpret — the port and the protocol above it must not.
   */
  proof(subjectRef: string, evidence: unknown): Promise<string>;
};

/**
 * Generalized from `SortationPort`: consumes the confidential payload
 * transiently, emits a routing code. Never returns the payload. "Route" is
 * deliberately generic — a postal sortation code in the address profile, a
 * call-connect token in the contact profile.
 */
export type RoutingPort = {
  route(payload: ConfidentialPayload, service: string): Promise<{ routingCode: string }>;
};

/**
 * Failed-fulfilment notification. Addressed by subjectRef — a root-identity
 * reference — so nothing that reaches this port could be repurposed to
 * notify a counterparty participant id by mistake.
 */
export type NotificationPort = {
  notify(subjectRef: string, event: string): void;
};

/* -------------------------------------------------------------- projections */

/**
 * Everything a counterparty is ever allowed to hold. There is deliberately
 * no attribute-shaped field and no way to add one: Zone 3 storage is shaped
 * by this type.
 */
export type MerchantView = {
  pairwiseId: string;
  geoBucket: GeoBucket;
  /** Opaque, policy-interpreted proofing-assurance label — not a protocol-compared ordinal. */
  verifiedAssurance: string;
  serviceLevel: string;
  estimatedDelivery: string;
};

/**
 * Household / co-residency barrier, after Posten Norge's address register:
 * several subjects share a confidential-payload record, and by default they
 * must not be able to enumerate each other through it.
 */
export type Residency = {
  cohortRecordId: string;
  subjectRef: string;
  barrier: boolean;
};

export function visibleCoResidents(all: Residency[], viewer: string, cohortRecordId: string) {
  const viewerRow = all.find(
    (r) => r.subjectRef === viewer && r.cohortRecordId === cohortRecordId,
  );
  if (!viewerRow) return [];
  return all
    .filter((r) => r.cohortRecordId === cohortRecordId && r.subjectRef !== viewer)
    .filter((r) => !r.barrier && !viewerRow.barrier)
    .map((r) => r.subjectRef);
}

/* --------------------------------------------------------------- cohorts */

export const K_ANON_FLOOR = 25;

/** No cohort below k is ever exposed to a brand. Returns 0 or a size >= k. */
export function cohortSize(matching: number): number {
  return matching >= K_ANON_FLOOR ? matching : 0;
}

/* ------------------------------------------------------ precision ladder */

/**
 * Geographic precision as a monotone ordered dimension.
 *
 * Before this existed, the address profile truncated its grid code to a
 * hard-coded constant and a docstring asserted the result was "coarse
 * enough to guarantee k-anonymity." Nothing computed that, and nothing
 * connected it to `K_ANON_FLOOR` above — the floor was real but wired only
 * to brand-cohort visibility, never to geography. This section is the
 * missing connection, and `K_ANON_FLOOR` is now the single source for both.
 *
 * Deliberately free of any grid vocabulary: a rung is a character count and
 * a ground area. Which grid, and what a cell measures, belongs to the
 * attribute profile (see `profiles/address/src/precision.ts` for the
 * DIGIPIN ladder). The core knows only that precision is ordered.
 */

/** One rung: how many characters of a code are disclosed, and the ground area one cell covers. */
export type PrecisionRung = { chars: number; cellKm2: number };

/**
 * Ordered coarsest-first. The ordering is the point: `chars` strictly
 * increases and `cellKm2` strictly decreases, so cohort size is monotone
 * non-increasing along the ladder. That monotonicity is what lets
 * `rungMeetingFloor` stop at the first failure instead of scanning on.
 */
export type PrecisionLadder = readonly PrecisionRung[];

/**
 * Where cohort estimates come from. Pluggable on purpose: a real deployment
 * supplies census or operator data; the demo supplies a flat value. The core
 * has no opinion, which is what keeps this honest — the k-floor is enforced
 * against whatever number the deployment can actually defend.
 */
export type DensityPort = { peoplePerKm2(code: string): number };

/** Thrown when even the coarsest rung on the ladder cannot reach the k-floor. */
export class PrecisionFloorUnsatisfiable extends Error {}
/** Thrown when a ladder is not strictly ordered — a programming error, caught at the boundary. */
export class PrecisionLadderNotMonotone extends Error {}

/** Expected number of people sharing one cell at this rung. */
export function cohortAtRung(rung: PrecisionRung, peoplePerKm2: number): number {
  return rung.cellKm2 * peoplePerKm2;
}

/** Fails loudly if a ladder is not coarsest-first and strictly ordered on both axes. */
export function assertMonotoneLadder(ladder: PrecisionLadder): void {
  for (let i = 1; i < ladder.length; i++) {
    const prev = ladder[i - 1]!;
    const cur = ladder[i]!;
    if (cur.chars <= prev.chars || cur.cellKm2 >= prev.cellKm2) {
      throw new PrecisionLadderNotMonotone(
        `rung ${i} (${cur.chars} chars, ${cur.cellKm2} km2) does not strictly refine rung ${i - 1}`,
      );
    }
  }
}

/**
 * The most precision the k-floor permits — the finest rung whose cell still
 * holds at least `k` people.
 *
 * A note on direction, because the obvious reading is backwards. A *shorter*
 * prefix means a *larger* cell and therefore *more* people, so short
 * prefixes satisfy a k-floor trivially; the one-character prefix always
 * passes and is useless for routing. The k-floor is therefore an **upper
 * bound on precision**, not a lower one, and the useful answer is the
 * longest prefix still under that bound.
 *
 * The lower bound is operational — a carrier needs some minimum precision to
 * choose a sorting bin — and it belongs to the operator, not here. When a
 * deployment supplies one, the two bounds define a window, and a window that
 * closes (routing needs more precision than the floor permits) is a real
 * conflict that must surface rather than resolve silently in either
 * direction. `minChars` is how a caller declares that lower bound.
 */
export function rungMeetingFloor(
  ladder: PrecisionLadder,
  peoplePerKm2: number,
  k: number = K_ANON_FLOOR,
  minChars = 0,
): PrecisionRung {
  assertMonotoneLadder(ladder);
  let best: PrecisionRung | undefined;
  for (const rung of ladder) {
    if (cohortAtRung(rung, peoplePerKm2) < k) break; // monotone: no finer rung can pass either
    best = rung;
  }
  if (!best) {
    throw new PrecisionFloorUnsatisfiable(
      `no rung reaches k=${k} at ${peoplePerKm2} people/km2; the coarsest cell is too sparse`,
    );
  }
  if (best.chars < minChars) {
    throw new PrecisionFloorUnsatisfiable(
      `routing needs ${minChars} characters but k=${k} at ${peoplePerKm2} people/km2 permits only ${best.chars}`,
    );
  }
  return best;
}
