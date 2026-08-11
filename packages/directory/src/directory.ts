/**
 * DeDi-shaped directory port.
 *
 * DeDi (dedi.global, an LF Decentralized Trust project) is a decentralized
 * public-registry protocol for publishing and looking up keys, membership,
 * and revocation lists — a directory layer, not an encryption layer. A
 * third party (an auditor, a counterparty, a new operator) is meant to be
 * able to independently verify "is this key/policy/revocation real and
 * current" by querying the directory, without trusting whoever originally
 * published it.
 *
 * `DeDiDirectoryPort` is the interface that boundary would sit behind in
 * this codebase. `InProcessDirectory` below is the only implementation —
 * and it is **not dedi.global**. It is an in-memory demo backend: a plain
 * Map, in the same process, with no network call, no chain, no
 * cross-organization trust. It exists so the rest of the codebase (label
 * key rotation, registry revocations, policy reloads) can be honestly wired
 * against the *shape* of a directory publish/lookup call, without this demo
 * taking a hard dependency on a live network service — this repo's
 * acceptance criteria explicitly call for "runs entirely offline", which a
 * real dedi.global integration (HTTP calls to a public/consortium chain)
 * cannot satisfy.
 *
 * What swapping in the real thing would require: an implementation of this
 * same `DeDiDirectoryPort` interface that makes HTTP calls to dedi.global's
 * REST API (create/read a namespace, DID-style entry, and revocation list
 * per LF Decentralized Trust's DeDi protocol) instead of writing to
 * `#entries`. Every call site below (`OperatorKeyring.rotate()`,
 * `Registry.suspend()`, `NonceLedger.revoke()`, `PolicyStore.reload()`)
 * would need zero changes — they only depend on this interface, never on
 * `InProcessDirectory`'s internals.
 */

export type DirectoryKeyEntry = {
  ownerId: string; // operator or label-signing key's subscriberId/kid
  kid: string;
  publicKey: string; // base64 raw SPKI
  notBefore: number;
  notAfter: number;
  publishedAt: number;
};

export type DirectoryRevocationEntry = {
  subject: string; // capabilityId, subscriberId, or nonce id being revoked
  kind: "capability" | "subscriber" | "nonce";
  reason?: string;
  publishedAt: number;
};

export type DirectoryPolicyEntry = {
  policyHash: string; // digestOf(policy) — same hash carried on consent entries
  version: number;
  signerKeyId: string;
  publishedAt: number;
};

/**
 * Publish/lookup surface for keys, revocations, and disclosure policy — the
 * three directory-shaped facts this codebase needs a third party to be able
 * to verify independently. Modeled on DeDi's three DeDi-protocol concerns
 * (key/membership registry, revocation lists, and signed policy/schema
 * publication), not on any one HTTP API — see the module docstring above
 * for what a real dedi.global-backed implementation would need to add.
 */
export interface DeDiDirectoryPort {
  publishKey(entry: DirectoryKeyEntry): void;
  lookupKey(ownerId: string, kid: string): DirectoryKeyEntry | undefined;

  publishRevocation(entry: DirectoryRevocationEntry): void;
  lookupRevocations(kind?: DirectoryRevocationEntry["kind"]): DirectoryRevocationEntry[];

  publishPolicy(entry: DirectoryPolicyEntry): void;
  lookupPolicy(policyHash: string): DirectoryPolicyEntry | undefined;
}

/**
 * In-memory demo backend for `DeDiDirectoryPort`. NOT dedi.global — see the
 * module docstring. Every entry lives in a plain Map for the lifetime of
 * this process; nothing here is durable, distributed, or independently
 * operated the way a real DeDi deployment would be.
 */
export class InProcessDirectory implements DeDiDirectoryPort {
  #keys = new Map<string, DirectoryKeyEntry>();
  #revocations: DirectoryRevocationEntry[] = [];
  #policies = new Map<string, DirectoryPolicyEntry>();

  publishKey(entry: DirectoryKeyEntry): void {
    this.#keys.set(`${entry.ownerId}|${entry.kid}`, entry);
  }

  lookupKey(ownerId: string, kid: string): DirectoryKeyEntry | undefined {
    return this.#keys.get(`${ownerId}|${kid}`);
  }

  publishRevocation(entry: DirectoryRevocationEntry): void {
    this.#revocations.push(entry);
  }

  lookupRevocations(kind?: DirectoryRevocationEntry["kind"]): DirectoryRevocationEntry[] {
    return kind ? this.#revocations.filter((r) => r.kind === kind) : [...this.#revocations];
  }

  publishPolicy(entry: DirectoryPolicyEntry): void {
    this.#policies.set(entry.policyHash, entry);
  }

  lookupPolicy(policyHash: string): DirectoryPolicyEntry | undefined {
    return this.#policies.get(policyHash);
  }
}
