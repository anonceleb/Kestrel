/**
 * The operator's rotating label-signing keys.
 *
 * [A4] "The COSE-signed label must verify against a rotating operator key
 * with no network call." — PRIOR_ART_REVIEW.md, after Aadhaar's Secure QR.
 *
 * Private key material never leaves this class; `publicMaterial()` is the
 * only thing that should ever reach a handheld scanner, distributed ahead of
 * time so the scanner can verify offline. Old keys stay resolvable for their
 * validity window so labels already printed keep verifying after a rotation.
 *
 * When constructed with a `directory` (a `DeDiDirectoryPort` — see
 * packages/directory/src/directory.ts), every rotation also publishes the
 * new key's *public* material through `publishKey()`, so a third party can
 * independently verify "is this the operator's current label-signing key"
 * by querying the directory rather than trusting whatever key a printed
 * label happens to claim.
 */
import { randomUUID } from "node:crypto";
import { newKeyPair } from "../../registry/src/signing.ts";
import type { DeDiDirectoryPort } from "../../directory/src/directory.ts";

export type OperatorKey = {
  kid: string;
  publicKey: string; // base64 raw SPKI
  privateKey: string; // base64 pkcs8 — Zone 1 only, never exported
  notBefore: number;
  notAfter: number;
};

export type OperatorPublicKey = Omit<OperatorKey, "privateKey">;

export class OperatorKeyring {
  #keys = new Map<string, OperatorKey>();
  #currentKid: string | undefined;
  #directory: DeDiDirectoryPort | undefined;
  #ownerId: string;

  constructor(opts: { directory?: DeDiDirectoryPort; ownerId?: string } = {}) {
    this.#directory = opts.directory;
    this.#ownerId = opts.ownerId ?? "operator";
  }

  /** Mints a fresh Ed25519 key and makes it the one new labels sign with. */
  rotate(validForMs = 90 * 24 * 3600 * 1000): OperatorKey {
    const { publicKey, privateKey } = newKeyPair();
    const now = Date.now();
    const key: OperatorKey = {
      kid: `op-${randomUUID().slice(0, 8)}`,
      publicKey,
      privateKey,
      notBefore: now,
      notAfter: now + validForMs,
    };
    this.#keys.set(key.kid, key);
    this.#currentKid = key.kid;
    this.#directory?.publishKey({
      ownerId: this.#ownerId,
      kid: key.kid,
      publicKey: key.publicKey,
      notBefore: key.notBefore,
      notAfter: key.notAfter,
      publishedAt: now,
    });
    return key;
  }

  current(): OperatorKey {
    if (!this.#currentKid) this.rotate();
    return this.#keys.get(this.#currentKid!)!;
  }

  /** What ships to a handheld scanner: public material only, no private keys. */
  publicMaterial(): OperatorPublicKey[] {
    return [...this.#keys.values()].map(({ privateKey: _privateKey, ...pub }) => pub);
  }
}
