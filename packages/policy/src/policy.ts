/**
 * Signed, versioned, hot-reloadable disclosure policy.
 *
 * A small typed ruleset, signed by the operator's key the same way a
 * request envelope is (packages/registry/src/signing.ts), content-addressed
 * by its own hash, and swappable at runtime without a restart. What the
 * audit claim actually needs isn't the rule language — it's that every past
 * decision can point at the exact bytes of the policy that made it, which
 * the hash gives for free.
 *
 * [Gap fix — THREAT_MODEL.md §2 item 4] The old `defaultPolicyStore()` in
 * `services/platform` generated a fresh Ed25519 keypair inline, signed
 * `minTierToShip` with it, and discarded the private key — Platform could
 * "sign" its own policy changes with a key nobody else ever held. That
 * function is now `demoOnlyInsecurePolicyStore()`, moved here so its name
 * carries the warning wherever it's imported, gated behind the
 * `CFP_ALLOW_DEMO_POLICY=1` environment variable, and it prints a loud
 * runtime warning every time it's constructed. Any real deployment must
 * pass Platform an explicit, operator-signed `PolicyStore`.
 */
import { createPrivateKey, createPublicKey, sign as edSign, verify as edVerify } from "node:crypto";
import { digestOf } from "../../registry/src/signing.ts";
import { newKeyPair } from "../../registry/src/signing.ts";

export class PolicyInvalid extends Error {}
export class PolicyStale extends Error {}
export class DemoPolicyNotAllowed extends Error {}

/** Today's one live disclosure rule: the minimum proofing tier a grantee must have vouched before Platform.createGrant may mint a grant. */
export type DisclosurePolicy = {
  version: number; // monotonic — reload() refuses to go backwards
  minTierToRelease: 1 | 2 | 3;
};

export type SignedPolicy = {
  policy: DisclosurePolicy;
  /** sha256(canonical(policy)), base64 — rides along in the consent entry so a decision is replayable against the rules in force when it was made. */
  hash: string;
  signature: string; // base64 ed25519 over `hash`
  signerKeyId: string;
};

function priv(b64: string) {
  return createPrivateKey({ key: Buffer.from(b64, "base64"), type: "pkcs8", format: "der" });
}
function pub(b64: string) {
  return createPublicKey({ key: Buffer.from(b64, "base64"), type: "spki", format: "der" });
}

export function signPolicy(privateKeyB64: string, signerKeyId: string, policy: DisclosurePolicy): SignedPolicy {
  const hash = digestOf(policy);
  const signature = edSign(null, Buffer.from(hash), priv(privateKeyB64)).toString("base64");
  return { policy, hash, signature, signerKeyId };
}

export function verifyPolicy(publicKeyB64: string, signed: SignedPolicy): boolean {
  if (digestOf(signed.policy) !== signed.hash) return false;
  return edVerify(null, Buffer.from(signed.hash), pub(publicKeyB64), Buffer.from(signed.signature, "base64"));
}

/**
 * Holds exactly one active policy plus every policy that was ever active,
 * indexed by hash — so `byHash()` can answer "what did the rules say when
 * this specific decision was made", not just "what do they say now".
 */
export class PolicyStore {
  #publicKey: string;
  #active: SignedPolicy;
  #history = new Map<string, SignedPolicy>();

  constructor(publicKeyB64: string, initial: SignedPolicy) {
    this.#publicKey = publicKeyB64;
    this.#active = this.#accept(initial);
  }

  #accept(signed: SignedPolicy): SignedPolicy {
    if (!verifyPolicy(this.#publicKey, signed)) {
      throw new PolicyInvalid(`policy v${signed.policy.version} failed signature verification`);
    }
    Object.freeze(signed.policy);
    Object.freeze(signed);
    this.#history.set(signed.hash, signed);
    return signed;
  }

  /** Hot-reload: verified and versioned. Rejects anything that isn't strictly newer than what's active. */
  reload(next: SignedPolicy): void {
    if (next.policy.version <= this.#active.policy.version) {
      throw new PolicyStale(`policy v${next.policy.version} is not newer than active v${this.#active.policy.version}`);
    }
    this.#active = this.#accept(next);
  }

  active(): SignedPolicy {
    return this.#active;
  }

  /** Replay: what were the rules when a past decision recorded this hash? */
  byHash(hash: string): SignedPolicy | undefined {
    return this.#history.get(hash);
  }
}

/**
 * [Gap fix] The insecure, demo-only fallback the old `defaultPolicyStore()`
 * silently was. Loudly named, loudly gated: throws `DemoPolicyNotAllowed`
 * unless `process.env.CFP_ALLOW_DEMO_POLICY === "1"`, and prints a warning
 * to stderr every time it's actually constructed. A real Platform
 * construction must supply its own operator-signed `PolicyStore` instead —
 * see `web/` and `tools/demo/walkthrough.ts` for what that looks like.
 */
export function demoOnlyInsecurePolicyStore(): PolicyStore {
  if (process.env.CFP_ALLOW_DEMO_POLICY !== "1") {
    throw new DemoPolicyNotAllowed(
      "no PolicyStore supplied and CFP_ALLOW_DEMO_POLICY is not set — " +
        "a real deployment must pass an operator-signed PolicyStore explicitly",
    );
  }
  // eslint-disable-next-line no-console
  console.warn(
    "[cfp-demo] WARNING: using demoOnlyInsecurePolicyStore() — this policy is self-signed " +
      "by a throwaway key discarded immediately after signing. Never use this outside a demo.",
  );
  const { publicKey, privateKey } = newKeyPair();
  const initial = signPolicy(privateKey, "demo-only-insecure-signer", { version: 1, minTierToRelease: 2 });
  return new PolicyStore(publicKey, initial);
}
