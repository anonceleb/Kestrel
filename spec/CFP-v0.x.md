# CFP v0.x — Confidential Fulfilment Profile

**Status: pilot-scoped interface note. Submitted nowhere.** This is not a
governance artifact — no working group has been asked to adopt it, no
standards body has received it, and it is not versioned 1.0 or "v0.9"
because neither claim would be true. It is extracted-from-pilot discipline:
a written interface contract (token format, redemption semantics, error
behavior) so a pilot has something concrete to run against before the first
real transaction, not after. The number in the filename moves as the pilot
teaches this document things it doesn't know yet.

## 1. What this is

A capability-grant primitive for causing an action against a sensitive
attribute without that attribute ever crossing the network. The primitive
is generic; address (postal fulfilment) is its first attribute profile,
contact/phone (mobility number-masking) is its second. Nothing in this
document is address-specific except where explicitly marked "address
profile only."

## 2. Token format

A `FulfilmentGrant` (`packages/capability/src/capability.ts`):

```
FulfilmentGrant = {
  id: string,            // UUID, part of the signed material
  caveats: {
    pairwiseId: string,    // subject-side pairwise reference, never a stable id
    purpose: "delivery" | "return" | "redirect",
    maxUnits: number,      // generic magnitude cap — kg for a parcel, minutes for a call
    fulfiller: string,     // the executing operator/channel
    channelKind: "door" | "access-point" | "locker",
    expiresAt: number,     // epoch ms
    singleUse: boolean,
    consentRef: string,    // points at the ConsentEntry this grant was minted against
  },
  chain: string[],        // attenuation lineage
  mac: string,            // HMAC-SHA256 over { id, caveats, chain }
}
```

`id` is signed material — the MAC covers it, not just `caveats`/`chain` —
because single-use enforcement is keyed on `id` alone; an unsigned `id`
would let any holder mint an unlimited supply of "single-use" tokens by
swapping in a fresh one.

## 3. Redemption semantics

Redemption (`Vault.resolve(grant, actor)`) is the single audited exit from
Zone 1:

1. Verify the grant's MAC and expiry.
2. Verify `actor` is a known, active registry participant.
3. Burn the grant's nonce (single-use enforcement) — a second `resolve()`
   call with the same grant throws `CapabilityBurned`.
4. Check the referenced consent entry is valid for this purpose and this
   actor, and not revoked.
5. **Write the audit record — actor, purpose, consent reference, record id —
   before decrypting anything.** A decryption that cannot be attributed to
   these three things is not a policy violation; it is unreachable code.
6. Decrypt, route through the profile's `RoutingPort`, and return only the
   routing code. The confidential payload never leaves this call frame.

## 4. Error behavior

A replayed grant and a revoked grant fail identically — both throw
`CapabilityBurned` from the same code path in `Vault.resolve()`. This is
deliberate: a counterparty catching by error type must not be able to
distinguish "already used" from "the subject pulled it mid-flight," because
that distinction would leak information the revocation design exists to
hide. `getCapabilityStatus()` is the only place the two are told apart, and
only to the grant's own counterparty, as exactly three states — `issued`,
`revoked`, `expired` — never a delivery-progress feed.

## 5. Attenuation rules

`attenuate()` produces a strictly narrower grant: `maxUnits` may only
decrease, `expiresAt` may only decrease, `pairwiseId` may never change,
`singleUse` may only tighten (`false → true`, never the reverse), and
`purpose` may never change through this function. The one sanctioned
purpose transition — `delivery → return` — has its own function,
`attenuateToReturn()`, which still runs the identical narrowing check;
`attenuate()` itself keeps rejecting that same transition, so the sanctioned
path is the only reachable one.

## 6. Pairwise reference derivation

```
PairwiseId = base32(HMAC-SHA256(root_secret, "cfp/pairwise/" + counterpartyId))
```

Deterministic (no storage required to recognize a returning subject),
one-way (possession of a `PairwiseId` reveals nothing about the root
secret), and derived per-counterparty (two counterparties' identifiers for
the same subject share no exploitable structure — enforced in CI by a
crude linkability oracle that fails loudly on any shared-prefix
"optimization").

**Root-secret placement.** `derivePairwiseId` is callable from exactly one
place in this codebase: `Vault.issuePairwiseId`, in Zone 1. `Platform` — the
class most likely to be reachable from a network-facing endpoint in a real
deployment — has no method anywhere on its surface that accepts a
`RootSecret`. This is a structural claim, checked by
`tests/grant-core/gap-fixes.test.ts` (INV-32), not a deployment-discipline
claim: the type does not appear on Platform's public API at all.

**Consent-ledger correlation.** `ConsentEntry.subject` is a pairwise
reference, derived per-counterparty, never the stable root-identity
reference the pre-fix design stored there. Platform's own ledger — the one
actor besides Vault that sees every consent entry — cannot correlate a
subject across counterparties by comparing `subject` values, because there
is nothing shared to compare (INV-33).

## 7. Federation & vault-discovery interface

A network with one vault operator has a kill switch and a honeypot,
whatever the cryptography says. This is a real gap in the current
implementation, named here rather than smoothed over: `Vault` in this repo
is a single class, single-tenant per process. The interface a federated
deployment needs, not yet built:

- **Vault discovery.** A grant's `fulfiller` field already names the
  executing operator; a federated deployment resolves that name against a
  registry-published vault endpoint the same way `packages/registry`
  already resolves a participant's public key — no new trust primitive, an
  extension of the one that exists.
- **Cross-vault grant portability.** A grant minted against one vault must
  be redeemable, or explicitly re-issuable, against another when a subject
  migrates operators — the number-portability analogue. Not implemented;
  the caveat shape (`pairwiseId`, `consentRef`) is deliberately
  vault-agnostic so this is additive, not a redesign.
- **ASP-to-ASP portability.** A subject's ability to move between
  accredited service providers without re-proving identity from zero, the
  same portability commitment payment tokenization made structural.
  Committed here as a v0.1 design constraint; not yet implemented.

## 7a. Registry & directory — subscriber identity and the DeDi-shaped interface

`packages/registry` (`Registry`, `signRequest`, `SignedEnvelope`) is a
**Beckn network-registry client**, not a self-minted identity scheme.
Participants are identified by `subscriberId` (FQDN-shaped, per Beckn's
subscriber_id convention — e.g. `merchant.example.org`), and every signed
envelope follows Beckn's actual wire format:

- `keyId="{subscriberId}|{uniqueKeyId}|ed25519"`
- digest: BLAKE2b-512 hash of the canonical request body, base64-encoded
  (Beckn's "BLAKE-512")
- signing string, exactly: `(created): {v}\n(expires): {v}\ndigest: BLAKE-512={digest}`

`Registry` in this repo **simulates that wire protocol in-process** — an
in-memory map standing in for the registry's subscribe/lookup HTTP surface.
A real deployment swaps the map for network calls to the network's actual
registry; envelope generation and verification do not change at all when
that swap happens. The scheme name Beckn uses is "XEd25519," but for a key
pair generated directly as Ed25519 (never derived from an X25519 key —
the case this demo and most real Beckn/ONDC deployments use), XEdDSA and
plain EdDSA produce identical signatures, so Node's native Ed25519
sign/verify is a faithful implementation of that genesis-key case. See
`packages/registry/src/signing.ts`'s module docstring for the full
reasoning and its explicit boundary (it does not claim to implement the
general X25519-key-conversion case).

Alongside the registry, `packages/directory` defines `DeDiDirectoryPort` —
an interface for publishing and looking up operator/label signing keys,
capability and subscriber revocations, and signed disclosure-policy
entries, modeled on DeDi (dedi.global, an LF Decentralized Trust project)'s
three directory-protocol concerns. **The only implementation shipped here,
`InProcessDirectory`, is an in-memory demo backend — explicitly not a live
dedi.global integration.** DeDi is a network/chain-backed directory
protocol; calling it live would break this repo's "runs entirely offline"
property, so the interface is wired in (`OperatorKeyring.rotate()`,
`Registry.suspend()`, `NonceLedger.revoke()`, and `PolicyStore.reload()`
all publish through it, independently verifiable by reading the same
interface back) without a network dependency. A real deployment implements
`DeDiDirectoryPort` against dedi.global's REST API instead; every call site
above depends only on the interface, not on `InProcessDirectory`.

## 8. Stewardship — the date-certain transfer clause

The grant-core invariant suite (`tests/grant-core/`) is donated under open
license (Apache-2.0, this repository), forkable, evolution governed by a
working group its author participates in but does not control.

> **A time-box whose clock the steward controls is not a time-box.**
> Transfer to a named neutral home — FIDE/NFH or ONDC's extension
> governance — no later than **twelve (12) months after CFP v0.1
> publication**, whether or not a working group has formed by then. This
> clause is operative regardless of working-group status; "no group has
> formed yet" is not a condition that extends the twelve months.

This is the D-1 clause from the convergence memo between this project and
FIDE (see the lineage repository's `docs/Convergence_Memo_FIDE.md`,
Pushback 3 and Part II §2, D-1), reproduced here verbatim in intent because
a spec-text commitment is the only version of this promise that survives a
change of author. It is restated on `web/candid-books.html` for the same
reason.

## 9. What remains open

Stated with the same prominence as what's closed, because a short honest
list is worth more than a long defensive one:

- **Offline double-redemption.** `verifyLabelOffline()` checks signature,
  expiry, and key validity window only — it has no way to know whether the
  underlying grant was already burned online. Two couriers scanning the
  same still-valid artifact before either syncs to the vault would both see
  a valid artifact; only the first to actually call `Vault.resolve()`
  succeeds, but nothing about the artifact itself reveals this offline.
- **Carrier-identity binding.** No binding exists between a `FulfilmentGrant`
  and the specific carrier/relay identity redeeming it (an mTLS-bound
  identity would close the gap above). Not attempted here.
- **Depot-time resolution as a synchronous dependency.** Resolution is a
  once-per-parcel online event on operator infrastructure. In a deep-rural
  network the "depot" can be a low-connectivity branch office, not an urban
  sortation hub — a genuine, unresolved empirical question (see the
  lineage repo's convergence memo, D-2), not a solved one.
- **Threshold-split vault keys.** Single-custodian `Kms`, no m-of-n split.
  Named as an open question, not attempted.

## 10. Two closed gaps' worth of detail (for the remaining three, see §6 above)

- **Registry write authorization** (`packages/registry`). `register()`/
  `suspend()` require a `WriteAuth` — a signed envelope from an
  already-registered, active `role: "facilitator"` participant — verified
  the same way every inter-participant request is. `Vault.erase()` requires
  the identical credential shape. INV-29/29b.
- **No self-signed default policy.** A `Platform` constructed without an
  explicit `PolicyStore` gets `demoOnlyInsecurePolicyStore()`
  (`packages/policy`), which throws `DemoPolicyNotAllowed` unless
  `CFP_ALLOW_DEMO_POLICY=1` is set, and prints a warning to stderr even
  then. Every real deployment path must supply an operator-signed
  `PolicyStore`. INV-30/30b.

See `web/candid-books.html` for the same five gaps with links to their
tests, and `THREAT_MODEL.md` in the lineage repository for the original
admission.
