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
    purpose: "delivery" | "return",
    maxUnits: number,      // generic magnitude cap — kg for a parcel, minutes for a call
    fulfiller: string,     // the executing operator/channel
    channelKind: "direct" | "access-point" | "locker",
    expiresAt: number,     // epoch ms
    singleUse: boolean,    // governs the TOKEN
    maxAttempts: number,   // governs the FULFILMENT — the NDR budget, monotone
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
3. Check the referenced consent entry is valid for this purpose and this
   actor, and not revoked. **This precedes the burn deliberately**: an
   earlier revision burned first, which let any registered participant
   holding a valid grant destroy it by attempting redemption, denying the
   consented counterparty (see §9, INV-37).
4. Burn the grant's nonce (single-use enforcement) — a second `resolve()`
   call with the same grant throws `CapabilityBurned`. The burn is the
   linearization point immediately before decryption, so a real deployment
   makes it an atomic compare-and-set and proceeds only if it wins.
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
hide. This property is normative for **every** counterparty-facing surface,
not just `Vault.resolve()`, so it holds as a meta-invariant rather than a
per-endpoint one.

Consequently `Platform.getCapabilityStatus()`, the poll a counterparty uses
on a grant it already holds, returns exactly two states — `issued` |
`not-actionable` — never a delivery-progress feed, and never the reason a
grant stopped being actionable. The counterparty is the adversary this
design protects the subject against; telling it "revoked" is telling the
adversary the subject just acted against it.

The full three-state read — `issued` | `revoked` | `expired` — exists as
`Platform.getSubjectCapabilityStatus()`, ownership-checked against the
*subject* who granted the capability, not the counterparty who holds it.
Only the subject may see why their own grant stopped being actionable.

## 5. Attenuation rules

`attenuate()` produces a strictly narrower grant: `maxUnits` may only
decrease, `expiresAt` may only decrease, `pairwiseId` may never change,
`singleUse` may only tighten (`false → true`, never the reverse),
`maxAttempts` may only decrease, and `purpose` may never change through this
function. Two sanctioned transitions have their own functions, both reusing
the identical narrowing check, so the sanctioned paths are the only
reachable ones:

- `attenuateToReturn()` — the one purpose transition, `delivery → return`.
  `attenuate()` itself keeps rejecting that same transition.
- `attenuateToReattempt()` — the NDR leg. Not a purpose change: a re-attempt
  is still a delivery. It is the only path that may decrement `maxAttempts`,
  and it always decrements by exactly one, raising `ReattemptsExhausted`
  rather than issuing an unusable grant when the budget is spent.

**Attenuation narrows authority; it does not transfer it.** Redemption is
bound to the actor named in the grant's consent entry, so a validly narrowed
grant in a third party's hands is refused. See §9.

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

## 6a. Geographic precision and the k-floor

Coarse geography is disclosed to counterparties as a `geoBucket`. How coarse
is **derived, not chosen**: the emitted bucket is the finest rung of a
precision ladder whose cell still holds at least `K_ANON_FLOOR` people at
the density the deployment can defend (`rungMeetingFloor` in
`packages/core`, `DIGIPIN_LADDER` in `profiles/address`).

**Direction matters, and the obvious reading is backwards.** A shorter
prefix means a larger cell and therefore more people, so short prefixes
satisfy a k-floor trivially. The k-floor is an **upper bound on precision**,
not a lower one, and the useful answer is the longest prefix still under it.
The lower bound is operational — a carrier needs some minimum precision to
choose a sorting bin — and belongs to the operator. When both are supplied
and the window closes, that is a real conflict and it raises
`PrecisionFloorUnsatisfiable` rather than silently resolving in either
direction.

### 6a.1 The DIGIPIN ladder

Geometry and its provenance: India Post's grid covers a 36° × 36° box
(latitude 2.5–38.5°N, longitude 63.5–99.5°E), each character subdivides the
cell 4×4, and the code is 10 characters. Cell side is therefore
36 / 4ⁿ degrees. At 10 characters that yields ~3.8 m, which agrees with
DoP's published "~4×4 m" figure — the agreement is the check that this
geometry is correct, and it is asserted by a test.

Areas are computed at **20°N**, stated rather than buried because it moves
the answer: longitude foreshortens with latitude, so the same rung is
about 6% larger in area at Kanyakumari than at Delhi.

| Characters | Cell (at 20°N) | Area km² | Density for k=25 | Density for k=50 |
| ---: | --- | ---: | ---: | ---: |
| 4 | 15.7 km × 14.7 km | 230.2806 | 0.109 | 0.217 |
| 5 | 3.9 km × 3.7 km | 14.3925 | 2 | 3 |
| 6 | 978 m × 919 m | 0.8995 | 28 | 56 |
| 7 | 245 m × 230 m | 0.0562 | 445 | 889 |
| 8 | 61 m × 57 m | 0.0035 | 7.11e+3 | 1.42e+4 |
| 9 | 15 m × 14 m | 2.20e-4 | 1.14e+5 | 2.28e+5 |
| 10 | 4 m × 4 m | 1.37e-5 | 1.82e+6 | 3.64e+6 |

The last two columns are people per km² required for a cell at that rung to
hold k people.

### 6a.2 The concession this table forces, stated with the arithmetic attached

Earlier revisions of this implementation truncated DIGIPIN to a fixed 6
characters and described the result as "coarse enough to guarantee
k-anonymity." **Nothing computed that**, and the constant was not merely
underived — it was wrong wherever density was thin. Read the table: a
6-character cell needs ~28 people/km² to hold k=25, and ~56 to hold k=50.
Large parts of rural India sit below both. A fixed 6 therefore
under-protected exactly the populations that DIGIPIN exists to serve, which
is the opposite of the intended trade.

Two figures, both derived above, neither hidden: **~28 people/km² against
the enforced k=25, ~56 against the k≥50 this project's own materials
previously asserted.** Conceding the inversion with the arithmetic attached
is worth more than any claim the constant supported.

The ladder replaces the constant. Where density is thin the emitted cell
widens; where no rung can reach the floor, the call refuses. Both behaviours
are asserted by INV-36 across a density sweep from sparse rural to metro
core, rather than at one convenient point — the whole failure mode of a
constant being that it holds somewhere and not elsewhere.

**Still open:** density is supplied through a `DensityPort`, and the only
implementation shipped here is a flat value. A deployment that used it in
production would be asserting that India has uniform population density. The
port exists so that census or operator data can be supplied without touching
the k-floor logic; wiring real data, and deciding whose density figure is
authoritative, is a deployment question this specification does not settle.

## 7. Multi-operator handoff and federation

Two distinct claims live under this heading, and bundling them reproduces
the original cross-border/multi-operator scoping error one level down. They
are split here (D-7) into what is supported today against a single vault,
and what is deferred to a federated deployment.

### 7.1 Multi-operator handoff against one vault — supported today

A forward leg and a reverse leg run by two different legal entities against
the *same* vault and consent ledger is expressible in shipped code now, not
a future design. `Platform.createReturn` (`services/platform/src/platform.ts:312`)
takes an `actorId` that is never checked against the forward leg's
`grantedTo` — ownership is checked against the *subject* only. A return can
therefore be routed to a carrier that never held the forward-leg grant,
against the same `ConsentLedger`, with no redesign. Evidenced by a test
that drives a return through a different `actorId` than the originating
grant's counterparty and asserts the new consent entry's `grantedTo`
differs from the original
(`tests/grant-core/exceptions.test.ts`, "multi-operator handoff against one
vault").

### 7.2 Federated custody — deferred

A network with more than one vault *operator* — separate custodians, not
just separate counterparties against one custodian — has a kill switch and
a honeypot, whatever the cryptography says. This is a real gap in the
current implementation, named here rather than smoothed over: `Vault` in
this repo is a single class, single-tenant per process. The interface a
federated deployment needs, not yet built:

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

### 7.3 Erasure: why `Vault.erase()` is an authorization gate and not only a log

`Vault.erase()` requires a facilitator-signed credential, verified against
the same `Registry` that gates `Registry.register()` and `suspend()`. Two
designs were available and the choice was previously left unstated, which
is a poor thing to leave to a DPDP reader's inference. Resolving it here.

**The tension.** Erasure is a data-principal *right*. Putting a gatekeeper
in front of a right is exactly the shape a regulator should be suspicious
of: a facilitator that declines to countersign has, in effect, denied the
right. The alternative design — let any caller erase, and make the erasure
itself accountable through an append-only log — has no such veto.

**The decision: keep the authorization gate.** The reasoning is that
`erase()` is not the subject's request channel. It is the operator-side
*execution* of an erasure decision that arrived out of band, and it is
irreversible in the strongest available sense: destroying the shred salt
renders every derived ciphertext permanently unreadable, backups included.
An unauthenticated irreversible operation on a multi-tenant vault is a
denial-of-service primitive and an evidence-destruction primitive before it
is a privacy feature — anyone able to name a `subjectRef` could destroy
another party's records, and there is no undo to fall back on. The
countersignature is what makes the destruction attributable to a named
network actor after the fact.

**What the gate must therefore not become.** Because the objection above is
correct as far as it goes, the gate is only defensible with the following
constraints, which a conforming deployment MUST implement and which this
implementation does **not** yet enforce:

1. A facilitator MUST countersign a verified data-principal erasure request
   within a bounded window defined by network policy, and that window MUST
   be no longer than the statutory response period the deployment is subject
   to.
2. A refusal MUST be recorded with a reason, in the same accountability
   store as the erasure itself. A silent non-response is not a refusal and
   MUST NOT be available as a behaviour.
3. The countersigning role MUST NOT be held by any party with an interest in
   the records surviving — in particular, not by the counterparty whose
   fulfilment produced them.

Stated plainly: this is an authorization gate *and* an accountability log,
not one instead of the other, and items 1–3 are specification-level
commitments that the current code does not check. They are listed in §9.

## 7a. Registry & directory — subscriber identity and the DeDi-shaped interface

`packages/registry` (`Registry`, `signRequest`, `SignedEnvelope`) is **a
Beckn-convention signing layer over a stub registry**, not a Beckn
network-registry client and not a self-minted identity scheme either —
both framings overstate or understate what it is. Participants are
identified by `subscriberId` (FQDN-shaped, per Beckn's subscriber_id
convention — e.g. `merchant.example.org`), and every signed envelope
follows Beckn's actual wire format. What is not Beckn's: `Registry`'s trust
anchor is a locally-seeded genesis facilitator in an in-process `Map`, not
a real network registry, and `ParticipantRole`
(`merchant | operator | brand | platform | facilitator`) is a
locally-defined vocabulary occupying the slot where Beckn's
`subscriber_type` (`BAP | BPP | BG`) belongs — carried as the separate,
optional `Participant.subscriberType` field rather than conflated with
`role`. `tier` is likewise a locally-defined accreditation ordinal, not a
Beckn concept.

What *is* Beckn's is the wire format every signed envelope follows:

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
`DeDiDirectoryPort` against dedi.global's REST API instead — but this is
not a drop-in swap. Every port method today is synchronous and returns
`void`; a network-backed DeDi implementation makes every call site above
async, which is a refactor through the middle of the codebase, not a new
adapter class behind unchanged signatures. Entries also carry no publisher
proof, no record version, and no namespace, all three of which DeDi's real
create/read surface needs. This is a wired, tested half-step — days of
work to close, not hours, and better done against a real namespace with
the protocol's own guidance.

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

This clause exists because a time-boxed transfer commitment is only as
durable as the text that carries it: a spec-text commitment is the only
version of this promise that survives a change of author. It is restated on
`web/candid-books.html` for the same reason.

This repository carries no mark of conformance, and no participation in the
CFP working group is gated on a conformance assessment against it. Ekumen
LLP does not operate, and will not operate, any address-service-provider
role in a live CFP network; this repository is a specification and
reference-implementation donation, not an offer to run infrastructure.

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
  sortation hub — a genuine, unresolved empirical question, not a solved
  one.
- **Threshold-split vault keys.** Single-custodian `Kms`, no m-of-n split.
  Named as an open question, not attempted.
- **The erasure gate's counter-constraints.** §7.3 resolves `Vault.erase()`
  as an authorization gate, but the three constraints that make that
  defensible — a bounded countersigning window, recorded refusals, and a
  countersigner with no interest in the records surviving — are
  specification commitments only. None is enforced in code.
- **Authorize-before-burn (fixed, noted for the record).** `Vault.resolve`
  previously burned the single-use nonce before checking consent, so any
  registered participant holding a valid grant could permanently destroy it
  by attempting redemption — a denial of service against the subject's
  fulfilment, reachable by anyone the grant legitimately passed through.
  The consent check now precedes the burn; the burn remains the
  linearization point immediately before decryption, so single-use
  semantics under concurrency are unchanged. Pinned by INV-37.
- **Forward-leg delegation.** Attenuation narrows authority but does not
  transfer it: `Vault.resolve` requires the redeeming actor to be the party
  named in the grant's consent entry, so a courier holding a validly
  narrowed grant from a merchant cannot redeem it. `Platform.createReturn`
  mints a fresh consent entry for the reverse leg (§7.1); there is no
  forward-leg equivalent, so merchant-to-carrier handoff currently requires
  a round trip that the attenuation story implies it does not. Demonstrated
  live at turn 7 of `web/agentic-flow.html`. The security half of this is
  worth stating too: a stolen grant is not redeemable by an arbitrary
  registered operator, only by the consented one.
- **Density provenance for the precision ladder.** §6a derives bucket
  precision from a `DensityPort`, and the only implementation shipped is a
  flat value. Whose density figure is authoritative, and at what
  granularity, is unsettled.

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
tests.
