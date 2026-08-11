# CFP — Confidential Fulfilment Profile

A capability, not a shared secret: a scoped, expiring, single-use, revocable,
non-widening grant to cause an action against a sensitive attribute — where
the attribute itself never crosses the network. Address is the first
attribute profile. Contact/phone is the second. The grant core underneath
both is generic.

> *"Yes to the primitive. No to the layer. Not yet to the extension."*
> — the FIDE convergence memo this repo executes

**Live demo:** [kestrel-ebon.vercel.app](https://kestrel-ebon.vercel.app/index.html)

**Runs entirely offline. No install, no database, no cloud account, no network.**
Node ≥ 22.6 only — TypeScript executes via native type stripping.

```bash
npm run verify   # privacy-lint + grant-core + profile invariant suites
npm run demo     # narrated end-to-end grant lifecycle
```

## Lineage

This repo is derived by copy from a prior address-shaped reference
implementation, which proved the mechanism: counterparties hold scoped,
expiring, single-use, revocable, non-widening grants over a street address;
only a vault resolves them; 28 executable privacy invariants enforced it in
CI. That prior repo stays untouched as reference implementation and prior
art — this repo does not move or edit it, only forks from it. The fork
exists because a three-round strategy review concluded the address-specific
framing was "a layer named after one car" — the generic capability-grant
primitive underneath is the actual contribution worth offering an open
network steward, with address as its first instance and contact/phone as
its second.

## What changed from the prior implementation

- **Renamed the core off address vocabulary.** `S2ID` → `PairwiseId`,
  `AddressPlaintext` → `ConfidentialPayload`, `SortationPort` → `RoutingPort`,
  `ShipmentRequest`/`createShipment` → `FulfilmentRequest`/`createGrant`,
  `Capability` → aliased publicly as `FulfilmentGrant`. Nothing under
  `packages/` may contain an address-shaped identifier outside `profiles/` —
  enforced by a new `tools/privacy-lint` rule, not just a naming convention.
- **Closed the five gaps `THREAT_MODEL.md` admitted were open** (registry
  write authorization, the self-signed default policy, adapter log-hygiene
  coverage, root-secret/pairwise-ID placement, platform-side cross-merchant
  correlation) — see `spec/CFP-v0.x.md` and `web/candid-books.html` for what
  changed and which test proves it.
- **Added a third postal adapter** (`adapters/india-post`, DIGIPIN-shaped)
  to prove the interop claim across three operators, not two.
- **Split the grant core from the address profile** into `profiles/address`
  and a new `profiles/contact` (phone-number masking, mobility-shaped) that
  reuses the identical `FulfilmentGrant` mint/attenuate/redeem path with no
  forked token logic.
- **Rebuilt the demo surface** (`web/`) for a protocol steward audience
  rather than a merchant one: the agentic-checkout comparison leads, an
  attack console lets a skeptical reader try to break the primitive in the
  browser, and a candid-books page states what's closed, what's still open,
  and the stewardship commitment verbatim.

## What's here

```
packages/
  crypto/      envelope encryption (ChaCha20-Poly1305), HKDF record keys, crypto-shredding
  identity/    pairwise ID derivation — stable per counterparty, unlinkable across counterparties
  registry/    Ed25519 request signing + participant registry (ONDC/Beckn shape), authorized writes
  capability/  scoped, expiring, single-use, attenuable FulfilmentGrant tokens
  labels/      COSE_Sign1 offline-verifiable redemption artifacts + rotating operator keys
  policy/      signed, versioned, hot-reloadable disclosure policy — no self-signed default
  network/     Beckn-shaped async request/callback pairs (action/on_action)
  metering/    per-participant metered API quota
  webhooks/    signed HTTP delivery — HMAC-SHA256, fetch(), bounded retry
  sdk/         the published integrator-facing surface — FulfilmentClient, GrantResult
  core/        domain, consent ledger, ports — imports NOTHING from adapters or services
services/
  vault/       ZONE 1 — the only decryption path; pairwise-ID issuance lives here, not Platform
  platform/    ZONE 2 — orchestration; holds ciphertext, holds no keys, never issues pairwise IDs
adapters/
  postal-meridia/  fictional operator, carried over unchanged — proves operator-agnosticism
  dakhil-post/     second fictional operator, different address shape and key custody
  india-post/      third operator — DIGIPIN-prefix routing and COSE artifacts
profiles/
  address/     the India-Post-shaped ConfidentialPayload — line1/line2/locality/postcode + DIGIPIN
  contact/     phone-number masking — ConfidentialPayload is { e164 }, a call-relay RoutingPort
tests/
  grant-core/       mechanism-only invariants — the donated artifact
  profiles/address/ address-profile invariants + three-way adapter interop
  profiles/contact/ proves the contact profile reuses the identical grant core
tools/
  privacy-lint/    CI gate: core purity, zone-3 shape, log hygiene across packages/services/adapters/profiles
  demo/            narrated walkthrough
spec/CFP-v0.x.md   the pilot-scoped interface note — submitted nowhere
web/               the six-page browser demo
```

## Deploy recipe

Everything here was prepared so the only manual steps were:

```bash
git init                 # already done in this repo
gh repo create cfp-demo --public --source=. --push
vercel                   # bind a new Vercel project to the new GitHub repo
```

Live at [kestrel-ebon.vercel.app](https://kestrel-ebon.vercel.app/index.html).

No serverless functions are required — `web/` is static HTML with inline
CSS/JS, and every page has a working client-side fallback so the "runs
entirely offline" property survives the fork.

## Tone

This is a contribution, not a pitch. No certification language, no trust
marks, no "moat." The primitive leads; address and contact are instances of
it, not the point. Open problems (offline double-redemption, carrier
binding) are stated with the same prominence as closed ones — see
`web/candid-books.html`.
