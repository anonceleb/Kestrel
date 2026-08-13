# CFP — Confidential Fulfilment Profile

Authored and maintained by **Ashwin Kumar Natarajan and Karthik Nagasubramanian**
(operating as Ekumen Digital Solutions LLP, incorporation pending). See
[`NOTICE`](./NOTICE) for licensing and this project's lineage from an
earlier, discontinued prototype.

A capability, not a shared secret: a scoped, expiring, single-use, revocable,
non-widening grant to cause an action against a sensitive attribute — where
the attribute itself never crosses the network. Address is the first
attribute profile. Contact/phone is the second. The grant core underneath
both is generic.

A generic capability-grant primitive, address as its first attribute
profile, contact/phone as its second — donated as a protocol contribution,
not operated as a product.

**New here?** [`USE_CASES.md`](./USE_CASES.md) explains who this is for and what problem it
solves, in plain language, before the rest of this file gets technical.

**Live demo:** [kestrel-ebon.vercel.app](https://kestrel-ebon.vercel.app/index.html)

**Runs entirely offline. No install, no database, no cloud account, no network.**
Node ≥ 22.6 only — TypeScript executes via native type stripping.

```bash
npm run verify     # privacy-lint + grant-core + profile invariant suites
npm run demo       # narrated end-to-end grant lifecycle
npm run build:web  # regenerate web/assets/js from the sources (shim selftest gates the emit)
cd web && python3 -m http.server 8741   # then open http://localhost:8741 — the demo is static files
```

## Design choices

- **The core carries no address vocabulary.** `PairwiseId`,
  `ConfidentialPayload`, `RoutingPort`, `FulfilmentRequest`/`createGrant`,
  `FulfilmentGrant` as the public capability type. Nothing under
  `packages/` may contain an address-shaped identifier outside `profiles/` —
  enforced by a `tools/privacy-lint` rule, not just a naming convention. A
  strategy review concluded that an address-specific framing reads as "a
  layer named after one car" — the generic capability-grant primitive is
  the actual contribution worth offering an open network steward, with
  address as its first instance and contact/phone as its second.
- **Five threat-model gaps are closed with tests**, not just documented:
  registry write authorization, the self-signed default policy, adapter
  log-hygiene coverage, root-secret/pairwise-ID placement, and platform-side
  cross-merchant correlation — see `spec/CFP-v0.x.md` and
  `web/candid-books.html` for what closed and which test proves it.
- **Three postal adapters prove the interop claim** (`adapters/{postal-meridia,dakhil-post,india-post}`),
  the third DIGIPIN-shaped, with a test proving zero core diff and no output
  collisions across all three.
- **The grant core is split from the address profile** into
  `profiles/address` and a `profiles/contact` (phone-number masking,
  mobility-shaped) that reuses the identical `FulfilmentGrant`
  mint/attenuate/redeem path with no forked token logic.
- **The demo surface** (`web/`) runs the repo's own modules in the browser,
  not a re-implementation. `npm run build:web` transforms every source under
  `packages/`, `services/`, `profiles/`, and `adapters/` 1:1 into browser ES
  modules (Node's own type-stripper; import specifiers rewritten; nothing
  else), swapping `node:crypto` for a pure-JS shim that the build first
  verifies against `node:crypto` itself — 63 equivalence checks covering
  digests byte-for-byte, ChaCha20-Poly1305 in both directions, and Ed25519
  cross-verification — and refuses to emit on any mismatch. The result: the
  attack console throws the real error classes from the real `Vault`, the
  address page mints real Beckn-signed envelopes and COSE_Sign1 labels
  client-side, and `web/assets/js/manifest.json` records the SHA-256 of the
  source behind every emitted module, so "the demo runs the donated code" is
  checkable, not asserted.

## Scope: where CFP begins

CFP begins **after discovery.** There is no search, catalog, matching, or
`select`/`on_select`-shaped code anywhere in this repo — every flow here
starts from an already-formed order/grant context (a merchant already knows
what a subject bought and needs to fulfil it). Finding a merchant, a
product, or an operator is out of scope by design, not by omission: the
primitive this repo donates is the confidential-fulfilment grant that kicks
in once discovery has already happened, wherever it happens. See
`web/candid-books.html` for the closed/open status of every other boundary
this repo draws.

## What's here

```
packages/
  crypto/      envelope encryption (ChaCha20-Poly1305), HKDF record keys, crypto-shredding
  identity/    pairwise ID derivation — stable per counterparty, unlinkable across counterparties
  registry/    A Beckn-convention signing layer over a stub registry: subscriber_id identity,
               XEd25519/BLAKE-512 signed envelopes, authorized writes, Beckn's wire format —
               but a locally-defined role/tier vocabulary and an in-process Map as trust anchor,
               not a client of any real Beckn network registry (see the module docstring)
  directory/   DeDi-shaped key/revocation/policy directory port — an in-memory demo backend behind
               the DeDiDirectoryPort interface, explicitly NOT a live dedi.global integration
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
  README.md         invariant-count reconciliation against the base repository — read this first
                     if the numbers here and elsewhere don't look like they line up
  grant-core/       mechanism-only invariants — the donated artifact
  profiles/address/ address-profile invariants + three-way adapter interop
  profiles/contact/ proves the contact profile reuses the identical grant core
tools/
  privacy-lint/    CI gate: core purity, zone-3 shape, log hygiene across packages/services/adapters/profiles
  demo/            narrated walkthrough
  web-build/       emits web/assets/js from the real sources; shim selftest against node:crypto gates the emit
spec/CFP-v0.x.md   the pilot-scoped interface note — submitted nowhere
web/               the browser demo — six pages driving the modules under web/assets/js
```

## Deploy recipe

Everything here was prepared so the only manual steps were:

```bash
git init                 # already done in this repo
gh repo create cfp-demo --public --source=. --push
vercel                   # bind a new Vercel project to the new GitHub repo
```

Live at [kestrel-ebon.vercel.app](https://kestrel-ebon.vercel.app/index.html).

No serverless functions are required — `web/` is static HTML plus the
generated modules under `web/assets/js/` (committed, so Vercel needs no
build step). The pages make no network requests beyond loading their own
modules, so the "runs entirely offline" property holds behind any static
file server.

## Tone

This is a contribution, not a pitch. No certification language, no trust
marks, no "moat." The primitive leads; address and contact are instances of
it, not the point. Open problems (offline double-redemption, carrier
binding) are stated with the same prominence as closed ones — see
`web/candid-books.html`.
