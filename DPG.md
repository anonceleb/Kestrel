# DPG Standard — self-assessment

**Status: not submitted.** This is a working self-assessment of CFP against the nine
indicators of the [Digital Public Goods Standard](https://digitalpublicgoods.net/standard/),
kept in the repository so the gaps are visible. **No application has been made to the Digital
Public Goods Alliance, and nothing here has been reviewed or accepted by them.** An earlier
version of this file was titled "DPG Submission Evidence" and read as though it had been; it
had not.

Where an indicator is not met, this file says so rather than describing the nearest thing that
is met. Indicators 6 and 9 in particular are **not currently satisfied** — see below.

The project is named **CFP** (Confidential Fulfilment Profile). *Kestrel* survives only in the
GitHub repository URL and the hosted demo hostname, which are not yet renamed; in prose the name
is retired to the lineage note in [`NOTICE`](./NOTICE).

---

## Indicator 1 — Relevance to Sustainable Development Goals

*   **SDG 9 (Industry, Innovation and Infrastructure, target 9.c)** — CFP is an open building
    block for privacy-preserving fulfilment. Any developer can build on it without depending on
    closed infrastructure.
*   **SDG 11 (Sustainable Cities and Communities, target 11.1)** — the India Post adapter
    discloses a *truncated* DIGIPIN prefix rather than a full grid code, so a courier receives a
    coarse area rather than a doorstep. **How coarse is derived, not fixed:** the emitted bucket
    is the finest rung whose cell still holds at least `K_ANON_FLOOR` (25) people at the
    deployment's own density figure — see [`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md) §6a for the
    published ladder and its arithmetic.

    The honest caveat, which used to be the headline problem here: an earlier version truncated
    to a fixed 6 characters (~0.90 km²) and asserted that was "coarse enough to guarantee
    k-anonymity." Nothing computed it, and it was wrong where density was thin — a 6-character
    cell needs ~28 people/km² to hold 25 people, which much of rural India falls below. The
    ladder replaces the constant, and where no rung reaches the floor the call now refuses
    rather than emitting an under-protected bucket. **What remains open:** density arrives
    through a pluggable port whose only shipped implementation is a flat value, so the guarantee
    is only as good as the figure a deployment supplies.
*   **SDG 16 (Peace, Justice and Strong Institutions)** — each counterparty sees a different,
    unlinkable identifier for the same person, and every decryption is logged against the
    consent that authorised it, before the plaintext exists. That raises the cost of assembling
    a surveillance profile out of fulfilment data.

## Indicator 2 — Use of an approved open licence

Apache License 2.0 — see [`LICENSE`](./LICENSE). OSI-approved, applied identically to the spec,
the reference implementation, and the invariant suite. **Met.**

## Indicator 3 — Clear ownership

Ashwin Kumar Natarajan and Karthik Nagasubramanian, operating as Ekumen Digital Solutions LLP
(incorporation pending), authored and maintain this repository — see [`NOTICE`](./NOTICE) for
the full ownership statement **and the contact path**. Neither holds any right beyond the
Apache-2.0 licence: anyone may use, fork, or redistribute the code, spec, and suite today,
whether or not the authors stay involved.

[`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md) §8 commits to transferring stewardship to a named
neutral body no later than twelve months after **CFP v0.1 publication**. That publication has
not happened, and the `package.json` version is deliberately `0.0.x` so the package version
cannot be mistaken for the release that starts that clock. **Met.**

## Indicator 4 — Platform independence

*   TypeScript on plain Node.js (≥ 22.6), executed by native type-stripping.
*   **Zero runtime dependencies.** No specific cloud provider, database, or paid service.
*   The browser demo is static files — any web server can host it, and it runs fully offline.

**Met.**

## Indicator 5 — Documentation

*   [`USE_CASES.md`](./USE_CASES.md) — who this is for and what problem it solves, in plain language.
*   [`README.md`](./README.md) — overview, design choices, module map, how to run the suite.
*   [`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md) — the pilot-scoped interface note.
*   [`spec/CFP-beckn-binding.md`](./spec/CFP-beckn-binding.md) — how a grant would ride inside existing Beckn messages. **Specified, not implemented.**
*   [`CONTRIBUTING.md`](./CONTRIBUTING.md), [`SECURITY.md`](./SECURITY.md), [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md).
*   [`web/candid-books.html`](./web/candid-books.html) — every closed gap with the test that pins it, and every open one.
*   [`tests/README.md`](./tests/README.md) — invariant-count reconciliation.

**Met**, with the caveat that `packages/sdk` is documented as an integrator surface while being
unpublished and untested; that is stated in the README and on candid-books.

## Indicator 6 — Mechanism for extracting data — **NOT MET**

The DPG Standard asks whether **non-personally-identifiable data** can be extracted or imported
in a **non-proprietary format**. An earlier version of this file answered a different question —
how a *subject* reads their own personal data back — which is a privacy property, not this
indicator, and it is corrected here rather than left to a reviewer to catch.

Assessed honestly:

*   **CFP is a library, not a hosted service, and stores nothing centrally.** Whoever deploys it
    owns their datastore, so there is no vendor to be locked in by. That is the strongest thing
    that can be said, and it is not the same as satisfying the indicator.
*   **There is no export mechanism.** No CLI, no endpoint, no documented dump format for the
    consent ledger, the audit log, or the registry — the three stores that hold non-PII an
    operator would legitimately need to take with them. They are in-process maps.
*   **What would satisfy it:** a documented export of the consent ledger and audit log as
    newline-delimited JSON, which is a small piece of work and is not yet done.

Recorded here as an open item rather than argued around.

## Indicator 7 — Adherence to privacy and applicable laws

[`PRIVACY.md`](./PRIVACY.md) is the full statement. It describes **design alignment** with
GDPR, India's DPDP Act 2023, and IT Act §43A — and, deliberately, does not claim CFP "meets" or
"complies with" any of them, because compliance is a property of a deployment rather than of a
library. It carries a section on what is *not* enforced, starting with the erasure-gate
constraints that `spec/CFP-v0.x.md` §7.3 requires and the code does not implement.

Data minimisation and purpose limitation are structural: the orchestration layer never holds
plaintext, erasure is crypto-shredding, and every disclosure is logged against the policy that
authorised it. CFP collects nothing and transmits nothing to its authors. **Met, with the
non-enforced constraints named.**

## Indicator 8 — Use of open standards and best practices

*   **COSE (RFC 9052) and CBOR (RFC 8949)** — offline-verifiable labels, compact enough for a QR code.
*   **ChaCha20-Poly1305 (RFC 8439)** — authenticated encryption for stored attributes.
*   **HKDF (RFC 5869)** — per-record keys and pairwise pseudonyms.
*   **Ed25519 (RFC 8032)** — signs registry envelopes and labels.
*   **BLAKE2b-512 (RFC 7693)** — the canonical-body digest inside a signed envelope.
*   **Beckn Protocol** — CFP implements Beckn's *subscriber-signing* wire format and its
    `action`/`on_action` async pattern. It does **not** yet emit Beckn *messages*: there is no
    `Stop.authorization` or `Fulfillment.tags` emitter, and the binding is specified but not
    built (`spec/CFP-beckn-binding.md`).
*   **DIGIPIN** — the Department of Posts (India) geocoding standard. The adapter *buckets* on a
    derived-length prefix; the sortation code itself is a SHA-256 of the full DIGIPIN plus the
    service, so it carries no geography.

**Met.**

## Indicator 9 — Do no harm by design — **PARTLY MET**

The DPG Standard splits this into three sub-indicators. Assessed separately, because the
previous version of this file answered only the first and treated an open-bug list as the whole
of "do no harm."

### 9A — Data privacy and security

The substance of this project. Attributes are encrypted at rest under per-record keys and
decryptable only inside Zone 1; decryption is audited before the plaintext exists; identifiers
are pairwise; erasure is crypto-shredding. Known weaknesses are enumerated in
[`SECURITY.md`](./SECURITY.md), `spec/CFP-v0.x.md` §9, and
[`web/candid-books.html`](./web/candid-books.html) — with the same prominence as what is closed,
and the open list is the longer one. A private reporting channel exists (SECURITY.md).
**Met.**

### 9B — Inappropriate or illegal content

**Not applicable, and the reasoning matters more than the verdict.** CFP stores no
user-generated content: the only data it holds is an encrypted attribute payload supplied by
the deploying operator, and it is never rendered, indexed, searched, or served to third parties.
There is no discovery surface anywhere in the repository — no search, catalog, or matching code
— by design. **N/A.**

### 9C — Protection from harassment

**Partly met, and this is the honest gap.**

*   For the *project community*: [`CODE_OF_CONDUCT.md`](./CODE_OF_CONDUCT.md) adopts Contributor
    Covenant 2.1, with a private reporting channel, a 7-day acknowledgement, the enforcement
    ladder, and an explicit conflict-of-interest clause for the case where a report concerns one
    of the two maintainers.
*   For *end users of a deployment*: one relevant protection exists — the household barrier
    (INV-12), which stops co-residents at a shared record from enumerating each other, a
    scenario that matters for domestic-abuse survivors. Beyond that, CFP has no user-to-user
    interaction surface to harass through.
*   **What is missing:** the design does not address the case where the *counterparty* is the
    threat to the subject — a merchant or carrier operative using fulfilment access to locate
    someone. Grants are narrow, single-use and revocable, which limits that, and revocation is
    deliberately indistinguishable from expiry so a subject withdrawing consent does not signal
    it. But there is no threat-model section written from the vulnerable-user perspective, and
    that is the piece a DPGA reviewer would reasonably ask for.

---

## Summary

| Indicator | Status |
|---|---|
| 1 — SDG relevance | Met, with the density-provenance caveat stated |
| 2 — Open licence | Met |
| 3 — Clear ownership | Met |
| 4 — Platform independence | Met |
| 5 — Documentation | Met |
| 6 — Data extraction | **Not met** — no export mechanism |
| 7 — Privacy and applicable laws | Met, with non-enforced constraints named |
| 8 — Open standards | Met |
| 9 — Do no harm | **Partly met** — 9A met, 9B N/A, 9C partly |
