# Digital Public Goods (DPG) Submission Evidence

This document maps Kestrel to the nine indicators in the DPG Standard, for its submission to
the Digital Public Goods Alliance (DPGA).

## 1. SDG Relevance (Indicator 1)

Kestrel connects to a few UN Sustainable Development Goals:

*   **SDG 9 (Industry, Innovation and Infrastructure, target 9.c):** Kestrel is an open building
    block for secure, privacy-preserving delivery systems. Any developer can build on it without
    depending on closed, proprietary infrastructure.
*   **SDG 11 (Sustainable Cities and Communities, target 11.1):** the India Post adapter uses a
    shortened version of the DIGIPIN location code, so a courier gets a rough area instead of an
    exact coordinate. That helps, but it isn't a proven privacy guarantee yet. The shortened code
    always covers about 0.9 km², and by our own math that only hides people well in areas with at
    least roughly 55 people per km² — which rules out a lot of rural India, exactly the kind of
    place this SDG target is about. We list this as an open problem in
    [`web/candid-books.html`](./web/candid-books.html) rather than claim it's solved.
*   **SDG 16 (Peace, Justice and Strong Institutions):** each merchant sees a different,
    unlinkable ID for the same person, and every access to their data is logged against the
    consent that allowed it. That makes it harder for anyone to build a surveillance profile out
    of delivery data.

## 2. Platform Independence (Indicator 4)

Kestrel doesn't depend on any proprietary software.

*   Written in TypeScript, runs on plain Node.js (≥ 22.6).
*   Doesn't need a specific cloud provider, database, or paid service.
*   The browser version is static files — any web server can host it, and it runs fully offline.

## 3. Open Standards & Best Practices (Indicator 8)

Kestrel uses these open standards and cryptographic building blocks:

*   **Beckn Protocol** — uses Beckn's message formats and conventions for async request/callback pairs (`action`/`on_action`).
*   **COSE (RFC 9052) & CBOR (RFC 8949)** — offline-verifiable courier labels, compact enough for a QR code.
*   **ChaCha20-Poly1305 (RFC 8439)** — authenticated encryption for stored attributes.
*   **HKDF (RFC 5869)** — key derivation, used for per-record keys and pairwise pseudonyms.
*   **Ed25519 (RFC 8032)** — signs Beckn envelopes and parcel labels.
*   **DIGIPIN** — the Department of Posts (India) geocoding standard; the delivery adapter routes on a truncated prefix of it.

## 4. Ownership (Indicator 3)

Ashwin Kumar Natarajan and Karthik Nagasubramanian, operating as Ekumen
Digital Solutions LLP (incorporation pending), wrote and maintain this
repository — see [`NOTICE`](./NOTICE) for the full ownership statement and
[`README.md`](./README.md) for maintainer contact. Neither holds any special
rights beyond the Apache-2.0 license: anyone can use, fork, or redistribute
the code, spec, and test suite today, whether or not they stay involved. The spec also
commits to handing stewardship to a named neutral body within 12 months of the v0.1 release
(`spec/CFP-v0.x.md` §8).

## 5. License (Indicator 2)

Kestrel is licensed under Apache 2.0 — see [`LICENSE`](./LICENSE). It's an OSI-approved open
license with no restriction on who can use it or for what, applied the same way across the
spec, the reference code, and the test suite.

## 6. Documentation (Indicator 5)

Documentation exists at a few different levels:

*   [`USE_CASES.md`](./USE_CASES.md) — who this is for and what problem it solves, in plain
    language, with a concrete example. Start here if you're not a protocol engineer.
*   [`README.md`](./README.md) — project overview, design choices, module map, how to run the suite.
*   [`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md) — the pilot-scoped protocol spec (token format, redemption semantics, disclosure policy).
*   [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to propose changes.
*   [`web/candid-books.html`](./web/candid-books.html) — a running list of every closed gap (with the test that proves it) and every open gap.
*   [`tests/README.md`](./tests/README.md) — reconciles invariant and test counts against the base repository this project forked from.

## 7. Mechanism for Extracting Data (Indicator 6)

The core design rule: no personal data ever passes through or sits in the orchestration layer.
In practice:

*   Addresses and phone numbers are encrypted and stay in the Vault. The Platform, which coordinates the actual order, only ever sees opaque tokens — never the real data.
*   A subject, or whoever integrates on their behalf, can read their own stored data back out at any time. There's exactly one decryption path in the system, in `services/vault/src/vault.ts`.
*   This isn't a hosted service — whoever runs it controls their own data store, so there's no vendor lock-in on getting data out.
*   Deleting a record (`Vault.erase()`) destroys its encryption key, not just a database row. Once the key is gone, the encrypted data is permanently unreadable — a stronger guarantee than a normal soft-delete flag.

## 8. Privacy and Applicable Laws (Indicator 7)

[`PRIVACY.md`](./PRIVACY.md) has the full breakdown (GDPR, India's DPDP Act 2023, IT Act
2000 §43A). Short version: data minimization and purpose limitation are built into the
architecture, not bolted on — the orchestration layer never sees plaintext personal data at
all. The right to erasure works by crypto-shredding, and every disclosure is logged against
the exact policy that authorized it. Kestrel itself never collects, stores, or sends data to
us or anyone else — whoever deploys it is responsible for their own compliance, same as with
any self-hosted open-source software.

## 9. Do No Harm by Design (Indicator 9)

We publish what's still broken, not just what's fixed.
[`web/candid-books.html`](./web/candid-books.html) lists every closed gap next to the test that
proves it's closed, and every open one — right now that includes the DIGIPIN precision problem
from §1 above, carrier-identity binding, single-custodian vault keys, and how depot resolution
holds up on a bad connection. We think an honest list of open problems is what a "do no harm"
claim should look like, not something that undercuts one — a reviewer should be able to find
every known risk in one place instead of guessing from what isn't mentioned.
