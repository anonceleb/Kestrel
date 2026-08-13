# Digital Public Goods (DPG) Submission Evidence

This document provides structured evidence for Kestrel's submission to the Digital Public Goods Alliance (DPGA), mapping the solution to the indicators of the DPG Standard.

## 1. SDG Relevance (Indicator 1)

Kestrel is directly aligned with the following United Nations Sustainable Development Goals (SDGs):

*   **SDG 9: Industry, Innovation, and Infrastructure (Target 9.c)**: By providing a modular, open-source, capability-based digital credential primitive, Kestrel enables local and regional developers to build secure, privacy-preserving digital solutions without relying on closed proprietary infrastructure.
*   **SDG 11: Sustainable Cities and Communities (Target 11.1)**: Kestrel's India Post adapter demonstrates integration with the **DIGIPIN** geocoded grid, routing parcels off a truncated prefix rather than the full code so a courier never receives an exact coordinate. This is a real minimization step, but it is **not yet a verified k-anonymity guarantee**: the truncation is currently a fixed 6-character prefix (a constant ~0.90 km² cell), and against the repository's own asserted k≥50 that cell only holds up above roughly 55 people/km² — a threshold much of rural India falls below. The adaptive, density-aware prefix needed to make the anonymity claim hold uniformly (including in the unmapped/informal-settlement geographies this SDG target names) is an open item, tracked in [`web/candid-books.html`](./web/candid-books.html) alongside the numbers above. We report this honestly here rather than overclaim it as solved.
*   **SDG 16: Peace, Justice, and Strong Institutions (Target 16.9 & 16.10)**: By using pairwise pseudonyms and consent ledgers, Kestrel guarantees data privacy, protects digital fundamental rights, and ensures that citizens can safely verify credentials or fulfill deliveries without risking identity theft or mass surveillance.

## 2. Platform Independence (Indicator 4)

Kestrel has **zero mandatory proprietary dependencies**.
*   It is written in TypeScript and runs on standard, open-source Node.js (≥ 22.6) using native type stripping.
*   It does not require any specific cloud provider, vendor-locked database, or proprietary service.
*   The browser-compatible ES modules can be served by any static file server completely offline.

## 3. Open Standards & Best Practices (Indicator 8)

Kestrel adopts and complies with the following open standards and cryptographic best practices:

*   **Beckn Protocol**: Follows the Beckn protocol wire formats and naming conventions for async request-callback pairs (e.g., action/on_action).
*   **COSE (RFC 9052) & CBOR (RFC 8949)**: Encodes offline-verifiable courier labels in a compact binary format suitable for physical QR codes.
*   **ChaCha20-Poly1305 (RFC 8439)**: Utilized for authenticated, tamper-evident symmetric encryption of stored attributes.
*   **HKDF (RFC 5869)**: Standard HMAC-based key derivation function for generating deterministic per-record keys and pairwise pseudonyms.
*   **Ed25519 (RFC 8032)**: Public-key signature scheme for signing Beckn envelopes and parcel labels.
*   **DIGIPIN**: The Department of Posts (India) standard for geocoding, utilized by Kestrel's physical delivery adapter to route parcels using sortation-prefix privacy masks.

## 4. Ownership (Indicator 3)

Kestrel is authored and maintained by **Ekumen LLP** — see
[`NOTICE`](./NOTICE) for the full ownership and licensing statement, and
[`README.md`](./README.md) for current maintainer contact. Ekumen LLP holds no exclusive
rights beyond the Apache-2.0 license itself: the code, spec, and donated invariant suite are
usable, forkable, and redistributable by anyone under that license today, independent of
Ekumen's continued involvement. `spec/CFP-v0.x.md` §8 additionally commits to transferring
stewardship to a named neutral home no later than 12 months after v0.1 publication.

## 5. License (Indicator 2)

Kestrel is licensed under **Apache License 2.0** — see [`LICENSE`](./LICENSE). This is an
OSI-approved, DPG-Standard-compliant open license with no field-of-use restriction, applied
uniformly across the spec, the reference implementation, and the donated invariant suite.

## 6. Documentation (Indicator 5)

Kestrel ships documentation at multiple levels for different audiences:

*   [`README.md`](./README.md) — project overview, design choices, module map, and how to run the suite.
*   [`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md) — the pilot-scoped protocol specification (token format, redemption semantics, disclosure policy).
*   [`doc/CFP-functional-manual.md`](./doc/CFP-functional-manual.md) and [`doc/CFP-technical-manual.md`](./doc/CFP-technical-manual.md) — functional and technical deep dives.
*   [`CONTRIBUTING.md`](./CONTRIBUTING.md) — how to propose changes, plus the invariant-suite discipline contributors are expected to follow.
*   [`web/candid-books.html`](./web/candid-books.html) — a maintained, line-referenced ledger of every closed gap (with the test that proves it) and every open gap, kept to the same standard of evidence as the closed items.
*   [`tests/README.md`](./tests/README.md) — reconciles invariant and test counts against the base repository this project forked from.

## 7. Mechanism for Extracting Data (Indicator 6)

Kestrel's core design property is that no personally identifiable data is ever transmitted to
or held by the orchestration layer. Concretely:

*   Attributes (address, phone number) are encrypted client-side/in-vault and never leave the Vault (Zone 1) in plaintext; the Platform (Zone 2) coordinates using only opaque capability tokens.
*   A subject or an integrator can extract their own stored attributes at any time via the Vault's decryption path, which is the only decryption path in the system (`services/vault/src/vault.ts`).
*   Because the system is a self-hosted reference implementation rather than a hosted service, any deploying party fully controls their own data store and export mechanism — there is no vendor lock-in on data extraction.
*   Deletion (`Vault.erase()`) is implemented as crypto-shredding — destroying the per-record HKDF key renders the ciphertext permanently unrecoverable, which is a stronger and more auditable data-extraction/erasure boundary than a soft-delete flag.

## 8. Privacy and Applicable Laws (Indicator 7)

See [`PRIVACY.md`](./PRIVACY.md) for the full compliance mapping (GDPR, India's DPDP Act 2023,
IT Act 2000 §43A). In summary: Kestrel enforces data minimization and purpose limitation by
construction (the orchestration layer never sees plaintext PII), supports the right to erasure
via crypto-shredding, and logs every disclosure against a signed, versioned policy hash for
auditability. Kestrel does not itself collect, store, or transmit data to its authors or any
third party — compliance obligations for a specific deployment rest with the deploying entity,
as for any self-hosted open-source library.

## 9. Do No Harm by Design (Indicator 9)

Kestrel's threat-model work is deliberately public and includes what is **not yet** solved,
not only what is. [`web/candid-books.html`](./web/candid-books.html) is maintained as a single
page listing every closed gap next to the test that closes it, and every open gap — including,
at the time of writing, the DIGIPIN precision-floor gap described in §1 above, carrier-identity
binding, threshold-split vault key custody, and depot-time resolution under low connectivity.
We consider an honest open-items list a precondition for a "do no harm" claim, not an admission
against one: a reviewer should be able to find every unresolved risk in one place rather than
infer it from what the documentation omits.
