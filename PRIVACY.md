# Privacy & data protection

CFP (Confidential Fulfilment Profile) lets an action happen against a sensitive
attribute — an address, a phone number — without ever exposing or transmitting the attribute
itself.

**Read this first:** CFP is a **reference implementation**, not a compliance product. This
page describes how its design *aligns with* the goals of several privacy regimes and, just as
importantly, what a deployer still has to do. It does not claim CFP "meets," "satisfies,"
or "complies with" any regulation, because compliance is a property of a deployment — its
custody arrangements, retention policy, contracts, and operational controls — not of a
library. Several of the mechanisms below are demo-grade by design, and some of the constraints
the design depends on are stated in the spec but **not enforced in code**. Those are named
explicitly in §3.

## 1. Privacy by design

*   **It runs offline.** Everything executes client-side or in-process — no cloud database, no required network calls.
*   **Attributes stay encrypted.** They're stored only inside the Vault. The Platform, which coordinates the transaction, only ever handles opaque tokens — never the attribute.
*   **Each counterparty sees a different ID for the same person.** IDs are derived per-counterparty, so two merchants can't compare notes and discover they're dealing with the same subject.
*   **Deleting someone's data means destroying their encryption key**, not searching every backup for their record. Once the per-record salt is gone the ciphertext is permanently unreadable — crypto-shredding.
*   **Every stored record is encrypted** with ChaCha20-Poly1305 and bound to its own tenant and record ID, so a ciphertext can't be lifted into another record's slot.
*   **Decryption is audited before it happens.** The audit record is written in the same call frame, before plaintext exists — a decryption that cannot be attributed to an actor, a purpose and a consent reference is unreachable rather than merely discouraged.

## 2. How the design maps to privacy law

The middle column describes a **design alignment**, not a compliance claim. The right-hand
column is the part a deployer owns.

| Regulation | What the design does | What a deployer still has to do |
|---|---|---|
| **GDPR (EU)** | Data minimisation (Art 5(1)(c)) is structural: a counterparty receives a capability, never the attribute. Erasure (Art 17) is implemented as crypto-shredding, which reaches backups and append-only logs. Security of processing (Art 32) uses authenticated encryption (ChaCha20-Poly1305) and per-record keys. | Establish a lawful basis; run the key custody (see §3); set retention for the audit log, which deliberately survives erasure; handle DSARs, breach notification and records of processing; complete a DPIA. |
| **DPDP Act (India, 2023)** | Purpose limitation and consent are recorded per event in a hash-chained Consent Ledger that names the purpose and the actor, so any grant can be traced to the policy that authorised it, and consent can be revoked. | Appoint the Data Fiduciary; implement the erasure-gate constraints in §3, which the spec requires and the code does not enforce; provide subject-facing consent withdrawal and grievance redressal. |
| **IT Act (India, 2000)** | Contributes to Section 43A "reasonable security practices" through standard key derivation, authenticated encryption, signed registry writes and audit logging. | Adopt a documented security-practices standard; operate key custody in an HSM; obtain whatever certification the deployment's sector requires. |

## 3. What is *not* enforced, and other limits

Stated here rather than left for a reader to discover.

*   **The erasure gate's counter-constraints are specification-only.** `spec/CFP-v0.x.md` §7.3 resolves `Vault.erase()` as an authorization gate, and says that is only defensible alongside three constraints: a bounded countersigning window, recorded refusals, and a countersigner with no interest in the records surviving. **None of the three is enforced in code.** A deployment that does not implement them has a gatekeeper in front of an erasure right, which is the opposite of what the right requires.
*   **The audit log survives erasure by design**, because a dispute needs it. The interaction between surviving audit records and shredded payloads is not worked through.
*   **Pairwise unlinkability rests on a single root secret.** If it leaks, every pairwise ID becomes retroactively linkable. There is no per-tenant root and no rotation story.
*   **Key custody is single-custodian.** `Kms` has no m-of-n split, and in this repository the root key is in-process rather than in an HSM.
*   **State is in-memory.** The registry, directory, nonce ledger and usage meter are in-process maps. Single-use enforcement across more than one node is an unsolved distributed problem here, not a solved one.
*   **The geographic k-floor depends on a density figure the deployment supplies.** The only implementation shipped is a flat value; see `spec/CFP-v0.x.md` §6a.
*   **Further open problems** — offline double-redemption, carrier-identity binding, forward-leg delegation, vault federation — are listed in `spec/CFP-v0.x.md` §9 and on `web/candid-books.html`, with the same prominence as what is closed.

## 4. What we collect

CFP is a library, not a service — its authors never see, collect, or receive any user
data. Whoever deploys it is responsible for their own data protection and compliance.
