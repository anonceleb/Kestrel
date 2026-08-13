# Privacy & Regulatory Compliance (Kestrel)

Kestrel (Confidential Fulfilment Profile) lets an action happen against a sensitive
attribute — an address, a phone number — without ever exposing or transmitting the attribute
itself.

## 1. Privacy by Design

Kestrel doesn't retain or centrally collect personal data. Here's how:

*   **It runs offline.** Everything executes client-side or in-process — no cloud database, no required network calls.
*   **Attributes stay encrypted.** They're stored only inside the Vault. The Platform, which coordinates the actual transaction, only ever handles opaque tokens — never the real data.
*   **Each merchant sees a different ID for the same person.** IDs are derived so that two merchants can't compare notes and figure out they're dealing with the same subject.
*   **Deleting someone's data means destroying their encryption key**, not searching every backup for their record. Once the key's gone, the data is permanently unreadable — that's crypto-shredding, and it's how the right to erasure is implemented.
*   **Every stored record is encrypted** with ChaCha20-Poly1305 and tied to its own tenant and record ID, so a ciphertext can't be copied and replayed somewhere else.

## 2. How This Maps to Privacy Law

Kestrel's design lines up with a few major privacy regimes:

| Regulation | How Kestrel meets it |
|---|---|
| **GDPR (EU)** | Data minimization (Art 5(1)(c)) is built in. Right to erasure (Art 17) works via crypto-shredding. Data security (Art 32) is met with authenticated encryption (ChaCha20-Poly1305). |
| **DPDP Act (India, 2023)** | Purpose limitation and consent tracking are enforced — the Consent Ledger records exactly which policy authorized each grant, so consent can be audited or revoked at any time. |
| **IT Act (India, 2000)** | Meets Section 43A's reasonable-security-practices requirement through standard key derivation, digital signatures, and access logs. |

## 3. What We Collect

Kestrel is a library, not a service — we (its authors) never see, collect, or receive any
user data. Whoever deploys it is responsible for their own data protection and compliance.
