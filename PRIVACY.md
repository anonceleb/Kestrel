# Privacy & Regulatory Compliance (Kestrel)

Kestrel (Confidential Fulfilment Profile) is a privacy-first, capability-based digital credential system designed to enable confidential actions against sensitive attributes (e.g., address, phone numbers) without exposing or transmitting the underlying data.

## 1. Privacy by Design Posture

Kestrel enforces **zero data retention and zero central collection** of Personally Identifiable Information (PII). It operates on the following architectural principles:

*   **Offline Execution**: The library executes entirely client-side or in-process (runs offline, no cloud database, no network calls required).
*   **Data Minimization**: Attributes are stored as encrypted ciphertexts inside the Vault (Zone 1). The Platform (Zone 2) only coordinates transactions using non-PII capability tokens.
*   **Pseudonymization (Pairwise IDs)**: Kestrel generates a unique, deterministic, non-correlatable identifier for each merchant-subject pair using HKDF and HMAC. Two different counterparties cannot link or join their records to identify a shared subject.
*   **Crypto-Shredding (Right to Erasure)**: Deletion is accomplished by destroying the HKDF record keys. The encrypted data becomes mathematically unrecoverable, fulfilling the right to be forgotten without complex database refactoring or backup-purging issues.
*   **Authenticated Encryption (AEAD)**: Stored ciphertexts are sealed with ChaCha20-Poly1305 and bound to additional authenticated data (AAD) consisting of `tenant_id` and `record_id` to prevent ciphertext relocation attacks.

## 2. Regulatory Compliance Mapping

Kestrel is designed to help integrators comply with strict global data privacy regulations:

| Regulation | Compliance Mechanism |
|---|---|
| **GDPR (EU)** | Enforces **Data Minimization** (Art 5(1)(c)) by design. Fulfills the **Right to Erasure** (Art 17) via instant crypto-shredding. Complies with **Data Security** (Art 32) using authenticated symmetric encryption (ChaCha20-Poly1305). |
| **Digital Personal Data Protection (DPDP) Act (India, 2023)** | Enforces purpose limitation and strict consent tracking. The Consent Ledger records the exact policy hash that authorized a grant, making consent audits verifiable and revocable at any time. |
| **Information Technology Act (India, 2000)** | Follows Section 43A guidelines for **Reasonable Security Practices and Procedures (RSPP)** by implementing secure, standardized key derivation, digital signatures, and access logs. |

## 3. Data Collection Policy
As a decentralized open-source library, Kestrel **does not collect, store, or transmit** any user data to its authors, maintainers, or any third party. The responsibility for data protection and operational compliance rests with the entities deploying Kestrel instances.
