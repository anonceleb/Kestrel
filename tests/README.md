# Invariant numbering — CFP vs. the base repository

The base repository's invariant suite is contiguous, INV-1…28, across 70 tests. CFP carries **31
distinct numbered invariants across INV-1…37, in 75 tests** (`npm run verify`, 2026-08-14). The
gaps are INV-17, 20, 21, 22, 26 and 28 — dispositioned below.
**These are not the same suite and the counts are not in tension** — CFP re-based the mechanism
suite for a purpose-generic core, added new invariants for the gaps that re-basing closed
(INV-27, INV-29…37), and re-cut some of the base repo's coverage into unnumbered tests or out of
demo scope entirely. Publish this sentence wherever the counts are cited, so a reader never has
to reconcile two different numbers themselves.

Numbers added after the original re-base: **INV-36** (no emitted geo bucket denotes a cell below
the k-floor), **INV-37** (a rejected redemption never burns the grant), **INV-4b** (Vault exposes
no decryption path outside `resolve()`), and **INV-29c** (a facilitator credential is bound to the
exact operation it authorizes).

Eleven base-repo invariant numbers originally did not appear in CFP: INV-15, 17, 19, 20, 21, 22,
23, 24, 25, 26, 28. Five have since been **restored** (INV-15, 19, 23, 24, 25); six remain carried
un-numbered or out of scope. This file is the disposition for each of the original eleven, so a
reviewer who diffs the two repos finds the answer already written rather than has to reconstruct
it.

| Dropped | What it asserted in the base repo | Disposition |
|---|---|---|
| INV-15 | Failed delivery notifies the consumer, never the merchant. | **Restored below**, as INV-15. `Vault.notifyFailedDelivery` had no caller, no test, and no numbered invariant — the property was genuinely unasserted, not merely renumbered. |
| INV-17 | Redirect issues a fresh capability *without telling the merchant the destination changed*. | Carried un-numbered at `tests/grant-core/exceptions.test.ts` ("a redirect changes only channelKind — units and expiry are carried over unchanged"). The non-disclosure half is the same test's assertion that only `channelKind` changes; nothing else is exposed to the merchant to change. |
| INV-19 | The policy hash that gated a decision is recorded on its consent entry, byte-identical; a past decision replays against the policy in force. | **Restored below**, as INV-19. `policyHash` was written at grant time and read back nowhere — an unasserted claim the code's own docstring made. |
| INV-20 | Async settlement: callback exactly once, bad signature rejected synchronously. | Carried un-numbered as `[A10]` in `tests/grant-core/commerce.test.ts`. |
| INV-21 | `MerchantClient.checkout()` (here, `FulfilmentClient.requestGrantSync()`) returns exactly the curated shape, no PII-shaped field. | **Out of demo scope.** `packages/sdk` has zero tests. It is protected structurally by the privacy-lint's Zone-3 shape check (`GrantResult`) but that check asserts shape, not behavior. Flagged, not silently dropped: `packages/sdk` ships in the browser bundle untested. |
| INV-22 | Metering / `QuotaExceeded`. | Carried un-numbered in `tests/grant-core/commerce.test.ts` ("metering: a participant over quota is rejected before minting runs"). |
| INV-23 | The capability MAC covers `id`; a swapped id invalidates the signature. | **Restored below**, as INV-23. Implemented at `packages/capability/src/capability.ts`, previously asserted nowhere — the classic capability-forgery bug class. |
| INV-24 | `createReturn` **and** `refund` refuse a `subjectRef` that isn't the consent's subject. | **Half restored.** Return ownership is carried un-numbered ("returns are ownership-checked: a stranger subjectRef cannot self-mint a return"). The refund half is **restored below as INV-24** — the check existed in code and was unasserted. |
| INV-25 | The active policy cannot be mutated through the reference `active()` returns. | **Restored below**, as INV-25. `Object.freeze` is applied in `packages/policy/src/policy.ts`, previously unasserted. |
| INV-26 | One transaction's failure doesn't drop unrelated pending transactions. | Carried un-numbered as `[A10]` in `tests/grant-core/commerce.test.ts`. |
| INV-28 | Webhook signature round-trip, real HTTP delivery, bounded retry, exhaustion. | Carried un-numbered in `tests/grant-core/commerce.test.ts` ("webhooks: HMAC-signed, real fetch() delivery with bounded retry"). |

**The honest summary, not "plumbing":** six of the eleven survive as unnumbered tests or were
scoped out with the SDK. Five were genuinely unasserted properties, not renumbering artifacts — one
of them (INV-19) unasserts a claim the code's own docstring makes, and one (INV-15) guards the
least-built path in the repository. All five are restored below with their original base-repo
numbers, in `tests/grant-core/exceptions.test.ts` (INV-15, INV-24) and
`tests/grant-core/gap-fixes.test.ts` (INV-19, INV-23, INV-25).

`packages/sdk` remains genuinely untested. That is stated here and on `web/candid-books.html`
rather than left for a reviewer to discover.
