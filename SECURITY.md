# Security policy

## Status of this code

CFP is a **pre-v0.1 reference implementation with no production deployment**. It is a protocol
contribution — a spec, a donated invariant suite, and code that demonstrates them — not a
supported product. There is no release train, no supported-versions matrix, and no patch SLA,
because there is nothing deployed to patch.

That is also why the known-weakness list below is public rather than embargoed.

## Reporting a vulnerability

**Use GitHub's private vulnerability reporting:**
[Report a vulnerability](https://github.com/anonceleb/Kestrel/security/advisories/new)
(repository → **Security** → **Advisories** → **Report a vulnerability**).

That channel is private between you and the maintainers until an advisory is published, and it
needs no email address from either side. Please use it for anything that would let someone:

- read a confidential attribute without a valid grant, or outside `Vault.resolve`;
- redeem, widen, or forge a grant they were not issued;
- write to the registry, or erase records, without a valid facilitator credential;
- correlate a subject across counterparties;
- decrypt a record after `erase()`.

We will acknowledge a report and say whether we agree it is a vulnerability. Being a
two-person project with no deployment, we cannot promise a fix window — we can promise a
straight answer, and that anything confirmed goes onto `web/candid-books.html` whether or not
it is fixed.

**Everything else — bugs, spec questions, disagreements about the threat model — belongs in a
public issue.** See [CONTRIBUTING.md](./CONTRIBUTING.md).

## Already known, please don't re-report

These are documented open problems, not undiscovered bugs. They are listed in
[`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md) §9 and on
[`web/candid-books.html`](./web/candid-books.html) with the same prominence as what is closed:

- **Offline double-redemption.** An offline label check cannot know the underlying grant was
  already burned online.
- **No carrier-identity binding.** Nothing cryptographically binds a grant to the operative
  redeeming it; there is no proof-of-possession. Redemption *is* bound to the actor named in
  the consent entry, which is a subscriber-level check, not a cryptographic one.
- **Single-custodian vault keys.** `Kms` has no m-of-n split, and the root key is in-process.
- **Root-secret compromise linearises pairwise IDs.** One secret, no per-tenant root, no
  rotation story.
- **Caveats are not enforced at redemption.** `Vault.resolve` does not check `maxUnits`,
  `channelKind` or `fulfiller`, a suspended participant can still redeem, and `singleUse:
  false` is burned anyway.
- **In-memory state everywhere.** Registry, directory, nonce ledger and usage meter are
  in-process maps; single-use across more than one node is unsolved here.
- **The erasure gate's counter-constraints are specification-only** (`spec/CFP-v0.x.md` §7.3).

A report that a *documented* weakness is worse than we describe, or is reachable by a path we
did not anticipate, is very welcome — that is new information.

## Scope

In scope: everything under `packages/`, `services/`, `adapters/`, `profiles/`, `tools/`, and
the generated modules under `web/assets/js/`.

Out of scope: the hosting of the demo site itself, and anything requiring a compromised
developer machine or a malicious dependency (there are no runtime dependencies).
