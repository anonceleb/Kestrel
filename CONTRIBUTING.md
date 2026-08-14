# Contributing to CFP

This repository is a protocol contribution — a spec, a donated invariant suite, and a reference
implementation — not a product. See [NOTICE](./NOTICE) for who maintains it and
[spec/CFP-v0.x.md](./spec/CFP-v0.x.md) §8 for the stewardship commitment this implies.

## Before you open a PR

- `npm run verify` must be green: privacy-lint plus every invariant suite. No exceptions.
- If you're changing anything under `packages/`, read `tools/privacy-lint/lint.ts`'s header first —
  it enforces core purity and purpose-generic vocabulary, and a change that looks fine locally can
  still fail it.
- If you're adding or removing a numbered invariant, update [tests/README.md](./tests/README.md) —
  that file is the disposition table a reviewer checks first when the invariant count changes.
- Run `npm run build:web` if you touch anything under `packages/`, `services/`, `profiles/`, or
  `adapters/` — the browser demo runs the real modules, and a stale `web/assets/js/` is a bug.

## Scope

Read the README's "Scope: where CFP begins" section before proposing anything discovery-,
catalog-, or matching-shaped — that boundary is deliberate, not an oversight, and PRs that cross it
will be declined regardless of quality.

## Reporting a security or privacy issue

See [SECURITY.md](./SECURITY.md). Short version: anything that would let someone read a
confidential attribute, forge or widen a grant, or write to the registry without authority goes
through [GitHub's private vulnerability reporting](https://github.com/anonceleb/Kestrel/security/advisories/new).
Everything else — ordinary bugs, spec questions, disagreements about the threat model — belongs
in a public issue.

This file previously said to open *all* security issues in public. That was wrong even for a
pre-v0.1 reference implementation: the code has no deployment to protect, but a reporter should
still get to choose disclosure timing, and telling them the private channel does not exist takes
that choice away. The documented open problems in SECURITY.md remain public, because they are
already public.

## Conduct

This project follows the [Contributor Covenant 2.1](./CODE_OF_CONDUCT.md), including how to
report and what happens when a report concerns a maintainer.

## Maintainer

Ashwin Kumar Natarajan and Karthik Nagasubramanian, operating as Ekumen
Digital Solutions LLP (incorporation pending) — see [NOTICE](./NOTICE).
Named here because a repository a foundation is asked to help steward
needs a name to write to, not an inference to make.
