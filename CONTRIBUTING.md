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

Open an issue. This is a pre-v0.1 reference implementation with no production deployment, so there
is no embargo process — file it in the open the same as any other bug.

## Maintainer

Ekumen LLP (Ashwin Natarajan, Karthik) — see [NOTICE](./NOTICE). Named here because a repository a
foundation is asked to help steward needs a name to write to, not an inference to make.
