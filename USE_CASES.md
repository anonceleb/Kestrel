# Who this is for, and what problem it solves

The rest of this repository is written for a protocol engineer. This page isn't — it's for
someone deciding whether CFP is relevant to them before they read a line of code.

## The problem, in one paragraph

Right now, if you buy something online, your delivery address sits in plaintext in the
merchant's database, the courier's database, any third-party logistics platform in between,
and every backup and log any of those systems ever take. It stays there indefinitely, long
after the parcel arrives, because nothing forces it to be deleted and no one owns the job of
deleting it. The same is true of your phone number wherever a delivery driver or courier app
needs to reach you. Every one of those copies is a separate place your address or number can
leak from — a breach, an insider, a subpoena, a subprocessor you never agreed to. CFP exists
to remove the copies without removing the delivery.

## Who benefits

- **A subject (the person receiving the parcel or the call).** Their address or phone number
  never has to be handed to a merchant, an app, or a call center at all. Fewer places their
  data lives means fewer places it can leak from — and if they revoke access, that access is
  actually gone, not just marked deleted in a database a merchant still controls.
- **A merchant or platform.** They fulfil the order without ever holding the address or number
  in their own systems — nothing to secure, nothing to leak, nothing to explain in a breach
  notification, because they never had it.
- **A courier or postal operator.** They still get exactly what they need to route and deliver
  the parcel or place the call — just scoped to that one delivery, not a standing copy they
  keep afterward.
- **A regulator or platform operator (e.g. an open commerce network like ONDC/Beckn).** CFP is
  a protocol-level answer to "how do participants exchange sensitive delivery data without one
  of them becoming a honeypot" — relevant to anyone building or governing a network where many
  independent merchants and couriers need to interoperate.

## A concrete walkthrough

Priya orders a book online. Today, the bookstore's system stores her address, hands a copy to
the courier, and both keep it after the parcel arrives — indefinitely, in most systems.

Under CFP: Priya's address lives in exactly one place, a vault she (or a service acting on her
behalf) controls. When she checks out, the bookstore doesn't receive her address — it receives
a **capability**: a token that says "the holder may cause one delivery to this subject, once,
within this time window," signed and scoped, but carrying no address inside it. The bookstore
hands that capability to the courier. The courier redeems it against the vault at the moment of
delivery — the vault decrypts the address just long enough to route the parcel, writes an audit
record of that access, and the plaintext never touches the bookstore's database, the courier's
long-term storage, or any log in between. If the parcel needs a second delivery attempt, a
narrower capability is issued for exactly that — never a wider one. If Priya revokes access,
every future redemption attempt fails immediately, everywhere, because there's only one vault
to revoke it in.

The same mechanism, unmodified, covers a phone number instead of an address — a courier app can
place one call to Priya through a masked relay without ever learning her real number.

## What this is *not*

CFP does not help a merchant find a courier, or a customer find a merchant — there's no search,
catalog, or matching logic here (see the "Scope" section in [README.md](./README.md)). It
begins after an order already exists and a delivery needs to happen. It's infrastructure for
the moment data changes hands, not a marketplace.

It's also not a finished product you install — it's a reference implementation and a protocol
specification ([`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md)) meant to be adopted into an existing
commerce network's message flow, the way the design document
([`README.md`](./README.md)) and gap ledger ([`web/candid-books.html`](./web/candid-books.html))
describe — including what's still open, not just what's closed.

## Try it

The live demo ([kestrel-ebon.vercel.app](https://kestrel-ebon.vercel.app/index.html)) runs this
exact walkthrough in a browser, against the repository's own code — see `profile-address.html`
for the address flow and `profile-contact.html` for the phone-masking flow. No install, no
account, no network calls beyond loading the page itself.
