# Who this is for, and what problem it solves

The rest of this repo is written for a protocol engineer. This page isn't — it's for anyone
trying to figure out if CFP is relevant to them before reading any code.

## The problem, in one paragraph

When you order something online today, your delivery address ends up stored in plaintext —
in the merchant's database, the courier's database, and usually a few systems in between. It
generally stays there indefinitely after the parcel arrives, because nothing forces anyone to
delete it. Your phone number ends up in the same spot wherever a delivery app needs to call
you. Every one of those copies is a place your data could later leak from. CFP is a way to get
a delivery done without creating any of those copies in the first place.

## Who benefits

- **The person receiving the delivery.** Their address or phone number is never handed to the
  merchant or the app at all. If they revoke access, it's actually revoked — not just marked
  deleted in a database someone else still controls.
- **The merchant or platform.** They fulfil the order without ever storing the address or
  number themselves — nothing to secure, nothing to disclose in a breach report, because they
  never held it.
- **The courier or postal operator.** They still get what they need to deliver the parcel or
  make the call, just for that one delivery — not a copy they keep afterward.
- **A network operator or regulator** — an open commerce network like ONDC/Beckn, for
  example. CFP is one answer to how participants in a shared network exchange sensitive
  delivery data without any single participant ending up holding everyone's data.

## A concrete walkthrough

Priya orders a book online. Today, the bookstore stores her address, passes a copy to the
courier, and both usually keep it after delivery.

Under CFP, Priya's address lives in one place: a vault she controls, or that a service
controls on her behalf. When she checks out, the bookstore doesn't get her address — it gets
a capability, a signed token that says "the holder may cause one delivery to this person,
once, within this window," with no address inside it. The bookstore passes that token to the
courier. The courier redeems it against the vault at delivery time: the vault decrypts the
address just long enough to route the parcel, logs that it happened, and the plaintext address
never touches the bookstore's database or the courier's long-term storage. A second delivery
attempt gets a new, narrower token, not a copy of the first. If Priya revokes access, every
future attempt fails immediately, because there's only one vault where that revocation has to
take effect.

The same mechanism works for a phone number instead of an address — a courier app can call
Priya through a masked relay without ever learning her real number.

## What this is not

CFP doesn't help a merchant find a courier, or a customer find a merchant — there's no search
or matching here (see the "Scope" section in [README.md](./README.md)). It starts after an
order already exists and a delivery needs to happen.

It's also not something you install and run as-is. It's a reference implementation and a
protocol spec ([`spec/CFP-v0.x.md`](./spec/CFP-v0.x.md)) meant to be adopted into an existing
commerce network's message flow. [README.md](./README.md) and
[`web/candid-books.html`](./web/candid-books.html) describe what's built and what's still open.

## Try it

The live demo ([kestrel-ebon.vercel.app](https://kestrel-ebon.vercel.app/index.html)) runs
this walkthrough in a browser, using the repo's own code — see `profile-address.html` for the
address flow and `profile-contact.html` for the phone-masking flow. No install, no account, no
network calls beyond loading the page.
