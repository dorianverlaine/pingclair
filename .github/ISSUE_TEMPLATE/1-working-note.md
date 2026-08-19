---
name: 🔍 Working note
about: Something you noticed and do not want to lose. Certainty optional.
title: "🔍 "
labels: needs-triage
---

<!--
This template is deliberately loose. It exists so that "I noticed something
odd and I am not going to chase it right now" has somewhere to live other
than your memory.

An uncertain note is worth opening. A note you never wrote is worth nothing.
Delete every heading below that you have nothing to say about — a short note
that is honest beats a long one padded to fill a form.
-->

## What I saw

<!-- The observation, in plain language. Name the failure concretely: "a
20 MB body gets buffered whole and the box OOMs" beats "suboptimal memory
characteristics". -->

## How sure I am

<!-- Say it plainly. All three of these are fine:

  - Confirmed: reproduced it, here is the input.
  - Probable: the code reads that way, I have not run it.
  - Suspicion: something felt wrong while I was reading, no evidence yet.

Getting this wrong in the confident direction is the expensive mistake, so
under-claim when you are unsure. -->

## Where it lives

<!-- `file.rs:123`, the directive, the transport. If it might affect H1/H2 and
H3 differently, say which one you actually looked at — they are separate
execution paths and "fixed on one protocol only" is this project's most
repeated defect. -->

## Need to

<!-- The next concrete actions, so the you of three days from now does not
have to reconstruct the thought. -->

- [ ] reproduce
- [ ] ...

<!--
📌 Labels do the classification, so do not write severity or status into the
body — they would go stale exactly the way the old TRIAGE.md file did:

  p0 / p1 / p2         how exposed a user is, not how annoying it is
  h1-h2 / h3 / both    which transport, when it matters
  needs-triage         you have not decided yet (this template sets it)

🔒 If this is a security weakness, close this tab and report it privately
instead: https://github.com/dorianverlaine/pingclair/security/advisories/new
-->
