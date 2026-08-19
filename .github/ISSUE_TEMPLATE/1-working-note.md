---
name: 🔍 Working note
about: Something you noticed and do not want to lose. Certainty optional.
title: "🔍 "
labels: 🔬 needs-triage
---

<!--
This template is deliberately loose. It exists so that "huh, that looks wrong,
and I am absolutely not chasing it right now" has somewhere to live other than
your memory, which — let us be honest — has a retention window of about four
days and no backup.

An uncertain note is worth opening. A note you never wrote is worth nothing.
Delete every heading you have nothing to say about. Nobody has ever been
thanked for padding a form.
-->

## 👀 What I saw

<!-- The observation, in plain language. Be concrete: "a 20 MB body gets
buffered whole and the box OOMs" tells the next reader everything, and
"suboptimal memory characteristics" tells them you own a thesaurus. -->

## 🎚️ How sure I am

<!-- Pick one and say it out loud:

  🟢 Confirmed  — reproduced it, here is the input
  🟡 Probable   — the code reads that way, I have not run it
  🔴 Suspicion  — something felt off while reading, zero evidence

There is no shame in 🔴. There is considerable shame in writing 🟢 and being
wrong, so when in doubt, round down. This project has a whole guardrail file
about the second kind of mistake. -->

## 📍 Where it lives

<!-- `file.rs:123`, the directive, the transport.

If it could affect H1/H2 and H3 differently, say which one you actually looked
at. "Fixed on one protocol only" is this repository's greatest hit — it has
charted more than once. -->

## 🔧 Need to

<!-- The next concrete actions, written for the you of three days from now,
who will remember none of this and will be slightly annoyed at present-you. -->

- [ ] reproduce
- [ ] ...

<!--
🏷️ Labels do the classification, so leave severity and status out of the body.
Written into prose they go stale silently, which is precisely how the file this
tracker replaced ended up lying to us for a fortnight:

  💥 p0 / 🔥 p1 / 🧹 p2    how exposed a user is, not how much it annoyed you
  🔗 h1-h2 / 🛰️ h3         which transport, when only one is affected
  🔬 needs-triage          you have not decided yet (this template sets it)

🔒 If this is a security weakness, close this tab and use the private form
instead: https://github.com/dorianverlaine/pingclair/security/advisories/new
-->
