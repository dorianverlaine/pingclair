<!--
📌 One theme per pull request. If the title needs an "and", it is probably two
pull requests in a trench coat — and two small ones get reviewed this week,
while one large one gets reviewed "soon".
-->

## 📝 What this changes

<!-- One or two sentences an outsider could follow. Plain-language idea first,
mechanism second. -->

Closes #

## 🤔 Why

<!-- What breaks without it, concretely. "A 20 MB body gets buffered whole and
the box OOMs" lands; "improves memory characteristics" does not.

If anything here looks wrong but is deliberate, this is where you write the
sentence that stops a future reader from helpfully fixing it back. -->

## 🔬 Evidence

<!-- Not a checklist. Paste what you ran and what it printed.

`just ci` passing is the floor. It says nothing broke — it does not say the
thing you claim to have fixed is fixed. What earns trust is the test that goes
red without your change:

  $ cargo +1.97.1 nextest run -p pingclair --test integration my_new_test
  # fix reverted:
  FAIL [ 0.031s] my_new_test
  # fix applied:
  PASS [ 0.028s] my_new_test

Could not write a failing test? Say so, and say why. That is a real answer and
it will not be held against you. A green checkbox that means nothing, on the
other hand, is how a project ends up with 474 tests and a certificate-chain bug
that none of them could physically detect. Ask us how we know. -->

## 🔀 Both transports?

<!-- Delete this section if the change cannot touch request handling.

H1/H2 (`server.rs`) and H3 (`quic.rs`) are separate execution paths, and
"fixed on one protocol only" is the defect this repository has repeated most
enthusiastically. Both arms existing does not mean both arms agree.

  - [ ] Verified on H1/H2
  - [ ] Verified on H3
  - [ ] Parity is not required here, because: ... -->

## 📚 Documentation

<!-- Delete what does not apply.

  - CHANGELOG.md — required if an operator can see this: behaviour, defaults,
    configuration, a fixed bug. Write what they have to *do*, not which
    function you edited.
  - README.md / .zh.md / .fr.md — shipped user-facing behaviour, all three
    together or none.
  - docs/guardrails/*.md — add a rule when this change came out of a failure
    somebody else could repeat. Say what broke, not just what to do.
  - Nothing, because this is internal (refactor, tests, CI). -->

## 🤖 Which AI helped?

<!-- **Using AI here is encouraged, not merely tolerated.** This project is
built with it, and pretending otherwise would be theatre.

The one thing we ask is *which model*, because it calibrates review — the
failure modes of different models are genuinely different, and knowing what
wrote a change tells a reviewer where to look first.

  "None."
  "Claude Opus 5 wrote the tests, I wrote the fix."
  "Written end to end by Claude Opus 5; I reviewed it and ran the suite."
  "GPT-5.2 for the first draft, then rewritten by hand."

Whichever it was, submitting this says you have read the change and believe it
is correct. The model does not get to sign that part. -->

None.
