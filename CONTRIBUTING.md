# Contributing to Pingclair

Thanks for considering a contribution. Pingclair is a web server — the kind of
software that fails at 3am in someone else's production, so the bar here is
about **evidence**, not volume. A small change with a test that would have
caught the bug is worth more than a large one without.

---

## ⚖️ Before your first pull request

Pingclair requires a signed [Contributor License Agreement](CLA.md). It is a
one-time step and it covers every future contribution you make.

To sign, comment on your first pull request with exactly:

```
I have read the CLA document and I hereby sign the CLA.
```

**What you are agreeing to, in plain terms:** you keep the copyright to your
work. You grant the project a broad, irrevocable license to use it —
including the right to distribute it under different license terms in the
future. That last point is the reason the CLA exists: Pingclair is currently
Apache-2.0, and without it a future license change would require tracking down
every contributor for permission.

If that is not acceptable to you, that is a legitimate position. Open an issue
describing the change instead — a well-written bug report with a reproduction
is a real contribution and needs no agreement.

---

## 🗂️ How work is tracked

**Issues are the queue. Pull requests close them. Nothing else is a to-do
list.**

This replaced a maintainer-local plan file in August 2026. The reasons are
worth stating, because they shaped the templates. That file went stale between
sittings. The same problem quietly accumulated three descriptions in three
documents, all subtly disagreeing. And by the time anyone returned to an item,
the thinking behind it had to be excavated rather than read.

An issue fixes all three by construction: one canonical location, a state that
changes when a pull request merges rather than when somebody remembers, and a
comment thread that *is* the record of what you were thinking. The bar for
"better than a text file I have to update by hand" was, in fairness, not high.

### Opening one

Three templates, and none of them is mandatory — blank issues stay enabled.

| Template | For |
|---|---|
| 🔍 **Working note** | Something you noticed and do not want to lose. **Certainty is optional** — "this looks wrong, I have not checked" is a legitimate issue. |
| 🐛 **Bug report** | Pingclair did something other than what it said it would. Wants a reproduction and the smallest Pingclairfile that shows it. |
| 🧩 **Compatibility gap** | A Caddyfile that works with Caddy and does not work here. That is a defect on our side; you do not have to argue for it. |

The working note deserves a word, because most projects have nothing like it.
A suspicion you never wrote down is worth nothing, and a form demanding
reproduction steps guarantees it never gets written — so the suspicion dies in
somebody's short-term memory, which is where good bugs go to retire.

That template therefore asks for three things: the observation, **how sure you
are**, and what would settle it. "How sure" is its own field on purpose, with
three legitimate answers (🟢 confirmed, 🟡 probable, 🔴 pure suspicion). Round
down when in doubt. Confident prose over shaky evidence is the failure mode
this project guards against hardest, and a form field is harder to bluff than a
paragraph.

### Labels

Labels carry the classification so the body does not have to. A severity buried
in prose goes stale the instant it changes and nobody notices for a fortnight;
a label is visible in the list view, filterable, and awkward to ignore.

| Label | Meaning |
|---|---|
| 💥 `p0` | Data loss, a remotely triggerable crash, or a security defect. Interrupts whatever is in progress. |
| 🔥 `p1` | Wrong behaviour a user can reach. |
| 🧹 `p2` | Everything else: cleanups, missing coverage, papercuts, drifted documentation. |
| 🔬 `needs-triage` | Not yet classified. Both issue templates set it. |
| 🐛 `bug` · 🧩 `compatibility` · ✨ `enhancement` · 📚 `documentation` | What kind of thing it is. |
| 🔗 `h1-h2` · 🛰️ `h3` | Which transport, when only one is affected. |
| ⏳ `blocked-upstream` | Waiting on a dependency. The body names the upstream issue and what unblocks it. |
| 🚫 `wontfix` | Investigated, understood, deliberately not changing. **The body says why.** |

The emoji is part of the name, not decoration on top of it — the templates
reference these strings exactly, so `p0` alone will not match `💥 p0`. It earns
its place in the list view, where a wall of same-shaped text is exactly as
scannable as it sounds, and the severity you are hunting for is a glance rather
than a read.

Severity is about the user's exposure, not about how annoying the problem is
to whoever found it. The two correlate less often than you would hope.

📌 The labels and the board are created by `scripts/setup-tracker.sh`, which is
idempotent and treats this document as the source of truth. Change the scheme
here, run the script, and the repository catches up — rather than the scheme
living half in a document and half in somebody's browser tab, which is roughly
the arrangement this tracker exists to escape.

`wontfix` is not a bin. A closed issue that records "we checked, this differs
from Caddy, here is why we are keeping our behaviour" is one of the more
valuable things in the tracker — it stops the same question being reopened in
six months, and it stops somebody "fixing" a deliberate difference back.

### 📊 The board

Issues also live on a [project board](https://github.com/users/dorianverlaine/projects/1),
because a flat list of open issues answers "what exists" and never answers
"what is actually moving".

```text
📥 Inbox  →  🔬 Triage  →  📋 Ready  →  🔧 In Progress  →  👀 Review  →  ✅ Done
```

| Column | What it means | What gets it out |
|---|---|---|
| 📥 **Inbox** | Newly opened, nobody has looked yet. Everything lands here. | Somebody reads it. |
| 🔬 **Triage** | Being assessed: is it real, how exposed is a user, which transport? | A severity label, or a close with a reason. |
| 📋 **Ready** | Understood well enough that someone could start without asking a question first. | Somebody starts. |
| 🔧 **In Progress** | Actively being worked on. **Say so in the issue** so two people do not write the same patch. | A pull request opens. |
| 👀 **Review** | Pull request open, waiting on review or CI. | Merge, or back to 🔧. |
| ✅ **Done** | Merged, or closed with a recorded reason. | Nothing. It rests. |

Two rules keep this from becoming decoration:

**📋 Ready is a promise, not a wish.** An issue in Ready means the next person
can pick it up cold. If it still needs a decision, a measurement, or a "let me
check what Caddy does first", it belongs in 🔬 Triage, however keen everyone is
about it.

**🔧 In Progress has a small ceiling.** Work in progress is work not shipped,
and six half-finished branches are strictly worse than two finished ones. If
the column is filling up, the honest move is to move something back rather
than to widen the column.

📌 `✅ Done` here means the same thing `✅` means everywhere else in this
repository: **finished, with something to point at.** It is not a synonym for
"good", "agreed", or "probably fine". That marker has exactly one meaning here,
and it got that rule the hard way — a sweep once counted `✅` characters to
decide which tracking documents were still current, concluded a 43-of-46
complete document had been abandoned, and was confidently wrong about all of
it.

### Working on one

Say so in the issue before you start, so two people do not write the same
patch. For anything substantial, describe the approach there first — five
minutes of that can save a weekend, especially around TLS, HTTP/3 or the
configuration grammar, where the constraints are not obvious from the code.

Put `Closes #123` in the pull request body. That is what makes the queue
self-maintaining: the issue closes on merge, and nobody has to remember.

### What issues are not for

- **Security weaknesses.** Report privately, see below.
- **Verification status.** Whether a claim has evidence behind it is a
  cross-cutting map, not a work item, and it stays in its own ledger.
- **Rules.** A constraint that will still be true after every open issue is
  closed belongs in `docs/guardrails/`, not in the tracker.

---

## 🚦 The gate

Every commit on `main` passes the full CI gate. The canonical local command
is the same one CI runs, pinned to Rust 1.97:

```bash
just ci
```

That recipe runs formatting, Clippy, `cargo-shear`, repository invariant
checks, documentation linting, the full `nextest` suite, and a benchmark
smoke run. The individual recipes (`just fmt-check`, `just clippy`,
`just test`, ...) are available when only one half is needed.

CI is split into two layers: `blocking-ci.yml` is the fast pre-merge gate
with a single required status, and `postmerge-ci.yml` runs the heavy
verification (sharded nextest, release-profile Clippy, HTTP/3) after `main`
changes. See `.github/workflows/README.md` for the full workflow map.

Warnings are errors. **Never silence one with a broad `allow` attribute** — if
a lint is wrong for a specific line, scope the `allow` to that line and say why
in a comment.

---

## 🧪 What counts as tested

Unit tests are the floor, not the ceiling. For anything that touches the
request path, the question reviewers will ask is *"what does this do to a 20 MB
body?"*

- **Behavior that only appears end-to-end needs a real binary.** Protocol
  negotiation, TLS, streaming and shutdown behavior are not adequately covered
  by unit tests. Build the binary, run it, capture the output.
- **Anything touching a response body must prove bounded memory.** Assert it in
  a test rather than describing it in a comment — a test survives refactoring,
  a comment does not. See `pingclair-proxy/src/encoding.rs` for the pattern.
- **A regression fix needs a test that fails without the fix.** Write the test
  first and watch it fail; a test that passes both ways proves nothing.
- **Preserve failing evidence.** Verification output goes in
  `benchmarks/results/<date>_<commit-prefix>/` — kept locally, never committed
  to the repository. When something is fixed, add a new directory — never
  overwrite the record of the failure.

`docs/guardrails/testing.md` lists environment traps that have already cost
someone a debugging session (a local proxy that intercepts test requests, ghost
processes after a timeout, compression tests that fail for the wrong reason).
Read it before writing test infrastructure.

---

## 🏗️ Architecture constraints

These are not style preferences. Violating them has broken the server before.

- **BoringSSL is load-bearing.** `quiche`, `boring` and Pingora's `boringssl`
  feature are one linking design. Introducing `openssl-sys`, `pingora-openssl`
  or reqwest's `native-tls` causes symbol conflicts that have produced startup
  SIGBUS and Linux link errors. Do not add them, including as dev-dependencies.
- **HTTP/3 is not a Pingora `Session`.** It is a raw tokio/quiche path in
  `pingclair-proxy/src/quic.rs`. Logic that must behave identically across
  protocols belongs in transport-neutral code (see `http_policy.rs`), not
  duplicated into the H3 loop.
- **No full-body buffering, anywhere.** Streaming, bounded channels and flow
  control are requirements, not optimizations.
- **Misconfiguration fails closed.** Reject it loudly at startup rather than
  silently ignoring it and serving something the operator did not ask for.

`AGENTS.md` has the full set.

---

## 📝 Style

- **Comments and doc comments in English**, written as complete sentences that
  explain *intent or constraint* rather than restating the code. If a line
  looks wrong but is deliberate, the comment saying why is the valuable part.
- **Each comment carries a semantically appropriate emoji.** License headers,
  shebangs and machine-required directives are exempt. This is a house
  convention; match the surrounding files.
- **Commit subjects: emoji, then a conventional imperative summary.**
  For example `✨ feat(proxy): add weighted backup pools` or
  `🐛 fix(test): reap stale integration children`.
- **Chinese documentation uses Traditional Chinese, Taiwan terminology.**
- `git diff --check` must pass.

---

## 📚 Where things are documented

Update the narrowest source of truth, plus anything that would otherwise become
misleading.

| File | Owns |
|---|---|
| GitHub issues | Everything outstanding: the plan, known defects, compatibility gaps. One item, one issue, one place. |
| Milestones | Which release an issue is meant for. A milestone with no due date is a bucket, not a promise. |
| `docs/guardrails/{testing,config,tls,proxy}.md` | Environment constraints and implementation rules, one file per subsystem. `docs/GUARDRAILS.md` indexes them. |
| `benchmarks/README.md` | Performance claims, methodology, bugs found under load. Raw per-run evidence stays local under `benchmarks/results/`, never committed. |
| `README.md` / `.zh.md` / `.fr.md` | **Shipped** user-facing behavior only — update all three together. |
| `CHANGELOG.md` | What changed between releases, from the point of view of someone upgrading. |

If your change is visible to someone running Pingclair — behavior, defaults,
configuration, a fixed bug — add a line to the `[Unreleased]` section of
`CHANGELOG.md` in the same commit. Write what an operator has to *do* about
it, not which function you edited; if the answer is "nothing", it probably
belongs in the commit message instead. Purely internal work (refactors, test
scaffolding, CI) does not need an entry.

The reason it goes in the same commit is arithmetic: `v0.1.7` was tagged and
then 173 commits landed before anyone wrote a changelog, and reconstructing
them afterwards meant reading every subject line and checking half of them
against the code. Two of those checks turned up claims that were simply wrong.
An entry written while the change is fresh costs a minute.

Never move an item to "verified" without leaving enough evidence for someone
else to reproduce the claim.

---

## 🤖 AI assistance

**Use it. We do.** This project is built with AI assistance and saying
otherwise would be theatre — the commit history has the trailers to prove it.
There is no penalty here for having had help, and no bonus points for
artisanal, hand-forged, single-origin code.

The one thing we ask is that you **name the model**. Both issue templates and
the pull request template have a field for it.

```text
None.
Claude Opus 5 wrote the tests, I wrote the fix.
Written end to end by Claude Opus 5; I reviewed it and ran the suite.
GPT-5.2 for the first draft, then rewritten by hand.
```

Why the model and not just "yes, AI": because it changes where a reviewer
looks first. Different models fail in genuinely different ways, and knowing
which one produced a change is a real prior — the same way "written at 3am by
someone who had been debugging for nine hours" would be, if people declared
that. A change that a model wrote end to end gets read differently from one
where it only wrote the tests. Neither gets read *worse*; they get read
*differently*, which is the entire point.

📌 A model can write the change. It cannot sign for it. Submitting a pull
request says **you** have read it and believe it is correct — including the
parts that look plausible and confident, which is exactly the failure mode
worth watching for. Confident prose over shaky evidence is the thing this
repository guards against hardest, and language models are extremely good at
confident prose.

---

## 🔒 Security issues

Do not open a public issue for a vulnerability. Report it privately through
GitHub's [security advisory](https://github.com/dorianverlaine/pingclair/security/advisories/new)
form so a fix can ship before the details are public.

---

## 💬 Not sure it will be accepted?

Open an issue first and say what you want to change. That costs you five
minutes and can save you a weekend — especially for anything touching TLS,
HTTP/3 or the config grammar, where the constraints are not always obvious from
the code alone.
