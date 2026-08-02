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

## 🚦 The gate

Every commit on `main` passes all four. CI runs them on Rust 1.97; run them
locally before pushing so you find failures faster than the runner does.

```bash
cargo +1.97.1 fmt --all -- --check
```

```bash
cargo +1.97.1 clippy --locked --workspace --all-targets -- -D warnings
```

```bash
cargo +1.97.1 build --locked --workspace
```

```bash
cargo +1.97.1 test --locked --workspace
```

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

`docs/GUARDRAILS.md` lists environment traps that have already cost someone a
debugging session (a local proxy that intercepts test requests, ghost processes
after a timeout, compression tests that fail for the wrong reason). Read it
before writing test infrastructure.

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
| `docs/TODO.md` | The v0.2.0 execution plan, day by day. 🔒 Maintainer-local, not in this repository — it lists unfixed weaknesses, and publishing that queue would just hand out a target list. Ask if you need the current plan. |
| `docs/GUARDRAILS.md` | Environment constraints and implementation rules. |
| `benchmarks/README.md` | Performance claims, methodology, bugs found under load. Raw per-run evidence stays local under `benchmarks/results/`, never committed. |
| `README.md` / `.zh.md` / `.fr.md` | **Shipped** user-facing behavior only — update all three together. |

Never move an item to "verified" without leaving enough evidence for someone
else to reproduce the claim.

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
