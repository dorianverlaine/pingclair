# ⚠️ Pingclair implementation guardrails

> Read this **before** you change code or run a verification pass. Everything
> recorded here is a hole somebody already fell into, not theoretical advice —
> every single rule has one real failure standing behind it.
>
> This file is only an index. The content is split by subsystem into the
> documents below; read the one or two that touch what you are changing. Split on
> 2026-08-05, moved across verbatim — not one rule was reworded or dropped.
> `guardrails/logging.md` was added on 2026-10-06, when it turned out that the
> measured cost of access logging lived only in commit bodies, and
> `guardrails/native-config.md` on 2026-10-09, when the 0.3 native language
> outgrew the README paragraph that introduced it.

| Document | Covers |
| --- | --- |
| [`guardrails/testing.md`](guardrails/testing.md) | Test and debug environment, ghost processes, the local toolchain and proxy, CI workflows, and where verification evidence is allowed to live |
| [`guardrails/config.md`](guardrails/config.md) | **Which layer validation belongs in** (a rule that lives in the adapter is a rule the Admin API walks straight past), failing closed on settings that cannot be honoured, the secure defaults that are configuration rules (`#[serde(untagged)]` recursion, masking secrets), defects in the measuring tools themselves, and why "it compiled" is not "it compiled correctly" |
| [`guardrails/native-config.md`](guardrails/native-config.md) | The native language's shape: how a file is selected, the one-spelling rule, L4 and L7 composition (writing order is execution order), file-level declarations and what may override them, bindings and `@Secret`, and the parse and expansion bounds |
| [`guardrails/tls.md`](guardrails/tls.md) | Dependencies and linking (one BoringSSL for the whole tree, what `[patch.crates-io]` does to the audit) and the trust-material secure defaults (certificates, downgrade switches, forwarded-header forgery) |
| [`guardrails/layer4.md`](guardrails/layer4.md) | L4 ownership, runtime gating, and where the reference readings behind those semantics live |
| [`guardrails/proxy.md`](guardrails/proxy.md) | Why HTTP/3 is pinned to quiche/BoringSSL, the architecture and correctness rules for `quic.rs`, and streaming and memory |
| [`guardrails/logging.md`](guardrails/logging.md) | Where the cost of a log record actually is (the formatter, not the sink), the invariants in the writer and the formatter that each stand behind a measured regression, the list of things that must never be done to the logging path, and how to measure a logging change so it cannot be mistaken for a win |

- What to work on next → [GitHub issues](https://github.com/dorianverlaine/pingclair/issues)
- Newly found problems that should not be fixed right now → an issue, using the
  🔍 working-note template, which accepts "I am not sure this is real yet"
- Finished work and verification evidence → local `benchmarks/results/` (never committed)

> 📌 When you add a rule, write it into the subsystem document it belongs to,
> not back into this index. The moment the index grows content of its own it
> becomes a fifth document to keep in sync.
