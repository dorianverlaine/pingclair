# ⚠️ Pingclair implementation guardrails

> Read this **before** you change code or run a verification pass. Everything
> recorded here is a hole somebody already fell into, not theoretical advice —
> every single rule has one real failure standing behind it.
>
> This file is only an index. The content is split by subsystem into four
> documents; read the one or two that touch what you are changing. Split on
> 2026-08-05, moved across verbatim — not one rule was reworded or dropped.

| Document | Covers |
| --- | --- |
| [`guardrails/testing.md`](guardrails/testing.md) | Test and debug environment, ghost processes, the local toolchain and proxy, CI workflows, and where verification evidence is allowed to live |
| [`guardrails/config.md`](guardrails/config.md) | **Which layer validation belongs in** (a rule that lives in the adapter is a rule the Admin API walks straight past), failing closed on settings that cannot be honoured, defects in the measuring tools themselves, and why "it compiled" is not "it compiled correctly" |
| [`guardrails/tls.md`](guardrails/tls.md) | Dependencies and linking (one BoringSSL for the whole tree, what `[patch.crates-io]` does to the audit) and secure defaults (fail closed, masking, certificates and trust material) |
| [`guardrails/proxy.md`](guardrails/proxy.md) | Why HTTP/3 is pinned to quiche/BoringSSL, the architecture and correctness rules for `quic.rs`, and streaming and memory |

- What to work on next → `docs/TODO.md` (🔒 maintainer-local, not in the repository)
- Newly found problems that should not be fixed right now → `TRIAGE.md` (repository root)
- Finished work and verification evidence → local `benchmarks/results/` (never committed)

> 📌 When you add a rule, write it into the subsystem document it belongs to,
> not back into this index. The moment the index grows content of its own it
> becomes a fifth document to keep in sync.
