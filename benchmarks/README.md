# Pingclair benchmarks

No benchmark results are published in this repository; all historical data
was cleared on 2026-08-03.

The reusable measurement harness lives in `benchmarks/aws-h3/`. Per-run
evidence is kept only in the local `benchmarks/results/` directory, which is
not committed.

## 📏 What has to be true before a number counts

Three rules, and every one of them exists because the harness produced a
*successful-looking wrong number* that was caught afterwards by reading the
output rather than by anything refusing to record it.

**1. The machine has to be idle.** A background compile made every round of one
re-baseline monotonically worse — proxy H2 went 53,836 → 39,447 → 36,172 rps —
and nothing in the table said the machine was busy. `require_quiet_machine` in
`scripts/lib.sh` now refuses to start when the load average is above 30% of the
core count. Override it with `BENCH_ALLOW_BUSY=1` when the other load is known
and wanted, so it becomes a decision rather than an accident.

**2. Every row prints its success count, and a row that did not fully succeed is
voided.** `h2load -H "host: …"` cannot set an HTTP/1.1 `Host` — that comes from
the URL authority — so a virtual-host mismatch turned all 30,000 requests into
4xx. The comparison point has no virtual hosts and answered 200. The table
showed us winning by four times, and both sides were measuring the cost of a
404. The harness now voids such a row and renames its file to `*.VOID.txt`; a
voided file must never be quoted.

**3. A cross-machine comparison is only valid between two runs that differ in
nothing but the machine — and the cipher counts.** Concurrency, client threads
and container CPU limits all varied between two hosts once and the difference
was read as a generational effect. On a CPU without AES-NI the two servers also
negotiated *different* ciphers — Pingclair on BoringSSL got
`TLS_CHACHA20_POLY1305_SHA256`, the comparison point on OpenSSL got
`TLS_AES_256_GCM_SHA384` — which are very different amounts of work without
hardware AES. That is not a fair comparison in either direction: neither "we lost
anyway" nor "we won fairly" can be claimed until both sides are pinned.

The TLS half of rule 3 is now enforced. `BENCH_TLS13_CIPHER` (default
`TLS_CHACHA20_POLY1305_SHA256`, chosen because it is fast in software on every
machine) is passed to the client, and `assert_cipher_pinned` voids any row whose
handshake did not actually use it — pinning alone is not enough, because a client
that ignored the flag would produce an ordinary-looking number.

⚠️ **Any TLS ratio measured on a machine without AES-NI before this was in place
is not quotable.** The suite was uncontrolled, so those numbers answer a question
nobody asked. They need re-measuring on that hardware, which is the one part of
these three rules a script cannot do for you.

The rest of rule 3 — matching concurrency, client threads and CPU limits — cannot
be enforced by a script either, and is why this section exists.
