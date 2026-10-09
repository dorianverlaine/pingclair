# Pingclair benchmarks

No benchmark results are published in this repository; all historical data
was cleared on 2026-08-03.

The reusable measurement harness lives in `benchmarks/aws-h3/`. Per-run
evidence is kept only in the local `benchmarks/results/` directory, which is
not committed.

## 🔌 L4 address selection and resource bounds

`just bench -- dns::benchmarks` compares the private production static single-address
path with dynamic one- and four-address snapshots, using one, four and eight
concurrent workers. Pools and per-worker timer drivers are initialized outside
timing. Each iteration includes timer-context entry, snapshot/deadline/cursor work
and an immediately ready injected dial; it performs no DNS or socket I/O.
Divan's allocator profiler measures timed allocations. These results describe
source selection overhead, not whole-server throughput or network latency.

On an idle Linux host, supply a freshly built release binary to the resource drill:

```bash
just l4-resources --binary /path/to/release/pingclair --commit FULL_COMMIT_SHA \
    --results /tmp/l4-resource-run --sessions 128 --reloads 64 --tls
```

The drill holds two listeners' quotas across route reloads, checks excess admission,
and retires controlled pending DNS TCP work while streams remain connected.
It records RSS, descriptors, sessions, queries and peak DNS TCP concurrency,
then checks that sessions and DNS sockets drain and descriptors return near baseline.
`--tls` sends a complete ClientHello before forwarding; without it, routes use
plain TCP. All endpoints are unique localhost ports and cleanup targets only
the child created by the drill. Results directories must be new, so failed
evidence cannot be overwritten. Preserve the harness, full source SHA, binary
hash, toolchain and build settings with each run; `--profile` records supplied
build metadata. Keep the output in the local evidence ledger and exclude test
TLS storage when copying it. This bounded workload does not validate the default
4096 process ceiling as a safe production capacity.

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

## 🎯 The static path has no line to fix

A `perf` profile of 30,000 static requests served directly on athlon put the
largest single user-space symbol at **`memcpy`, 0.96 %**. Nothing else reached
1 %. Self time was 61.5 % in `pingclair`, 7.4 % in `libc` and 30.5 % in the
kernel, and that 69 % of user space is spread across several hundred small
functions — the ordinary shape of monomorphised, inlined async state machines.

📌 **So the success criterion here cannot be "find the line and fix it".** There
is no line. It is "re-measure a ratio that the section above says is
trustworthy". A session that opens with `perf` and has no end condition will not
converge, which is why this is written down rather than rediscovered.

Two supporting measurements, both of which make the ratio *flatter* than the
truth rather than more flattering:

- `strace -f -c` shows **fewer syscalls per request than nginx** (5 versus 6),
  spending the same time in them (0.118 s versus 0.117 s) once
  `epoll_wait`/`clock_nanosleep`/`futex` are discounted on our side. The gap is
  neither I/O nor any single function.
- Container bridge networking eats nearly half the throughput — about
  10,000 req/s inside the container against 18,695 on the host, with
  `conntrack`/`seccomp` visible in the profile. Both candidates pay that fixed
  cost, so **the real gap is worse than the measured one, not better**.
