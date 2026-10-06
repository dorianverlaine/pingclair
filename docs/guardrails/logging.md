# ⚠️ Pingclair implementation guardrails — logging

> Read this before you touch anything that formats or writes a log record.
> Every rule below stands behind a failure that already happened, and the
> measured cost of getting it wrong is not a few percent: on the load this was
> measured under, logging to the systemd journal cost **about half of server
> throughput**, and suppressing the record entirely was worth more than every
> writer optimisation combined.
>
> 📌 This file exists because that knowledge used to live only in commit
> bodies and a local evidence directory. A commit body is not read during
> review, and `benchmarks/results/` is disposable by design — so the revision
> that broke a rule would have looked like a tidy simplification.

---

## 🏎️ Where the cost actually is

This is the finding everything else follows from, and it is counter-intuitive
enough to be worth stating before the rules.

One binary, one load pattern, same machine, only the **log destination**
varying (2026-09-20, `benchmarks/results/20260920_e44dcf1/logging/`):

| Destination | Relative throughput |
| --- | --- |
| Logging off | fastest |
| stderr discarded (`/dev/null`) | well below off |
| stderr to a file | **indistinguishable from discarded** |
| stderr on the systemd journal | **about half of off** |

**Writing to a black hole costs the same as writing to a file.** The I/O is not
the bottleneck, and neither is the writer thread. What is left is *building the
record* — and that work still runs on the emitting thread, because it has to.
`pingclair/src/logging.rs` says the same thing in prose:

> Formatting still happens on the emitting thread. Its cost must be measured
> separately from the destination: a journal receiver also consumes CPU and
> performs work per line, even when the producer writes asynchronously.
> Comparing only logging enabled versus disabled cannot attribute that cost.

After the writer-side fixes landed, the **residual** penalty was about **13% on
the static path and 7% on the reverse-proxy path**. An attempt to shrink the
record by collapsing ten structured fields into one pre-formatted field bought
about 6% on static and **nothing measurable on the proxy path**, and was
rejected on that evidence. The conclusion to keep is a single sentence from
that work: *the real cost is emitting a record per request at all.*

⚠️ One run in that campaign served 100,000 requests and logged **99,540**. The
only reason it was caught is that the harness asserts the record count equals
the request count. That is the bounded-queue drop policy firing for real, and
it is why the drop counter exists.

📌 The absolute figures are deliberately not repeated here. This repository
publishes conclusions, not raw runs; the raw tree stays local under
`benchmarks/results/`, which `.gitignore` excludes.

---

## 🧱 The invariants — each one is load-bearing

Changing any row below needs a measurement, not an opinion.

| Invariant | Where | Why it is that shape |
| --- | --- | --- |
| The sink is written from a **dedicated OS thread**, never a Tokio worker | `access_log.rs` (`LogWriter::spawn_with_rotation`) | The work is blocking file I/O; occupying a runtime worker takes a thread that requests need. This is also why logging still works during shutdown, after the runtime has stopped taking tasks |
| Submission is **`try_send` only — never blocking** | `access_log.rs` (`LogWriter::submit`) | `send` would block once the queue filled, which is the exact stall the queue exists to remove |
| The queue is **bounded**, and a full queue **drops** | 1024 lines for the access log; 8192 records for the process log | Unbounded turns a slow consumer into memory growth and eventually a kill. The two depths differ on purpose — do not unify them because they look like one knob |
| Drops are **counted and exported**, never silent | `pingclair_access_log_dropped_total` | A log with a silent gap is worse than one that says it has a gap. Any non-zero value means the log is incomplete for that period — alert on the rate |
| A **sampled** line is *not* counted as dropped | `SamplingWindow`, `access_log.rs` | The two are different facts. The counter means "the writer could not keep up", which is a fault worth acting on; a sampled line is one the operator asked not to have. One counter cannot mean both without making the alerting useless |
| The format buffer is **reused**, reserved at a **measured** size | `take_buffer(768)` | A normal structured record with both header maps is about 650 bytes. The previous 320-byte reserve **forced every request through a second allocation** |
| An oversized record **bypasses the batch and is never retained** | `MAX_REUSABLE_LINE_BYTES` (8 KiB); `writer.rs` oversized path | Otherwise an attacker-inflated record stays in the reuse pool forever |
| Fields are appended by **macros that expand inline** | `raw_field!`, `str_field!`, `display_str_field!` | They `push`/`push_str`/`write!` straight into the reused buffer. There is no intermediate `String`, no `format!`, no serialisation value tree, no per-field allocation |
| The `exclude` list is a **short `Vec` scanned linearly** | `AccessLogger::included` | Most loggers exclude nothing, so the scan returns after one length check. Hashing every field of every record cost more than the scan |
| **Cheap rejection happens before expensive work** | `AccessLogger::log` | Sampling is decided *before* the line is formatted, because a sampled entry is one nobody will ever read |
| Batching has **both** a byte ceiling and an **independent** deadline | `BATCH_BYTES` 64 KiB, `FLUSH_INTERVAL` 5 ms | A continuous stream must not postpone the deadline indefinitely |
| The sink file is **opened once and shared** | `LogSink::File` | Reopening per line costs a syscall pair on every request and lets two servers pointed at one path interleave partial lines |
| Rotation happens **on the writer thread, between lines** | `LogWriter::spawn_with_rotation` | Renaming and reopening while a write is in flight is the only way to interleave a rename with a write |
| The sampling decision is **lock-free** | `SamplingWindow::admits` | A mutex there would serialise every request behind whichever one is currently deciding whether to write a log line. One compare-exchange hands over the window; being off by one entry across the boundary is the right trade for a mechanism whose purpose is approximation |
| Shutdown drains within **one shared, bounded budget** | `flush_all`, 250 ms | A blocked sink must not hang shutdown, and one deadline for the whole drain bounds how long exit can take |

### 🔬 The invariants that have tests, and the ones that do not

Moved with the code or not at all:

- `a_wedged_sink_does_not_block_the_caller` — 10,000 submissions complete
  while the sink is wedged, "where previously the first one would have blocked
  forever".
- `dropped_lines_are_counted`, `a_healthy_sink_loses_nothing`.

🚫 **Nothing tests the formatter.** There is no test that would fail if
`included()` became a `HashMap`, if the 768-byte reserve became one shared
constant, or if the field macros became a `dyn` formatter. That is the most
exposed part of the module and the least guarded, which is why the first
section of this file is the one to read twice.

---

## 🚫 Do not

Each of these is a real regression or a rejected design, not a style preference.

- 🚫 **Do not let logging stall a request.** No inline write, no lock held on
  the emitting thread, no blocking send. A full disk, a stalled NFS mount, or a
  log device busy with garbage collection must cost log lines, never requests.
- 🚫 **Do not make the queue unbounded.** It does not remove the failure; it
  converts a stall into unbounded memory growth and a kill.
- 🚫 **Do not retry a partial batch write.** Replaying the batch duplicates
  records. Keep the remainder.
- 🚫 **Do not rely on `Drop` to drain.** `std::process::exit` runs no
  destructors, and the queue abandoned that way is the one carrying the most
  records.
- 🚫 **Do not stop draining at the first failing writer.** Iterating with
  `Iterator::all` skips every writer behind the failure — their barriers are
  never sent and their records are lost without a write being attempted. Offer
  every writer a barrier, share one deadline, and report an incomplete drain.
- 🚫 **Do not `join` the writer thread on shutdown.** The global sender is
  parked in a `OnceLock` that is never dropped, so `recv()` never returns and
  the process hangs. Short-lived CLI commands and six integration tests wedged
  past 660 seconds on exactly this.
- 🚫 **Do not move the destination stream when moving the write off the path.**
  Changing *where the work happens* is not licence to change *where the output
  goes*; that once broke five integration tests, and it would break every
  operator's log pipeline.
- 🚫 **Do not rotate from a request thread.**
- 🚫 **Do not open log files, rebuild filters, or do other log provisioning
  inside the reload publication gate.** It widens the window in which clients
  see "Configuration Reload In Progress".
- 🚫 **Do not forward each `write` call as its own message.** A `fmt::layer`
  formats across several calls, so per-call forwarding interleaves two workers
  mid-line. Buffer the whole record and send it once.
- 🚫 **Do not install the subscriber thread-locally.** `set_default` made every
  access line silently disappear. The failure was found by running the binary
  and looking for the line — not by a type error.
- 🚫 **Do not count a sampled line in the dropped counter**, and do not sample
  after formatting.
- 🚫 **Do not hash every field name to decide exclusion**, and do not build the
  record from per-field temporaries.
- 🚫 **Do not emit a log line per hostile event.** Severity and volume are part
  of the contract: a `wrk` run closing 200 connections once produced 153 ERROR
  lines in a single second — immediately after 507,348 requests had succeeded —
  and because the default filter passes ERROR only, that flood was the only
  thing an operator could see. Severity follows the *source* of the condition,
  not the level the emitting library chose.
- 🚫 **Do not decide anything by formatting.** The record filter must cost a
  comparison, not a string build.

---

## 📋 The failure history

Read this when you are about to "tidy up" something in the list above.

| Commit | Date | What broke | The fix |
| --- | --- | --- | --- |
| `363f50c` | 2026-08-05 | Every line was written and flushed inline under the sink lock, on the request thread. A full disk or stalled NFS **stopped the proxy from proxying** | Bounded queue, dedicated `pingclair-access-log` thread, `try_send`, drops counted. An unbounded queue was considered and rejected |
| `0a1f900` | 2026-08-04 | Client disconnects logged at ERROR: 153 ERROR lines in one second after 507,348 successful requests, and that flood was the only visible output | Severity from Pingora's `ErrorSource`; 153 → 0, throughput unchanged |
| `4f39ff7` | 2026-09-20 | Synchronous `fmt::layer()` write on the worker thread to the journal; **about half of throughput** | `NonBlockingWriter`, 8192-deep queue. Two hand-caught traps: per-`write` forwarding interleaved records, and `set_default` dropped every access line |
| `2c11b9c`, `e44dcf1` | 2026-09-20 | The writer join wedged short-lived runs — the CLI never exited and six integration tests sat past 660s after 1,377 had passed | Bounded 250 ms drain, no join |
| `e1febec` | 2026-09-21 | Per-request `write_all` + `flush`, plus a `Vec<(String, String)>` of headers and three `to_string()`s | 64 KiB batch with an independent deadline, buffer pool, borrowed header wrapper, `Cow` redaction, short `Vec` exclude list, `include_tls` compiled once |
| `dc25740` | 2026-09-21 | The background writer silently moved records stderr-ward; five integration tests reading captured stdout failed | stdout restored |
| `5e74418` | 2026-09-23 | `Iterator::all` in the drain **skipped every writer behind a failing one**; and `process::exit` abandoned the fullest queue | Every writer offered a barrier; one shared deadline; the tracing queue drained on the exit path |
| `aa38fd5` | 2026-09-23 | The drain did not acknowledge that records had reached stdout | Barrier acknowledges |
| `f26dbea` | 2026-09-24 | Opening the process-log file inside the reload publication gate widened the "Reload In Progress" window | Moved out of the gate; caught by a reload integration test |
| `07d2964` | 2026-10-06 | Pingora's routine keepalive-pool miss logged at ERROR, reproduced once in 51,200 requests | `log_bridge.rs` re-levels by exact `(target, literal message)` using `Arguments::as_str`, allocating nothing |

---

## 🧩 Applying this to a new transport

The rules above were earned on a per-**request** path. A per-**connection**
path — Layer 4 — changes which ones bite.

- 👍 **The rate differs, and that matters.** One record per connection is
  orders of magnitude cheaper than one per request for long-lived tunnels. The
  half-of-throughput figure does **not** transfer there.
- ⚠️ **But the cost scales with connection *rate*, not with the protocol.** Put
  the same listener in front of a service that carries one request per
  connection and the rate matches HTTP's, at which point the same residual
  penalty applies — from the same cause. Treat a per-connection record as a
  request-path record, not as a cold path.
- 🚫 **Nothing on the pre-route path may format or allocate to decide.** For
  Layer 4 that decision runs on **every unauthenticated connection**, which is
  far more pressure than a handful of Pingora records a minute.
- ⚠️ **Format at teardown, not at connection start.** A session can last hours;
  a format buffer taken when the connection is accepted and held until it ends
  pins that allocation for the session's whole life — the exact shape the reuse
  pool exists to avoid.
- 🚫 **Emit exactly once, on every exit path, including the paths that lose.**
  The record an operator most needs is the one for a session cut by a restart
  or a timeout. A session that vanishes without a line is indistinguishable
  from one that never existed.
- 📏 **Give the new record type its own measured reserve.** The 768-byte figure
  is measured for an HTTP record and is wrong for another shape in whichever
  direction the guess errs.
- 🚫 **An attacker-controlled value is a field, never a selector.** A received
  SNI may be written into a record that is being emitted anyway; it must never
  decide *which* destination runs, and it must never become a metric label.

---

## 📏 How to measure a logging change

- 🔬 **Attribute separately.** Measure the formatter and the destination as two
  costs. A single enabled-versus-disabled comparison cannot tell them apart,
  and it will report the sink's CPU as the proxy's.
- 🔬 **Assert the record count.** A throughput number without a matching
  record count cannot distinguish "fast" from "silently dropping". The one
  void run in the 2026-09-20 campaign was found this way and would otherwise
  have been reported as a win.
- 🔬 **Interleave rounds.** The A/B campaign that justified these changes ran
  three interleaved rounds; run-to-run variance on this path is large enough
  that sequential runs mislead.
- 🚫 **Do not publish a raw run as a claim.** Evidence stays under
  `benchmarks/results/<date>_<commit>/`, which is never committed; conclusions
  are published, and a microbenchmark win is not a server-performance claim.

---

## 🧭 Where this is going

The logging core is being extracted into `pingclair-runtime` (tracked on the
Layer 4 issue) so the HTTP and Layer 4 transports can share it without either
depending on the other. The extraction is a **pure move**: if a diff in that
work changes behaviour rather than relocating it, it is not reviewable as a
move, and the table in "The invariants" is what such a diff would quietly
break.
