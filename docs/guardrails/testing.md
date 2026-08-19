# ⚠️ Pingclair implementation guardrails — testing and debugging

## 🧪 Testing and debugging

- **Never keep two build configurations for one thing.** Found on Day 22,
  2026-08-05: there was a `Dockerfile` in the repository root, and
  `docker build .` — the single most obvious command to run from a clean
  checkout — **failed**, because it listed the crates to COPY one by one and
  missed the `vendor/` that `[patch.crates-io]` needs. CI built
  `deployment/Dockerfile` (`COPY . .`), so the root one had **never been built by
  any workflow**, and `benchmarks/docker-compose.yml` was pointing straight at it.

  The earlier incident on 2026-07-31 had already recorded the same shape (see the
  linking section below: Dockerfile drift left the production image different
  from CI). The conclusion then was "change one, change the other", and **that
  conclusion was not good enough** — consistency that depends on somebody
  remembering will eventually meet somebody who does not.

  > 🎯 **The operable rule**: duplicated build configuration gets **deleted**,
  > not kept in sync by discipline. The root one was removed on 2026-08-05,
  > `deployment/Dockerfile` is the only one left, and the `docker-image` job in
  > `ci.yml` builds it every time.

- **A green unit test can be checking the right thing at the wrong layer.**
  When `lb_policy header X-Session` was added on 2026-08-04, it came with
  `an_absent_or_empty_value_yields_no_key`: when the request carries no such
  header, `extract_hash_key` must return `None`. It was green, and **the
  assertion itself was entirely correct**.

  Nobody asked the next question: **what does the balancer do with that `None`?**
  The answer was `key.unwrap_or(b"")`, hashing the empty string — perfectly
  consistently, so every request without the header landed on the same backend.
  For a session header that means every user who has not logged in yet, which is
  the busiest traffic on the site, all going to one machine.

  The Day 22 verification that same day ran four real backends in containers, and
  all 40 requests landed on one of them. It was visible at a glance.

  > 🎯 **The operable rule**: when you test "A returns a sentinel in this case",
  > **test in the same breath what A's caller does when it receives that
  > sentinel**. The meaning of `None` / `""` / `0` / the empty set does not live
  > in the function that produces it; it lives where it is consumed. Testing only
  > the producer verifies half a contract and then claims the whole one holds.

- **A self-signed certificate cannot detect a certificate-chain defect.** A
  self-signed certificate is its own issuer and **has no** intermediate — "send
  only the leaf" and "send the full chain" produce byte-identical output. So any
  TLS test built on a self-signed fixture is **physically incapable** of observing
  a bug like "the server dropped the intermediate". That is how the two-region
  public-internet verification on 2026-07-30 caught H1/H2 sending only the leaf:
  until then, not one of 474 tests could possibly have found it. To verify a
  chain, the fixture needs a real two-level trust path, root → intermediate →
  leaf (`rcgen` builds one directly; see `build_two_level_chain` in
  `pingclair/tests/integration.rs`), asserted through the client's
  `peer_cert_chain().len()`.
- **A browser is not an acceptance tool for certificate chains.** Chrome and
  Firefox cache intermediates and will fetch a missing one themselves over AIA,
  so **a server that omits the intermediate still shows a green padlock**. curl,
  Go, Java, and Python requests fail hard with
  `unable to get local issuer certificate (20)`. Accept with a strict client;
  never take "the browser looks fine" as evidence.
- **The local macOS box has a system proxy on `127.0.0.1:1082`**; reqwest
  integration tests must call `.no_proxy()`, or requests get intercepted and the
  symptom looks like a routing error.
- **Local `dig` returns fake addresses.** The system proxy uses fake-IP DNS, so a
  plain `dig example.com` gives you `198.18.x.x`, which looks like DNS has not
  propagated. To see real resolution, name a public resolver:
  `dig @8.8.8.8 example.com`.
- **On a persistent 404/502 or a readiness anomaly**, check the port owner with
  `lsof`/`ss` first, then check whether the child already exited on a bind
  failure. **Do not start from the assumption that routing logic is wrong** —
  that misdiagnosis has cost a full debugging round.
- **On timeout, kill and wait first, then read stdout/stderr to EOF.** The other
  order blocks forever and leaves a ghost process behind.
- Real-binary tests always use a **dynamic port** and a **unique readiness
  token**. A fixed port lets an old process be mistaken for ready, and the test
  appears to pass while measuring something else entirely.
- **A real-binary drill must set `PINGCLAIR_TLS_STORE` to a writable directory**,
  even when the configuration contains no TLS at all. The TLS manager initialises
  the store unconditionally, before it reads the configuration. The default path
  is now per-user writable at `$XDG_DATA_HOME/pingclair`
  (`~/.local/share/pingclair`), and when it cannot be created or written it fails
  at startup with **an explicit error naming the path** (a write probe; see
  `pingclair/src/main.rs`) instead of the old unattributable `PermissionDenied`
  panic — but drills still set the variable, so that the CA, the ACME account key
  and the autosave document do not land in the CI runner's HOME and tests do not
  contaminate each other.
- **`zsh` does not word-split unquoted variables.** `for x in "a 1" ...;
  set -- $x` splits into two arguments under bash and stays one under zsh — the
  symptom is an empty `$2`, which reads very easily as a problem in the program
  under test. Test scripts use functions with explicit parameters instead.
- **A compression test's payload must be unique per chunk and incompressible.**
  Repeating one block lets zstd's window deduplicate it (64 MiB → 15 KB), which
  makes assertions like "output is flowing" **fail spuriously**.
- **The local gate runs `cargo +1.97.1`, not the default toolchain.** CI pins
  `1.97.1` (since the 2026-08-02 split that means the `blocking-ci.yml` fast gate
  plus the `postmerge-ci.yml` full gate, each calling reusable workflows), and the
  workspace declares `rust-version = "1.97"`. Locally, always enter through
  `just ci` so it is the same gate. Get the toolchain version wrong and type
  inference and rustfmt's line breaking both change, giving all-green locally
  followed by all-red in CI — and this repository has fallen in from both
  directions: on 2026-07-29 the local toolchain was newer than CI (a mixed array
  `&[&String, &String, &str]` is `E0308` on 1.88), and on 2026-08-02 the reverse,
  where the release image still pinned 1.88.0 while the lockfile already needed
  ≥ 1.97 (`rustc 1.88.0 is not supported`).
- 🎩 **CI runners are pinned to `ubuntu-24.04` / `ubuntu-24.04-arm`** (no more
  floating `ubuntu-latest`), matching `deployment/Dockerfile`'s `ubuntu:24.04` —
  same base, same rustup pin at 1.97.1, same `apt` package list. This rule comes
  from the 2026-07-31 incident: that Dockerfile **had not been built since the H3
  switch to tokio-quiche**, the image running in production had been built before
  the dependency tree changed, and its Rust version had long since diverged from
  what `Cargo.toml` declared. Running CI on a different distribution would hide
  all of that. **The two package lists must be kept in sync by hand** — CI's
  `apt-get install` and the Dockerfile builder stage's list have no mechanism
  forcing agreement, so this rule is itself the next likely repeat.
- 🐳 **CI's `docker.yml` reusable workflow really does build
  `deployment/Dockerfile` and boot it** (`docker run ... version`, and
  `docker run ... validate` against a real Pingclairfile). This is the direct
  countermeasure to "a build script nobody runs is untested code" — had this job
  existed at the time, the Dockerfile drift above would have gone red on the first
  push.
- 🚫 **Listener-topology rollback tests must no longer rely on "port 1 cannot be
  bound".** Since 2026-08-13, Admin and signal reload return `restart_required`
  for added or removed listeners before any bind is attempted; tests should use a
  genuinely free dynamic port and assert that the program still has not taken it.
  That verifies the product's contract rather than Docker's
  `ip_unprivileged_port_start`, the running user, or `CAP_NET_BIND_SERVICE`.

  > 📌 The general shape: **any test whose assertion is "this operation will
  > fail" carries a hidden environmental premise.** When you can assert a stable
  > API result directly, do not use an accident of the environment as an oracle.

- ⚖️ **A round-robin test must not assert who goes first.** Load balancing
  guarantees that adjacent requests alternate and that the totals come out even;
  **which backend starts is decided by the initial value of a shared counter**,
  and nothing in the configuration pins it. On 2026-08-10,
  `test_php_fastcgi_round_robins_across_multiple_responders` asserted
  `["first","second","first","second"]`, was green on macOS and red on Linux with
  `["second","first",…]` — the same correct behaviour, one phase apart. Assert the
  property (no two adjacent alike, each got half), not a sequence you observed
  once.

- 🎲 **`test_websocket_upgrade_tunnels_bytes_in_both_directions` is a known
  upstream (Pingora) flake.** `scripts/run-ci-tests.sh` (called by the `rust-ci`
  fast gate) re-runs the whole nextest round up to three times, but **only** when
  that test is the sole failure; any other failure, or three failures in a row,
  still goes red. **Do not change test code to chase this flake** — its occasional
  failure is not evidence of a regression, and a retry is enough to remove the
  noise.

  > 📌 **The citation** (added 2026-08-10; before that this rule had a conclusion
  > and no source, and this repository's own rule is that a conclusion-only
  > rejection note becomes a door nobody dares push):
  > reported upstream as
  > [cloudflare/pingora#946](https://github.com/cloudflare/pingora/issues/946),
  > "HTTP/1 upgrade torn down when the upstream's 101 is read before the
  > request's empty body" (opened 2026-07-30, still open), with the fix in
  > [#947](https://github.com/cloudflare/pingora/pull/947), "Keep an upgraded
  > tunnel open when the request body ends after 101" (opened 2026-08-04,
  > **not yet merged**). The symptom is an `UnexpectedEof` while waiting for the
  > tunnel marker.
  >
  > **This rule expires with #947**: once it merges and reaches the pingora
  > version we pin, the flake should disappear, and the retry must come out so
  > the test goes back to being one that is simply expected to pass. Keeping a
  > retry after the flake is fixed means keeping a test that can never go red.
- 🔒 **`security-audit.yml` (`cargo audit`) runs on the merge gate and on a
  nightly schedule**, not once before a release. RustSec publishes on its own
  schedule, not this project's, and a dependency that merged clean and was
  disclosed afterwards is only caught by running continuously. When a finding does
  appear, the exception process is **a written risk acceptance** (the existing
  written-risk-acceptance rule), not switching this job to
  `continue-on-error`.
- **Seeing anything below ERROR in container logs requires `RUST_LOG`.** The
  subscriber is built from `EnvFilter::from_default_env()`, so leaving it unset
  means ERROR only — and the symptom is a feature that plainly works while
  "logging nothing".
- **Strip ANSI before grepping container logs.** tracing's fmt layer colours
  field names even when stdout is not a tty, so `from=1.2.3.4` is really
  `from<ESC>[0m<ESC>[2m=<ESC>[0m1.2.3.4`, and grepping the literal string
  **fails spuriously**.
- **Never use `sed -i` on a single bind-mounted file.** A bind mount binds
  **an inode, not a path**: `sed -i` writes a new file and renames it over the
  old one, so the host sees the change and **the container keeps reading the old
  inode**. The failure is completely silent — reload reports success (it really
  did reload; the content was simply identical), so assertions like "the bad
  configuration was rejected" and "last-known-good is still live" **all pass
  falsely**. Always rewrite in place by truncation, `cat new > target`, and assert
  at the top of the drill that `stat -c %i` agrees between host and container.
  Hit for real on Day 7, 2026-07-28; two ✅ marks were fictional.
- **Do not put `grep -q` at the end of a `set -o pipefail` pipeline.** It exits
  early on a match, which SIGPIPEs the upstream process; 141 becomes the
  pipeline's status, so **a match reads as a failure**. And you only lose that
  race when the output is long enough, so it fails intermittently. Save to a file
  first, then grep the file.
- **A script taking a results directory must handle absolute paths.**
  `-v "$(pwd)/$conf"` turns an absolute path into `/tmp//tmp/...`, Docker
  silently creates an empty directory as the mount point, and the program will
  not start.
- **When testing DNS re-resolution, pin container addresses with `--ip`.** Letting
  Docker assign them turns "did the backend follow?" into a question about the
  daemon's address-reuse policy, and a test that only passes when a new IP
  happens to be handed out is not a test. To produce "the name no longer resolves
  but the old address is still healthy", `docker network disconnect` and then
  `connect --ip <the same address>` without an alias — same container, same
  address, only the name is gone.

---

## 📁 Verification evidence

- Results go to local `benchmarks/results/<date>_<commit-prefix>/`
  (**never committed**).
- **Failed evidence is never overwritten.** After a fix, open a new directory and
  keep the old failure as the comparison.
- Verification records the **full commit SHA**, never "latest".

## 📊 Performance measurement: three ways to succeed at the wrong number

All three really happened while re-establishing the baseline on 2026-08-11, and
**none of them makes the program report an error** — every one needs an after-the-
fact check to find. This section exists so the next person does not have to
rediscover them.

- **Never measure and build at the same time.** During the first baseline run
  that day, a `--platform linux/amd64` (Rosetta 2) release compile was running on
  the same machine. This harness measures **CPU per request**, so the background
  load *is* the thing being measured. The contamination is visible round by round
  in the data (proxied H2 at 53,836 → 39,447 → 36,172 rps, monotonically
  decaying).

  > 🎯 **The operable rule**: finish every binary, confirm the machine is quiet,
  > then start measuring. There is no such thing as "just a little in the
  > background". The voided run is kept at
  > `benchmarks/results/20260811_baseline/contaminated/`, because the decaying
  > numbers argue for the rule better than the rule does.

- **Print `succeeded` on every row and void the row when it does not match.**
  `h2load -H "host: bench.local"` **cannot set the HTTP/1.1 Host** — Host comes
  from the URL's authority. So nginx and Pingclair both received
  `Host: 127.0.0.1`, neither matched a vhost, and **all 30,000 requests were
  4xx** — while the comparison target, which has no concept of virtual hosts,
  returned 200 and looked entirely normal. That table showed us "winning" by a
  factor of four; the truth is that both sides were measuring the cost of a 404.

  > 🎯 **The operable rule**: `h2load` reports `succeeded/failed` itself; the
  > harness must print it beside every row and treat any row where it differs
  > from the request count as not having happened. To change the Host, use
  > `--connect-to=<ip>:<port>` with the real hostname in the URL, never `-H`.

- **Cross-machine comparison is only valid between two runs identical in
  everything but the machine.** Static results from the Mac (`--cpus=2`,
  `-t2 -c50 -n100000`) were once compared against athlon's (`--cpus=1`,
  `-t1 -c25 -n30000`) and the difference read as a machine-generation effect —
  **that was a comparison of settings**. The same run missed another variable:
  athlon has no AES-NI, so Pingclair negotiated ChaCha20-Poly1305 while nginx
  negotiated AES-256-GCM, and **the two were not doing the same work at all**.

  > 🎯 **The operable rule**: **the cipher is a variable too.** Before comparing
  > machines, confirm both negotiated the same cipher suite (`openssl s_client`
  > shows it) and fix concurrency, client threads, and the container CPU quota.
  > Otherwise the result describes your method rather than the machine.

- **A client that saturates is not a client.** `benchmarks/aws-h3/h3_bench.py` and
  `h3_bench_pipeline.py` are built on **aioquic — a pure-Python QUIC
  implementation** — and the harness's own README notes it is single-threaded,
  ~2k req/s, client-bound. Pointing it at three servers capable of 15k–47k req/s
  measures the client; worse, **the ranking can invert arbitrarily**, because what
  remains of the difference comes from each server's pacing and ACK behaviour
  toward a slow client rather than from throughput. Re-measuring on 2026-08-11
  with the ngtcp2/nghttp3 build of h2load produced the opposite of the earlier
  impression.

  > 🎯 **The operable rule**: H3 **performance** comparisons always use h2load
  > from the `goodideal/nghttp2` image (`--alpn-list=h3`). Those two aioquic
  > scripts are kept for **semantic parity** only — they can read response
  > content, which h2load cannot, and that is what they are for. Also, QUIC is
  > extremely sensitive to UDP buffers: `net.core.rmem_max` / `wmem_max` must be
  > fixed across all candidates (7500000 for that round), or you are measuring
  > kernel settings.

## 🔨 H3 scripts must always rebuild the binary (2026-08-17)

- 🤡 **`scripts/test-h3-*.sh` used to build only `if [[ ! -x "${binary}" ]]`.** So
  it ran the **stale** `target/debug/pingclair` and reported red about the code
  as it was before your change. That cost a round on 2026-08-17: the SEC-007 H3
  probe reported `No Matching Virtual Host` when the fix was already in the
  source. 🎯 The reverse is worse — **reporting green against a stale binary
  warns you about nothing**.
- 📌 Both scripts now `cargo build` **unconditionally** (a no-op when nothing
  changed). To use your own binary, set `PINGCLAIR_BINARY`; that path is checked
  for executability and never built.
- 🧭 The test: **a verification script's default behaviour must be to verify the
  source as it is now.** Making the rebuild optional turns "which version did you
  just test?" into something the user has to remember.

## 🔬 Do not swap the subject while you are swapping the instrument (2026-08-18)

Public-internet verification measured "the `Host` sent upstream over HTTP/2 is
empty". The first reaction was to suspect the instrument — the correct reaction,
and an entire section above is about how broken tooling disguises itself as a
broken product. So the measurement was repeated against an upstream that dumps
raw bytes, `Host` came back correct, and the earlier empty value was written up as
**a parsing problem in the echo upstream**, along with a lesson that one
instrument is not enough.

**That verdict was wrong.** It was a real defect: `uri strip_prefix` made the H2
site name disappear entirely (fixed in `7d07f49`).

Here is the mistake: swapping the instrument **also swapped the route under
test** — the old instrument hit `/rewrite` (which has `strip_prefix`), the new one
hit `/raw` (which does not). Two variables moved at once, and the whole difference
was charged to the instrument. It took a third measurement, same instrument with
only `strip_prefix` differing, to see the real cause.

> 🎯 **The operable rule**: when you suspect the instrument, the new instrument
> must hit **exactly the same target** — same route, same configuration, same
> request. Only then does the difference between the two results contain nothing
> but the instrument. Changing the subject is a separate experiment.

📌 This does not contradict "one instrument is not enough" above; it is the
condition that rule needs. A second instrument only adds information when
**everything else is held fixed**. Otherwise it is just one more misleading
measurement.
