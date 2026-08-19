# ⚠️ Pingclair implementation guardrails — TLS, dependencies, and secure defaults

## 🔗 Dependencies and linking

- **CI and the Dockerfile use stable Rust.** nightly once ICE'd compiling tokio
  under the release profile (`panic="abort"` + fat LTO + `codegen-units=1`).
- **The reqwest dev dependency stays on rustls.** native-tls/OpenSSL collides at
  link time with quiche's BoringSSL.
- **Never introduce `pingora-openssl`, `openssl-sys`, or reqwest `native-tls`.**
  `quiche 0.29`, `boring 4.22`, and Pingora's `boringssl` feature are one
  BoringSSL linking design; OpenSSL/BoringSSL symbol collisions have previously
  produced **a SIGBUS at startup and link errors on Linux**. These three rules are
  not preferences, they are preconditions for H3 — see "why H3 is pinned to
  quiche/BoringSSL" below.

- 🔓 **`boring-sys` is a direct dependency, and its version moves with `boring`.**
  `boring` 4.22 does not wrap `X509_STORE_CTX_set_purpose`, which downstream mTLS
  needs (see the downstream mTLS section for why), so the workspace declares
  `boring-sys = "4.22"` and `foreign-types = "0.5"` directly — the latter to get
  `ForeignTypeRef::as_ptr`, which `boring` only `extern crate`s and never
  re-exports. ⚠️ **Two `boring-sys` means two BoringSSL**, which is exactly the
  symbol collision described above. Both using a caret range is deliberate: they
  resolve to the same version together. The day `boring` needs a major bump, this
  line changes with it. 📌 The check is unchanged from before, with nothing added:
  `cargo tree -i boring-sys` must show exactly one, and
  `cargo tree -i openssl-sys` must match nothing.

- **Before forking an upstream crate, get a number — measured where the forked
  thing is the bottleneck.** Two forks were deleted at once on 2026-08-04
  (`pingora-core` and `pingora-http`, 38,532 lines). Both mechanisms were
  plausible; neither had a single measurement taken under conditions where the
  patched component was a saturated resource. `pingora-core` cut cumulative
  allocation by 86% for +0.9% throughput (inside the noise) with completely
  overlapping RSS ranges. The first load test was not even valid — nginx was
  pinned at 200% of its quota while Pingclair still had headroom, so the backend
  was what got measured. **The rule now: record CPU for all three parties on every
  A/B round, and throw the round away when the proxy is not the saturated layer.**

- **`[patch.crates-io]` makes a crate invisible to `cargo audit`.** After a patch,
  the lockfile entry loses its `source` and `checksum`, and cargo-audit only
  reports packages it can trace back to crates.io. Verified directly on
  2026-08-04: a project on `atty 0.2.14` reports RUSTSEC-2021-0145 and
  RUSTSEC-2024-0375, and the same project with `atty` path-patched **reports
  nothing and exits clean**. `security-audit.yml` therefore runs a second pass
  that strips the patch sections, regenerates the lockfile, and audits again —
  any new `[patch]` must be checked against that path still covering it.

- **`target/` grows silently until the disk is gone; cargo never reclaims old
  artefacts.** Measured at 77 GB on 2026-08-04 (`incremental` 41 GB, `deps` 44 GB
  across 252,603 files) with 12 GiB left on the whole disk. One `cargo clean`
  reclaimed 113 GB. **The routine treatment is `cargo sweep --time 7`**
  (`cargo-sweep` is installed), which drops artefacts untouched for a week without
  disturbing day-to-day iteration; `cargo clean` is for when the disk is actually
  tight. Note that `target/integration-linux` holds the pingora#946 reproduction
  binary and must be preserved across a clean.

---

## 🔐 Secure defaults

- Untrusted sources **must not** be able to forge `X-Forwarded-*`, `X-Real-IP`, or
  `CF-Connecting-IP`.
- Misconfiguration always **fails closed**, never gets ignored silently.
- Sensitive fields (`Authorization`, `Cookie`, API keys) are **masked by default**
  in logs, metrics, Admin dumps, and panic messages.
- Downgrade switches such as `insecure_skip_verify` must be **conspicuous and off
  by default**.
- **Recursive types must never use `#[serde(untagged)]`.** Under untagged, a
  newtype variant (`Not(Box<Self>)`) re-parses the entire payload as itself
  **while consuming no input**, so any value that matches no other variant
  recurses forever. serde's untagged replay never goes back through serde_json's
  parser, so serde_json's recursion limit cannot catch it, and a release binary
  with `panic = "abort"` simply dies. On `Matcher` this was a DoS remotely
  triggerable through the Admin API (fixed 2026-07-28). Recursive enums are always
  tagged.
- **Configuration rules belong in the core config layer, not only in the
  Pingclairfile adapter.** The Admin API deserialises a config document straight
  into the core types **with no adapter involved**. A check written only in
  `adapter/caddyfile.rs` is a check with a bypass. Contradictory or half-specified
  settings (`insecure_skip_verify` together with a pinned CA; a cert with no key)
  must be rejected on both paths. Day 11 upstream TLS on 2026-07-29 added the
  matching `compiler::validate_config` for exactly this reason.
- 🎯 **Writing the rule into `validate_config` is not the same as that path
  running it.** The rule above was followed and the conclusion was still false:
  Day 11 and per-listener `proxy_protocol` both correctly added their rules to
  `compiler::validate_config` and both wrote "the Admin path is covered too" into
  the commit message and this document — **while the Admin API had never called
  that function** (fixed on Day 17, 2026-07-30). The tests called the **function**;
  the actual **path** never went through it. After adding a rule, follow every
  entry point all the way down and confirm it really is reached; negative tests hit
  the real interface (an actual POST into the Admin socket), not the validation
  function.
- 🎯 **`panic = "abort"` is set only on the release profile, so tests cannot catch
  an abort.** debug unwinds, so an `unwrap()` only kills that connection's task
  and the server stays up. Which means an assertion like "is the server still
  there?" passes against the very panic it was written to catch — I wrote exactly
  that test on 2026-07-30. To verify a panic, check the child's stderr for
  `panicked at`; that signal holds under both profiles.
- **A listener-level switch must not be built as a global one.** PROXY protocol
  was once `global.proxy_protocol`, so turning it on made every listener demand
  the header and broke the directly-connected one. nginx spells it
  `listen 443 proxy_protocol;` and Caddy uses a per-server listener wrapper —
  neither is global, because real deployments routinely have one port behind an L4
  load balancer and another taking direct connections. Incidentally, `listen` used
  to **silently drop extra arguments**, so `listen :443 proxy_protocol` produced a
  listener that named the feature without requiring it — the same class as
  `encode gzipp`. Changed before the RC was frozen on 2026-07-30: **never take a
  configuration interface you know is wrong into remote verification**, because
  after release you cannot change it.
- **Putting your own ingress in front of a Pingora listener makes Pingora's
  admission control meaningless.** Day 14's PROXY protocol moved the Pingora app
  onto a private loopback listener behind a hand-built ingress;
  `limits { max_connections }` is held by `ResourceGuardedProxy`, so it then
  governed only **the internal hop** while external connections became unbounded.
  Pingora's 503 cannot help either — the external socket belongs to the ingress,
  not to Pingora. **Any hand-built accept loop must carry the same limit itself**,
  and the trust check goes **before** the permit is taken, or an untrusted flood
  eats the allowance reserved for real traffic. Fixed in the Day 14 review on
  2026-07-30; evidence in
  `benchmarks/results/20260730_day14_review_failed_ingress_limit/`.
- **`HttpHealthCheck` replaces only the address and inherits everything else from
  `peer_template`.** SNI, `Host`, and TLS material all come from that template,
  and the template is usually built from the **first backend**. So a pool whose
  backends have different names (`to https://a.internal` + `to https://b.internal`)
  probes b using a's SNI, hostname verification necessarily fails, and b is
  permanently ejected while serving perfectly well — real traffic goes through
  `build_http_peer`, which uses each backend's own `HostName` ext. Probes must
  read `target.ext.get::<HostName>()`. This bug is **completely invisible** on a
  single backend, on same-named backends, and on plain-HTTP pools, which is to say
  on almost every pre-existing test. Fixed in the Day 12 review on 2026-07-30.
- **Pingora's `HttpPeer` reuse hash does not include `options.ca`.** It hashes the
  client cert, `verify_cert`/`verify_hostname`/`alternative_cn`, SNI, and
  `group_key` — but **the CA bundle is not in there**. Two routes to the same
  address with the same SNI and different trust roots share a pooled connection,
  and the strict one inherits a session the permissive one verified (reuse skips
  the handshake entirely). Any new "who may be trusted" dimension must pack itself
  into `group_key`. Pingclair's approach: the protocol group occupies the low 8
  bits and the TLS identity hash is shifted above it, with `peer_protocol_group()`
  to recover the protocol — never compare `group_key == 4` directly again.
- **BoringSSL accepts a mismatched cert/key at configuration time** and fails only
  at handshake, where the upstream's `bad certificate` alert looks like a dozen
  unrelated network errors. When loading a client identity, always verify
  `cert.public_key()?.public_eq(&key)` yourself and **name both files** in the
  error message — that is what catches a half-finished rotation where the
  certificate was replaced and the key was not.
- **`trusted_ca_certs` replaces, it does not add.** Pingora goes through
  `SSL_set1_verify_cert_store`, which overwrites the whole store rather than
  appending. That is the semantics we want (a route pinning an internal CA should
  not simultaneously accept a same-named certificate signed by a public CA), but it
  has to be documented or it reads as "additional trust".
- **untagged also means "not round-trippable".** Variants are identified purely by
  payload shape, so two variants with the same shape become each other after a
  round trip — `Not` disappears entirely, inverting the routing decision. Any
  configuration type that will be serialised back out (Admin dump → post, config
  files) must be tagged.

---

## 🪪 Downstream mTLS (`tls client_auth`, K3, 2026-08-10)

- **Configuration that parses is not a handshake that holds.** `client_auth` once
  parsed completely and compiled completely while **no code on the handshake path
  read it** — the site claimed mutual TLS in its configuration and its logs, and
  admitted the entire internet. For that period `run.rs` chose to **refuse to
  start**: this kind of "claimed but absent" failure is worse than not supporting
  the feature at all. 📌 The test: when adding any security switch, find **the line
  that actually enforces it**. If you cannot find it, do not accept the setting.

- **All four modes need a custom verify callback; BoringSSL's built-in
  verification cannot express them.** The built-in has exactly one answer ("a
  trust path exists, or fail"), while `request` and `require` deliberately do not
  verify. Handing them to the built-in verifier rejects clients the operator
  explicitly wanted admitted. The mapping (mode bits for `SSL_set_custom_verify`):
  `request` = `PEER`; `require` = `PEER|FAIL_IF_NO_PEER_CERT`;
  `verify_if_given` = `PEER` plus verification in the callback;
  `require_and_verify` = `PEER|FAIL_IF_NO_PEER_CERT` plus verification in the
  callback. The empty-certificate case is handled by the mode bits themselves
  (`allow_anonymous` at `tls13_server.cc:1102`); the callback only runs when the
  client **actually sent** a certificate.

- 🎯 **The price of a custom verify callback: the purpose check no longer runs on
  its own, and you must turn it on.** The rule above chose the custom callback;
  this one is its bill. `X509_verify_cert` only consults what a certificate
  declares it is *for* when **somebody has specified a purpose**
  (`x509_vfy.c:570`: `if (ctx->param->purpose > 0 && X509_check_purpose(...))`),
  and a freshly created `X509_STORE_CTX` has purpose 0. So the answer to "does
  this chain build?" gets used as the answer to "may this certificate act as a
  client?" **The consequence**: the most common private-CA deployment is one CA
  signing the whole company — which makes every `serverAuth` server certificate a
  usable client identity. The fix is to call
  `X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT)` before
  `verify_cert()`. ⚠️ `boring` 4.22 does not wrap it —`X509VerifyParamRef` has
  `set_flags`, `set_host`, and `set_depth`, but no `set_purpose` — and its
  `boring_sys` is a private `extern crate`, which is why this depends on
  `boring-sys` and `foreign-types` directly. Their versions must track `boring`, or
  the tree gets two BoringSSLs.
  📌 One thing checked along the way that changed **nothing**: `set_purpose` also
  sets the context's trust to that purpose's default, `X509_TRUST_SSL_CLIENT`. For
  a CA loaded from ordinary PEM the outcome is identical — old value and new both
  land in `trust_compat` in `x509_trs.c`, trusting self-signed and nothing else.
  Only PEM carrying `X509_CERT_AUX` (the rare `TRUSTED CERTIFICATE` block) can
  tell the two apart.
  🤡 One edge that stops you short: a leaf declaring only `anyExtendedKeyUsage`
  **is rejected**. BoringSSL gives `any` its own bit (`XKU_ANYEKU`, 0x100) while
  the SSL-client check looks at `XKU_SSL_CLIENT` (0x2). That is the library's
  behaviour reproduced, not our choice — special-casing it here would mean writing
  a second copy of somebody else's purpose logic beside theirs.
  🎯 The four regression tests (`client_auth.rs`) were verified red first: remove
  that one `set_purpose` line and those four go red while the other eight stay
  green. There is also a real-handshake H3 test,
  `h3_client_auth_refuses_a_certificate_issued_only_for_servers`.

- **Build the trust store at startup; the handshake only borrows it.**
  `SslRef::set_verify_cert_store` goes through `SSL_set0_verify_cert_store`, which
  **takes ownership**, and boring's `X509Store` is not `Clone` — so the obvious
  code rebuilds the entire store on every handshake. Use
  `X509StoreContext::init(&store, leaf, chain, …)` instead, which needs only an
  `&X509StoreRef`, and each connection pays for one `Arc` clone.

- **On the server side `peer_cert_chain()` excludes the leaf; on the client side
  it includes it.** BoringSSL flags this itself with a `WARNING:` at `ssl.h:1609`.
  It happens to be exactly the argument set
  `X509_STORE_CTX_init(ctx, store, leaf, intermediates)` wants, with
  `peer_certificate()` supplying the leaf. Writing it with client-side intuition
  verifies one level too few.

- 🛡️ **A listener with mTLS must require SNI and `Host` to name the same site.**
  Admission is decided by the ClientHello and routing is decided by `Host`, and
  the two can differ. Put a site that requires certificates and one that does not
  on the same socket, and an attacker handshakes under the name that requires
  nothing and sends `Host` for the one that does. Upstream enables
  `strict_sni_host` automatically when it detects client auth for exactly this
  reason, answering `421` and closing the connection.
  ⚠️ **A client that sends no SNI is always rejected on such a listener**: having
  named nothing, it cannot have named the site now being demanded.

- 🚫 **Turn session resumption off on a listener with mTLS.** A resumed handshake
  sends no `CertificateRequest` (`tls13_server.cc:818` sets `hs->cert_request`
  only when `!session_reused`), and BoringSSL **does not re-verify** the peer
  chain it restores from the ticket. So an old ticket still admits a certificate
  that has expired, been revoked, or fallen out of a replaced trust pool. The cost
  is a full handshake on every connection to that listener, and it is paid
  deliberately. Go's `crypto/tls` has the same property, and upstream covers it
  with `VerifyConnection` (which runs on every connection, resumed included);
  BoringSSL has no equivalent hook, so we turn resumption off.

- 🛡️ **Both transports must give the same answer, and they are two separate TLS
  configurations.** H1/H2 goes through the Pingora acceptor's `cert_cb`; H3 goes
  through `tokio-quiche`'s `set_select_certificate_callback` — **QUIC never runs
  `cert_cb` at all**. Both sit in the same window, where the ClientHello is known
  and `CertificateRequest` has not been sent, so one `CompiledClientAuth` attaches
  to both.

- 🔄 **Reloading the mTLS trust pool must carry a generation, not just swap the
  callback.** TCP keep-alive and QUIC connections may have completed their
  handshake before the reload; letting only new handshakes read the new CA leaves
  old certificates authorising traffic on existing connections. A handshake must
  remember the listener-security generation and compare it against the current one
  per request, answering `421` and demanding reconnection on a mismatch. A TLS
  context that started without mTLS may already have issued resumable tickets, so
  enabling mTLS later must return `restart_required` rather than pretending to
  hot-apply. 📌 The policy compilation layer therefore lives in
  `pingclair-proxy/src/client_auth.rs` rather than in the binary: a security switch
  that holds on only one transport hands the attacker a "switch transports" option,
  and `Alt-Svc` actively invites them to. 🚫 When K3 landed, H3 was not yet
  verified, and the fail-closed measure at the time was **no QUIC and no `Alt-Svc`
  for any address with `client_auth`**; K4 (after `4e4b05e`) supplied the missing
  half and lifted it.

- 🤡 **quiche overwrites whatever session cache mode you set, so turning
  resumption off on QUIC works only through `SSL_OP_NO_TICKET`.**
  `Context::from_boring` (quiche 0.29.3, `src/tls/mod.rs:155`) takes your
  `SslContextBuilder` and then **unconditionally** calls `set_session_callback()`
  → `SSL_CTX_set_session_cache_mode(ctx, SSL_SESS_CACHE_CLIENT)` (`:264`) to
  install its own client session callback. The `SslSessionCacheMode::OFF` you set
  on the builder is overwritten on the spot. **Options, by contrast, accumulate**
  and quiche never clears them, so `NO_TICKET` survives.
  📌 My first version set both and carried a comment about "belt and braces" —
  **a protection that is silently reverted is worse than an honest one**, because
  it convinces the next reader there are two layers.
  🎯 This one was **measured, not read**:
  `h3_client_auth_turns_session_resumption_off` first proves the same harness
  **can** resume against an ordinary listener (without that control, "no
  resumption" might just mean the harness cannot resume) and then proves the mTLS
  listener does not. There is no such overwrite on the H1/H2 side —
  `TlsSettings::build()` is just `accept_builder.build()` with nobody touching
  options in between — so that side holds by reasoning, and the asymmetry is
  written down deliberately.

---

## 🌐 Public issuance (ACME, 2026-08-17)

- 🚫 **The name in a ClientHello is chosen by whoever connected, not by the
  configuration file.** This is the reason the section exists. The resolver both
  looks up a certificate and, on a miss, goes and gets one signed — and the miss is
  decided by SNI, so **a stranger picks a hostname and this machine performs
  outbound work against a public CA**: account, order, challenge, rate quota, all
  triggered by them. The fix gives `TlsManager` a `public_issuance_domains`
  allowlist, exactly symmetric to the existing `internal_domains`, checked before
  anything touches the CA.
  📌 **An empty allowlist means "sign for nobody"**, not "sign for anyone". A
  process that has not read the configuration yet, and any future path that forgets
  to publish the list, must land on the refusing side.
  ⚠️ It also means **catch-all sites (`_`, `*`, `:port`) no longer authorise any
  public issuance**. "This site accepts anything" is a statement about routing, not
  about certificate policy, and reading it as the latter *is* the defect. Upstream
  does this with `on_demand_tls` and an explicit `ask` endpoint, which we have not
  implemented (the registry marks it `recognised`), so unlimited on-demand issuance
  here was an accident rather than a feature.

- 🔤 **Normalise names before the store, the in-flight set, and the CA.**
  `CertStore` and the in-flight set are both keyed by string, while SNI is
  case-insensitive and may carry a trailing dot. The allowlist normalised and
  nothing downstream did, which means **one site can be spelled a thousand ways**,
  each one a cache miss, a claim, and a real ACME order — with the spelling chosen
  by the client. The same reasoning makes `ssl_cache` in `certs.rs` key on the
  normalised name, or that `HashMap` inflates on case permutations alone.

- 🎟️ **The in-flight marker must be an RAII guard, never "remove it after the
  call".** The ACME call is awaited inside the TLS handshake. Client disconnects →
  the future is dropped → **the removal line below never runs**, so that name is
  marked "issuing" forever and every later attempt is refused — one disconnect buys
  a permanently broken site. Fixed alongside it: the original check-then-insert
  race across two lock acquisitions. `HashSet::insert`'s return value answers "was
  it there?" and "is it mine now?" in one step.

- 🚦 **Per-name deduplication cannot say how many distinct names are running at
  once.** So there is also a process-wide `Semaphore`
  (`MAX_CONCURRENT_ISSUANCES = 4`). It uses `try_acquire` to refuse outright rather
  than queue: **a queue is memory and latency the asker gets to inflate**, while a
  refusal costs one handshake and both the renewal daemon and the next handshake
  will retry. 📌 Normal traffic never reaches this limit — eager issuance and
  renewal are both sequential, and simultaneous handshakes are the only source of
  concurrency. It is the second line behind the allowlist, not the first.

- 🤡 **`enabled` was written into the configuration, set to false by
  `auto_https off`, and then read by no runtime code at all.** Confirmed by
  searching the whole repository. 📌 The test is identical to the K3 mTLS one:
  **when adding any security switch, find the line that actually enforces it.**
  This is now the second appearance of the same mistake in this one file.
  🎯 Its home is now **after** the store fast path: turning automatic HTTPS off
  should block "go and get one", not "use the one we already have" — the latter
  makes no outbound call and spends no quota, and blocking it only takes the site
  down for nothing.

- 🎯 **Every rule in this section was verified red first.** Remove the allowlist →
  3 red; remove the `enabled` gate → 1 red; widen the semaphore → 1 red (8 ≠ 4);
  empty the drop guard → 2 red. ⚠️ There is a trap in writing these tests that I
  fell into twice: once inside, the mock issuer waits for a release signal, so
  removing a gate makes the test that "should never have reached the issuer"
  **hang instead of fail**. Every wait needs a bound (`expect_entered` /
  `expect_refused`), or the red manifests as a test that never finishes — the least
  useful form of "no" there is.

---

## 📡 DNS-01 (`tls { dns … }`, K5, 2026-08-10)

- 🤡 **rustls's crypto provider must be named explicitly, or the first connection
  panics.** This binary links two of them: `instant-acme` brings aws-lc-rs, and the
  workspace pins `rustls` to `ring`. rustls refuses to guess and panics the moment
  a `ClientConfig` is built:
  `panic!("Could not automatically determine the process-level CryptoProvider")`.
  **That is a panic against the real API at issuance time, not a test artefact** —
  name it with `HttpsConnectorBuilder::with_provider_and_webpki_roots(provider)`.
  📌 This was caught by the test that talks to a mock server. Had we taken the
  shortcut of only writing "tests that hit the real API", this panic would have
  made its first appearance in production. **Provider tests must run offline.**

- 🏢 **Try zone suffixes longest to shortest, and cache the answer.** Which zone
  `_acme-challenge.a.example.com` belongs to is not stated by the name; only the
  account knows. Longest first is what lets a delegated child zone win over its
  parent — which is the entire point of delegation.

- 🧹 **TXT records are replaced, not appended.** Otherwise a retried order leaves
  the previous challenge value behind, and some CAs treat a name carrying two TXT
  records as unreadable.

- 🏷️ **A wildcard's challenge record goes on the parent domain.**
  `*.example.com` and `example.com` share `_acme-challenge.example.com`; composing
  `_acme-challenge.*.example.com` literally produces a name no zone can hold.

- 🔎 **The propagation check's resolver must have caching off.** The check exists
  to observe the record appearing, and a cached NXDOMAIN will keep saying "not
  there" for the whole propagation window.

- 🔐 **The API token is a credential.** It is wrapped in a type whose `Debug`
  prints nothing — not to stop somebody hand-writing a log line, but to stop
  somebody later adding `#[derive(Debug)]` to an enclosing struct. Not even the
  length is printed: length leaks which kind of token it is.

- 🚫 **An unimplemented provider is refused by name at startup, not at
  configuration time.** Refusing at configuration time fails 12 upstream corpus
  files — they use `dns mock`, which upstream has as a test module. `adapt` saying
  "I can translate this" is honest; refusing to **serve** is where the line belongs.
  Same reasoning as K3's `client_auth`.

---

## 🔁 Upstream TLS for inline subrequests (2026-08-17)

- 🤡 **Configuration parsed, validated, and then thrown away — the worst kind of
  failure.** The main reverse-proxy route had `CompiledUpstreamTls` all along, but
  an inline subrequest (the shape `forward_auth` compiles into) goes through a
  different prepared shape, and the `None` in `build_http_peer(..., None)` was the
  whole defect. The operator wrote `trusted_ca_certs`, the configuration passed,
  and the dial used the system trust pool. 📌 The test is identical to K3's mTLS one
  and to SEC-004's `enabled`, making this the third occurrence: **when adding any
  security switch, find the line that actually enforces it.** If you cannot find
  it, do not accept the setting.

- 🛡️ **Move the fail-closed path across too, not just the happy path.**
  `RouteUpstreamTls::Broken` exists to say "the configuration demands a pinned
  private CA and the material will not load, so do not dial" — and a subrequest
  needs it more, because the answer from that `forward_auth` connection **decides
  whether the request is allowed through**. So subrequests share `RouteUpstreamTls`
  directly rather than carrying their own `Option`: with three states
  (Default/Compiled/Broken), dropping one turns into a silent downgrade.

- 🎯 **A prepared plan's match conditions must include every field that makes two
  exchanges different.** `matches_reverse_proxy` did not compare `upstream_tls`, so
  two subrequests on the same route differing only in trust material both matched
  the first plan, and the second dialled under the first one's policy. ⚠️ **No test
  catches this naturally**, because using the wrong plan still "works".

- 🧾 **The DSL cannot express this, and that itself is a gap.** Caddyfile's
  `forward_auth` accepts only `uri` and `copy_headers`; every other subdirective is
  an `UnknownDirective`. So the exposure here is JSON and Admin only.
  🎯 It **fails closed** (rejects) rather than ignoring silently, which makes it a
  missing feature rather than a second defect — but "the internal auth service sits
  behind a private CA" is a thoroughly ordinary shape and should be supported.
  📌 The tests therefore have to use JSON. The house rule is that "I could only do
  this in JSON" counts as a finding rather than a workaround; this is that finding,
  recorded in TRIAGE.
