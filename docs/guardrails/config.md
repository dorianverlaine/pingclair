# ⚠️ Pingclair implementation guardrails — configuration and compatibility

## 🔐 Control-plane publication

- **Admin and signal must decide configuration ownership inside the same
  publication lock.** Do not wait for the `/load` handler to receive the
  publisher's success and then mark `api_changed` outside the lock: SIGUSR1 may
  already have passed the outer check and be queued behind the lock, and it will
  then overwrite the Admin transaction that just succeeded with the stale API key
  and routes still sitting on disk. Admin publication must commit its ownership
  marker before it releases the lock, and the signal path must re-check after it
  acquires that same lock rather than trusting the signal loop's fast path.

  > 🎯 **The operable rule**: any state that decides *whether the next writer is
  > still allowed to write* gets committed together with the snapshot it
  > protects. Never record it after the caller has been told "success".

## 🚪 Which layer validation belongs in (2026-08-18)

> 🧭 This section originally lived only in `docs/guardrails/tls.md`. Anyone about
> to touch the compiler reads `config.md` first, and so never reached the rule
> that a rule written in the adapter is a rule the Admin API walks straight past
> — which happens to be **the single easiest one to break again**. So it lives
> here now.

- **A rule written in the adapter is a rule the Admin API walks straight past.**
  A Pingclairfile goes `parser/` → `adapter/caddyfile.rs` → `compiler.rs`. JSON
  configuration — including a document pasted in through the Admin API's
  `POST /load` — **skips the adapter entirely** and lands directly in
  `compiler.rs`. So anything rejected only in the adapter gets in the moment
  somebody writes it as JSON.

  > 🎯 **The operable rule**: if a rule is **about security**, it belongs in
  > `validate_config`; only **syntax and spelling** stay in the adapter. The test
  > is one question: **"if somebody routes around this with JSON, is that a
  > security problem?"** If yes, the adapter alone is not enough.

  🤡 This is not theoretical. SEC-002 was exactly this: misspell an mTLS field
  name in JSON, serde ignores it in silence, and "verified mTLS" quietly degrades
  to "a certificate is requested" — because the check only existed in the
  adapter. The fix was `deny_unknown_fields` on the type itself, which is
  **the layer both paths share**.

- **Configuration that cannot be honoured fails closed, and it fails in
  `validate_config`.** Accepting a knob that nothing reads at runtime is not
  compatibility, it is a lie — the only variable is how long it takes the
  operator to find out.

  > 🎯 **The operable rule**: if you accept a setting, use it at runtime. If you
  > cannot, reject it at load time with a message that says **why this build
  > cannot do it**. A warning line at startup **does not count** — that line is
  > buried in the boot log while the setting is still written down and still
  > looks like it took effect.

  📌 Three cases went this way on 2026-08-18: `preferred_chains` (the ACME client
  cannot ask for an alternate chain), twelve `transport http` knobs (concepts
  from Go's `http.Transport` with no same-layer equivalent in this build's
  upstream stack), and an invalid `admin.listen` (which used to panic on the
  startup thread). All three are breaking changes, and that is the point: the
  other option is a server that reports success and does something else.

  ⚠️ **An approximation is worse than a gap.** `read_buffer` is the size of a Go
  `bufio`; `PeerOptions::tcp_recv_buf` is a socket option. The names rhyme, the
  layers do not. Wiring one to the other changes behaviour under the banner of
  "compatibility", which is considerably worse than saying "we cannot do this".

- **Two spellings of one setting must converge in one place.** When the same
  thing can be written two ways, make one spelling an entry point into the other.
  Never let two paths interpret it independently.

  > 🎯 **The operable rule**: before you add the second spelling, ask "at which
  > line do these two merge?" If you cannot answer, the design is not finished.

  📌 Example: `versions 2` and `h2c://` both mean prior-knowledge h2. The
  implementation lets only the scheme decide the pool group, and `versions` goes
  through the same `set_http_version` — so it is not possible for the two to
  disagree about whether a connection may be reused.

## 📏 Measurement and verification

> 🧭 This whole section comes out of M4.5 on 2026-08-05. That day produced nine
> instances of "I thought I had measured a defect in the product, and I had
> measured my own tooling", plus three instances of "once the measurement was
> fixed, a real defect surfaced underneath". What the rules share is this:
> **doubt the method before you doubt the thing being measured.**

- **A broken measuring tool disguises itself as a broken product, and it looks
  worse than the real thing.** Nine times in one day on 2026-08-05: the corpus
  harness counted "expected to be rejected" as a failure (producing a fake 12%
  coverage number); the harness resolved relative `import` from the wrong working
  directory (so the corpus's `testdata/` was never found); the bcrypt hash used
  for comparison was invalid (so "the reference implementation rejects it too"
  got read as agreement); and nested `printf` ate the quotes, generating syntax
  the reference implementation would not accept.

  > 🎯 **The operable rule**: when it goes red, ask "is the test wrong?" first.
  > A differential test produces **false victories** as readily as false
  > failures, and both need investigating.

- **Fixing the measurement surfaces the defects it was hiding — that is not a
  regression.** Three times the same day: once classification was fixed, four
  corpus files went from green to red and exposed **three address checks that had
  never existed** (port > 65535, unknown scheme, `ws://`); once the harness's path
  handling was fixed, one false pass turned out to be sitting on a fail-open
  where an `import name { … }` **block was being dropped whole**.

  > 🎯 **The operable rule**: a red light that appears after you fix the
  > measurement is **a discovery until proven otherwise**, not a regression.
  > Trace each one to its source before deciding.

- **"It compiled" cannot tell correct compilation apart from a quiet
  misreading.** On 2026-08-05 four configurations that had been silently
  miscompiled were rejected. The corpus score **dropped by 3** while the
  behaviour got better.

  > 🎯 **The operable rule**: pure refactors and compatibility work get compared
  > byte for byte against **actual output** (the goldens in
  > `pingclair-config/tests/fixtures/`), not just "all four gates are green".
  > This repository has staged "compiles but means the wrong thing" twice.

- **The type exists ≠ the feature exists ≠ the feature is reachable.**
  `HandlerConfig::HandleErrors` existed while all three paths did nothing (the
  core returned 200, the proxy returned `Ok(false)`). `HandlePath` was the
  reverse — both serving paths had always worked and only one adapter arm was
  missing.

  > 🎯 **The operable rule**: decide "is this implemented?" by **reading the
  > function body**, not by counting match arms and not by checking whether a
  > type exists. Ten minutes after writing this rule into this very document on
  > 2026-08-05, I reached another conclusion by counting arms, and it was wrong.

- **"Cheap to implement" and "cheap points" are different things.** Twice in one
  day, cost was estimated from the **string prefix of an error message** and both
  estimates were wrong: "invalid argument" covered both "our rule is wrong" and
  "this feature does not exist", and wiring up `header_regexp` needed only one
  arm, but all three corpus files using it wanted the named form with capture
  placeholders, so the score did not move at all.

  > 🎯 **The operable rule**: before you prioritise, **open the actual input and
  > look at it**. Do not infer cost from how an error message is categorised.

- **Before you remove a guardrail, find out what it was holding back.** When the
  old recursive-descent parser was deleted on 2026-08-05, its nesting-depth limit
  went with it, and the guardrail test **blew the stack and aborted** — which
  under the release profile means the whole process disappears, and the admin API
  is an externally reachable path into that code.

  > 🎯 **The operable rule**: when deleting an implementation, ask which limits
  > were attached to it that have nothing to do with its main job. "The guardrail
  > left with the old implementation" is far harder to notice than "the guardrail
  > was deliberately removed".

- **When a comment and the implementation disagree, the comment does not raise
  its hand.** The cursor's text accessor returned the *name inside* `{host}`,
  while the doc comment directly above it said placeholders keep their braces.
  Wire that up and `header_up X-Host {host}` forever sends four characters,
  `host`, upstream.

  > 🎯 **The operable rule**: when you change a function that carries a doc
  > comment, read the comment as **an assertion** and check it.

- **Both directions of one rule go in together, or only one of them gets
  implemented.** The lexer was right about `www.{host}` (the word scanner pulls
  the trailing placeholder in) and wrong about `{host}/x` (a leading placeholder
  was emitted as a token and scanning stopped). Same file, same "text glued to a
  placeholder belongs to the same word" rule, two directions implemented
  separately — so only one of them was alive. The cost: `redir {host}/moved 302`
  (a legal Caddyfile) was rejected, while `try_files {path} {path}/ …`
  **silently** grew an extra `/` candidate that matches the site root on every
  request — which looks exactly like normal operation.

  > 🎯 **The operable rule**: when implementing "X and Y adjacent count as one
  > thing", both directions go through **the same code or the same constant**.
  > The 2026-08-07 fix extracted `ENDS_A_WORD` for both call sites rather than
  > writing a second character set at the second one.

- **A stopgap disappears together with the thing it was stopping.** Before the
  defect above was fixed, the compiler carried a rule rejecting the `/` candidate
  so the silent error would at least be a loud one. Once the defect was fixed
  that rule became "reject a legal configuration the reference implementation
  accepts" — keeping it is not caution, it is manufacturing a compatibility
  difference nobody can explain.

  > 🎯 **The operable rule**: a stopgap's comment says **what it is waiting for**,
  > and the stopgap is deleted in the same commit that removes that reason.

- **Two spellings of one setting must not accept two ranges of values.**
  `health_check { interval 10s }` takes whole seconds; the first version of the
  new flat `health_interval 10s` read it as milliseconds — a probe interval of
  ten thousand seconds.

  > 🎯 **The operable rule**: when adding an alias or a flattened spelling, both
  > sides go through **the same parsing helper**. Neither calls the primitive
  > directly.

- **A "shorthand" directive expands into the thing it is shorthand for. You do
  not write a second implementation.** Upstream, `try_files` is not a handler; it
  is shorthand for a `file` matcher plus a rewrite. This repository first wrote a
  standalone `resolve_try_files` and later implemented the `file` matcher, so
  "find the first candidate that exists" had two implementations — and they
  disagreed about all five selection policies, the `=404` candidate, globs, and
  every placeholder except `{path}`. The two never had a drift problem because
  **they were never in sync to begin with**: the weaker one had written its own
  gaps into the configuration layer's rejection list, which made the gaps look
  like design.

  > 🎯 **The operable rule**: when the adapter meets a directive upstream openly
  > calls a shorthand (`try_files`, `php_fastcgi`, `forward_auth`), go read what
  > upstream expands it into, then expand into the same thing. Writing a separate
  > runtime implementation requires first writing down why that expansion does
  > not work here.

- **A validation rule attaches to the type that does the work, not to whichever
  type happened to call it first.** The `..` and placeholder checks on `try_files`
  candidates only ever ran for `HandlerConfig::TryFiles`. Once `try_files` was
  changed to expand into a `file` matcher, not one of those checks fired again —
  and `Matcher::File`, which `php_fastcgi` had been producing all along, had
  never been checked at all.

  > 🎯 **The operable rule**: when you change which type a directive compiles
  > into, **move its validation with it**, and while you are there ask whether
  > the paths that already produced the new type were missing those checks too.

- **Whether a directive's first argument is a matcher is a question for
  upstream's registration, not for intuition.** Upstream registers `try_files`
  with `RegisterDirective` (not `RegisterHandlerDirective`), and its own comment
  reads "notice no matcher tokens accepted" — so every argument is a candidate.
  This repository treated the first argument beginning with `/` as an inline path
  matcher, so `try_files /a.html /b.html` became "only on the path `/a.html`, try
  only `/b.html`" and dragged the rest of the site's handlers under that matcher
  too. It compiled, and it did something the operator never wrote.
  `try_files /index.html` on its own failed closed — which is how the defect was
  found.

  > 🎯 **The operable rule**: a new entry in `first_argument_is_data` cites
  > upstream's **registration function** as its justification, never what some
  > configuration happens to look like.

## 📁 A `file_server` index is an untrusted path component too (2026-08-17)

- 💀 **`Path::join` given an absolute path *replaces* rather than extends.**
  `root.join("/etc/passwd")` == `/etc/passwd`; the root is discarded entirely.
  This is not a Rust quirk — every mainstream path API shares the semantics — but
  it turns "the configuration has a typo" into "we escaped the root" instead of
  "no such file". ⚠️ **Nothing at the call site shows it**, so it has to be caught
  at load time.

- 🎯 **"The request path is untrusted" is not the same as "the resolved path is
  safe".** The request path already had lexical confinement; the index is joined
  on **afterwards**, which made it the last unchecked component on the whole
  path. The test: **ask how many sources this path is assembled from**, not
  "is the untrusted one handled". Two sources (request path, configured index)
  means two checks.

- 🛡️ **Do both layers, and the second must not depend on the first having run.**
  Rejecting at load time (absolute paths, `..`, backslash, colon, empty string)
  is the layer the operator sees; feeding the index back through `resolve_path`
  for the same confinement at runtime is the second. 📌 The tests therefore
  **construct `FileServerConfig` directly in code** to bypass validation — you
  cannot reach the second layer through "the configuration was rejected", and a
  second layer that only holds when the first one ran is not a second layer.

- 🙈 **The `hide` and regular-file checks move with it.** The `hide` check applied
  only to the resolved request path and was not re-run after the index was
  chosen, so an index could name a file the operator had explicitly hidden. And
  `exists()` is true for directories — a directory would be accepted as an index
  and then read as a file, with the failure surfacing a long way from the
  decision. Use `is_file()`.

- 🧭 **The validation goes in `validate_config`, not only in the adapter.** The
  Admin API deserialises straight into the canonical types with no adapter
  involved. This repository has already paid for this rule twice (see the secure
  defaults section).

## 🙈 Secrets landing on disk and in logs (2026-08-17)

- 💀 **`std::fs::write` creates files as `0666 & !umask`, which normally lands on
  `0644`.** So for anything containing a secret, "just write a file" defaults to
  **readable by everyone on the box**. Two things were caught by this: the Admin
  autosave document (carrying the admin key and DNS credentials) and the
  `storage-export` archive (carrying the internal CA private key, every
  certificate's private key, and the ACME account key). 🎯 The test: **ask what
  happens if another user on this machine reads this file**, not "does this code
  have a bug".

- 🛡️ **Create at 0600; do not create and then chmod.** Create-then-chmod leaves a
  window in which another user can `open()` the file, and **the descriptor keeps
  reading after the mode changes**. `OpenOptions::mode(0o600)` is the correct
  form. ⚠️ Note that `mode` **applies only on creation** — overwriting an existing
  `0644` file keeps `0644`. `storage-export` warns in that case rather than
  accepting it silently.

- 🧬 **One atomic writer, not a second one.** `pingclair-tls::secure_file` already
  did five things right: a unique temporary name, created at 0600, `sync_all`,
  rename, and fsync of the parent directory. Autosave did not use it — it called
  `fs::write` with a **fixed** `<path>.tmp` (two writers collide) and never
  fsynced at all. 📌 This is the same class as the SEC-006 lesson: **a security
  rule written down a second time is a second chance to leave a step out.** The
  writer now lives in `pingclair-tls` (core depends on it; the reverse would
  cycle) and is re-exported as `pingclair_core::secure_file` for the crates above.

- 🙈 **Wrap secrets, because the `{:?}` that leaks one is never written next to
  the secret.** The entire value of `SecretString` is its `Debug`. A `String`
  secret inside a type that derives `Debug` is one `{:?}` away from a log line —
  and that `{:?}` can be **anywhere, on any type that contains it**, panic
  messages included. 🎯 `Display` and `AsRef<str>` are deliberately **not**
  implemented: either one lets it be formatted by accident. Getting the value
  requires `.expose()`, which is a greppable word — `rg 'expose\(\)'` is the audit
  list. 🧭 It is `serde(transparent)`, so the wire format is unchanged and old
  configurations still load and round-trip. **This rule is about what reaches the
  log, not about what reaches the disk** — that is the rule above.
  📌 `dns01::cloudflare::ApiToken` already used this pattern, so this is not an
  invention; it is an existing practice applied to the two fields that were
  missing it.
