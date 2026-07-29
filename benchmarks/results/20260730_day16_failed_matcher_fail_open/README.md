# Day 16 — two findings, both from searching rather than bumping into

Commit `3119aa4`. Found by `pingclair-config/tests/malformed_config.rs`, which
exists precisely because every previous defect of this class was luck.

## 1. A typo in a matcher name makes the route match everything

**Severity: an access restriction inverts, and the configuration validates.**

```pingclair-broken
:8080 {
	@admin_only path /admin/*
	handle @admin_onlyy { respond "SECRET" 200 }
	respond "public"
}
```

One extra character. `pingclair validate` says:

```
✅ Configuration is valid!
```

And at runtime every path serves the restricted response:

```
GET /                → SECRET
GET /admin/x         → SECRET
GET /anything-at-all → SECRET
```

`compile_matcher()` resolves `Matcher::Named` against the defined set and, when
the name is absent, falls through to

```rust
CoreMatcher::Path { patterns: vec!["/*".to_string()] }
```

with a comment noting the author was unsure what else to return. `/*` matches
every request, so an unresolved name does not disable the route — it opens it.

This is the same shape as `encode gzipp` and the global block swallowing
unknown directives, both already fixed, but the consequence is worse. Those
silently dropped a setting. This one silently replaces a restriction with its
opposite.

## 2. Nested matchers overflow the stack

**Severity: `pingclair validate` on an untrusted file aborts the process.**

```
depth   100  → ✅ valid
depth   500  → ✅ valid
depth  1000  → ✅ valid
depth  2000  → ✅ valid          ← accepted, which is also wrong
depth  5000  → fatal runtime error: stack overflow, aborting
```

`parse_single_matcher()` recurses on `not` and `compile_matcher()` recurses over
the resulting tree; neither is bounded. Block nesting *is* bounded, at 100
(`parser.rs:188`) — matcher nesting was simply never given the same treatment.

Release builds set `panic = "abort"`, so this is not a caught error.

**The JSON path is not affected.** Tagging the matcher representation on Day 6
means `serde_json`'s own recursion limit catches the equivalent document, which
was checked separately and passes. This one is reachable through the DSL only —
`pingclair validate` and `pingclair run` — which is still the command an
operator points at a configuration they did not write.
