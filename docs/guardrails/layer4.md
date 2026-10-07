# 🔌 Layer 4 implementation boundaries

The configuration library adapts declarations. CLI adaptation and runtime
loading still refuse them through common validation.
Outstanding implementation remains tracked in GitHub issue #183.

## 🧭 Ownership

- `pingclair-core::config` owns the shared, strict declaration schema.
- `pingclair-config` owns syntax conversion and common validation.
- L4 transport belongs in a separate `pingclair-l4` crate, without an HTTP
  proxy dependency. Precompute routes and peer networks when provisioning.
- Keep one immutable snapshot per connection. Integrate listener ownership,
  automatic HTTP companions, reload, shutdown drain and blocked peers before
  removing the common validation gate. Explicit HTTP/L4 overlaps already fail.
- Extract shared runtime infrastructure only when a concrete consumer needs it.

## 🔬 Reference evidence, 2026-10-07

nginx revision `2b5c2b605b5df669da5dec6749dcc76c07d1315d` is the semantic
reference. Caddy supplies block and named-matcher syntax only.

- `ngx_stream_core_preread_phase` finalizes on timeout with `NGX_STREAM_OK`;
  that status is not `NGX_OK`, which advances the phase. Timeout is not fallback.
- `ngx_stream_ssl_preread_handler` declines non-TLS and some malformed inputs;
  do not assume every parse failure means nginx closes the connection. Preserve
  this distinction when defining and testing the classifier outcomes.
- `ngx_parse_size` uses binary k/m units. Millisecond `ngx_parse_time` uses
  seconds for bare integers, permits zero and rejects month/year units.
- `proxy_timeout` bounds inactivity, not total connection lifetime. Relay EOF
  handling must drain buffered bytes before finalization or half-close.

Sources: [stream core](https://github.com/nginx/nginx/blob/2b5c2b605b5df669da5dec6749dcc76c07d1315d/src/stream/ngx_stream_core_module.c),
[TLS preread](https://github.com/nginx/nginx/blob/2b5c2b605b5df669da5dec6749dcc76c07d1315d/src/stream/ngx_stream_ssl_preread_module.c),
[numeric parsing](https://github.com/nginx/nginx/blob/2b5c2b605b5df669da5dec6749dcc76c07d1315d/src/core/ngx_parse.c),
[proxy](https://nginx.org/en/docs/stream/ngx_stream_proxy_module.html),
[Caddy syntax](https://github.com/mholt/caddy-l4/blob/master/layer4/caddyfile.go).
