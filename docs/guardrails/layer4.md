# 🔌 Layer 4 implementation boundaries

The 0.3 alpha branch routes raw TCP using complete TLS ClientHello metadata
and peer addresses. TLS remains end to end. Issue #183 provides background;
nginx source and tested behavior decide semantics when early issue prose differs.

## 🧭 Ownership

- `pingclair-core::config` owns the shared, strict declaration schema.
- `pingclair-config` owns syntax conversion and common validation.
- L4 transport belongs in a separate `pingclair-l4` crate, without an HTTP
  proxy dependency. Precompute routes and peer networks when provisioning.
- Keep one immutable snapshot per connection. The top-level `pingclair` runtime
  owns prebound Pingora listeners, effective HTTP/Admin overlap checks, route
  publication and shutdown drain. Blocked peers are refused before preread.
- Route reloads affect new connections; listener topology or limits require
  restart. Failed preparation publishes nothing. Static upstream names resolve
  at load/reload, without periodic DNS refresh or health checking.
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

## 🔌 Minimal TCP configuration

```caddyfile
{
    layer4 {
        :9443 {
            @secure tls sni example.test
            route @secure {
                proxy 127.0.0.1:8443
            }
            route {
                proxy 127.0.0.1:8080
            }
        }
    }
}
```

Matchers within a set use AND; values within a field and alternative matcher
sets use OR. Routes use declaration order. SNI is an exact ASCII name compared
without case; ALPN identifiers are case-sensitive. No match closes the stream.
Non-TLS input may use the unconditional final route. A listener with no TLS
matcher connects without preread, including server-first protocols.

Defaults are `preread_timeout 30s`, `preread_buffer_size 16k`,
`proxy_connect_timeout 60s`, `proxy_timeout 600s`, `proxy_buffer_size 16k`,
and `proxy_half_close off`. Two buffers bound forwarding memory; the preread
prefix may retain its configured capacity. Global HTTP listener options do not
configure these raw TCP services. There is no UDP, TLS termination, PROXY
protocol, wildcard SNI, load balancing or dynamic DNS in this alpha.
