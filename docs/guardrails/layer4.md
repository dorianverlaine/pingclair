# 🔌 Layer 4 implementation boundaries

The 0.3 line on `main` routes raw TCP using complete TLS ClientHello metadata
and peer addresses. TLS remains end to end. Issue #183 provides background;
nginx source and tested behavior decide semantics when early issue prose differs.

## 🧭 Ownership

- `pingclair-core::config` owns the shared, strict declaration schema.
- `pingclair-config` owns syntax conversion and common validation.
- L4 transport belongs in a separate `pingclair-l4` crate, without an HTTP
  proxy dependency. Precompute routes and peer networks when provisioning.
- Keep one immutable snapshot per connection. The top-level `pingclair` runtime
  owns prebound TCP listeners registered as Pingora services, effective HTTP/Admin overlap checks, route
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
protocol, wildcard SNI or weighted balancing in this alpha.

## 🌐 Explicit dynamic DNS sources

Native TCP routes select exactly one `to:` or `dynamic:` source:

```swift
TCPListener(on: ":9443") {
    Route(when: .tls(sni: ["local.example.test"])) {
        Proxy(to: "127.0.0.1:8443")
    }
    Fallback {
        Proxy(dynamic: .a("backend.example.test", port: 443, versions: .ip,
            valid: .seconds(30), stale: .seconds(60)))
    }
}
```

The equivalent Caddy-style source is:

```caddyfile
{
    layer4 {
        :9443 {
            @local tls sni local.example.test
            route @local {
                proxy 127.0.0.1:8443
            }
            route {
                proxy {
                    dynamic a {
                        name backend.example.test
                        port 443
                        versions ip
                        valid 30s
                        stale 60s
                    }
                }
            }
        }
    }
}
```

The source requires a fixed ASCII DNS name and nonzero port. `versions` accepts
`ipv4`, `ipv6` or `ip` (both, the default); native cases have a leading dot.
Omitting `valid` preserves the minimum answer and CNAME TTL, including zero.
An explicit positive `valid` overrides freshness. `stale` adds at most 300 seconds
to that freshness deadline and defaults to 60 seconds; transient errors cannot
move either deadline. Empty answers, NXDOMAIN, oversized answers and forbidden
destinations revoke the whole pool. DNS unavailability refuses new connections
to that route without delaying startup or affecting other routes and live tunnels.

Optional `resolvers` accepts one through four numeric IP or IP:port endpoints
(port 53 when omitted); otherwise the operating system resolver configuration
is used without a public fallback.
DNS jobs bypass search domains and caches. Up to 256 distinct complete source
policies share one coordinator, with at most eight jobs across active and retired
generations, one job per pool and at least one second between starts. A job has
one five-second deadline, at most eight CNAME hops and 64 unique addresses.
Transient errors back off with bounded jitter. Truncated UDP replies use TCP.

By default, only public destinations are allowed. A nonempty native
`allowIP: ["10.0.0.0/8"]` or Caddy `allow_ip 10.0.0.0/8` explicitly permits
listed non-public ranges. Loopback and link-local access require CIDRs confined
to those classes; a broad CIDR cannot grant them incidentally. Unspecified,
multicast and known local HTTP, L4 or Admin destinations remain forbidden.
Wildcard listener policy includes local interface addresses enumerated during
preparation. Address policy rejects the entire answer if any address is forbidden.
Changing resolver, lifetime, family or destination policy cannot reuse an old
snapshot. Failed reload preparation leaves the published configuration intact.

L4 sources support A/AAAA only. HTTP `refresh`, `grace`, `dialTimeout` and SRV
options are refused here; listener connect timeouts own the dial budget.


## 📊 Connection observability

The shared `pingclair-runtime` registry and access-log writer serve both HTTP
and TCP. L4 owns its counters and session outcomes; it never imports the HTTP
proxy. Metric handles and logging policy are prepared before accepting traffic.
The forwarding loop neither builds labels nor formats logs. Disabling logs
removes their per-I/O byte accounting through compile-time specialization;
disabling both logs and metrics also skips observation clock reads. Route-only
reloads reuse unchanged loggers, including their writer and sampling window.

```caddyfile
{
    auto_https off
    metrics
    layer4 {
        :9443 {
            log {
                output file ./l4-access.log
                format json
            }
            route {
                proxy 127.0.0.1:8443
            }
        }
    }
}
http://127.0.0.1:9090 {
    metrics /metrics
}
```

`metrics` uses the existing collection switch and scrape endpoint. Each
connection captures that switch at admission, so an existing connection can
finish its accounting after collection is disabled by reload. No client IP,
SNI, ALPN or resolved upstream address becomes a metric label. Listener labels
are normalized configured addresses; route labels are one-based declaration
ordinals, with `none` before selection. Counters are process-lifetime history,
so changing what a route ordinal means does not reset its accumulated values.

| Metric | Additional labels | Meaning |
| --- | --- | --- |
| `l4_connections_total` | `route`, `outcome` | Sessions that have ended, including cancellation |
| `l4_active_connections` | None | Accepted sessions still in progress |
| `l4_bytes_total` | `direction` | Successful destination writes, visible before EOF |
| `l4_connection_duration_seconds` | None | Session lifetime histogram, including preread and connect |
| `l4_preread_failures_total` | `reason` | Timeout, overflow, I/O error or declined TLS-shaped input |
| `l4_upstream_connect_failures_total` | `reason` | Failed session dials, classified as timeout or I/O error |
| `l4_upstream_connect_attempts_total` | `route` | Address attempts started by static or dynamic routes, including fallback |
| `l4_dns_refreshes_total` | `route`, `reason` | Completed or retired DNS jobs observed by that route |
| `l4_dns_pool_available` | `route` | A usable DNS snapshot exists before its hard deadline |

Every family also has a `listener` label. Byte directions are
`client_to_upstream` and `upstream_to_client`; replayed preread bytes count once,
when written upstream. `declined_tls` is a diagnostic, not necessarily a rejected
connection: unsupported or malformed TLS-shaped input may still use a non-TLS
route. It does not claim that every declined input is malformed.

DNS refresh reasons are `available`, `empty`, `nxdomain`, `transient`, `timeout`,
`invalid` and `cancelled`. Identical full source policies may share a DNS job;
each configured route observes its result. `available` means a valid answer was
published, while a transient failure may leave a stale snapshot usable. The
availability gauge expires without client traffic and becomes zero when its
source is removed or shutdown begins. Preparing a failed reload cannot clear
the published gauge. DNS names, resolved addresses and generations are never
labels. Counters follow the collection switch; availability represents current
published state. Removed route series remain at zero availability, with their
process-lifetime counter history preserved.

Access logging is off unless the listener declares `log`. Bare `log` uses text
on stdout; a block uses the existing output, format, field deletion, sampling
and rotation syntax. This alpha supports one unnamed logger per L4 listener;
named global channel references are rejected. The namespace is
`layer4.log.access`. HTTP headers, hostname selection, negotiated TLS fields and
levels other than `info` are rejected by common validation, including JSON loads.
Changing a logger affects new sessions; established sessions retain the old one.
A configured destination that cannot be opened rejects startup or reload.

JSON records contain `ts` (session start), `protocol`, `listener`, `remote_addr`,
`remote_port`, `route` when selected, `outcome`, `status`, `bytes_received`,
`bytes_sent`, `session_time`, `upstream_bytes_received` and `upstream_bytes_sent`.
A successful dial also provides `upstream_addr` and `upstream_connect_time`.
Durations use seconds. Received and sent byte fields describe actual successful
socket I/O, so bytes read but never forwarded can differ. Text uses the same
fields as escaped key/value pairs. Neither format records payloads or TLS names.
Sampling and a full queue may drop records; the shared
`pingclair_access_log_dropped_total` counts queue drops.

Status follows [nginx stream](https://nginx.org/en/docs/stream/ngx_stream_core_module.html#variables),
not HTTP responses on the TCP wire: `403` is a blocked peer, `400` is preread
overflow, `502` is no selected/reachable upstream, and `500` is cancellation or
an internal allocation failure. Normal completion, client EOF/I/O termination
and idle/preread timeout use `200`; the explicit `outcome` distinguishes them.
The meanings of session byte fields and durations follow
[nginx stream logging](https://nginx.org/en/docs/stream/ngx_stream_log_module.html).

## 🚦 Connection admission

`max_connections` accepts an integer from 1 through 4096 and defaults to 1024
per listener. A shared process ceiling of 4096 also applies. Both quotas cover
preread, upstream dialing and forwarding, and persist across route reloads.
Changing a listener quota requires restart. Excess accepted sockets close before
spawning a session task or allocating preread buffers; no permit wait queue exists.
The kernel accept backlog remains governed by the operating system.

L4 owns its TCP accept loop inside a Pingora service because Pingora 0.9.0
`services::listening::Service::run_endpoint` spawns before calling `ServerApp`.
Checking admission only in that callback would leave task creation unbounded.
Accept errors back off for one second, interruptible by shutdown. Accepted work
enters the shared drain counter before spawning; cancellation drops both permits.

`l4_admission_rejections_total{listener}` counts refusals when metrics are enabled.
These pre-session refusals do not produce access-log records or completed-session
metrics. Limits are session counts, not socket counts: an established tunnel uses
a downstream and an upstream socket. Deployment limits must fit the host's memory
and file descriptor budget; the defaults do not establish measured capacity.

## 🔁 Static address pools

A hostname still resolves at load or reload. Its compiled pool deduplicates and
sorts at most 64 addresses; an empty or larger pool rejects preparation. Each new
connection rotates its starting address using one atomic increment. A literal or
single-address pool bypasses that increment and keeps the configured total timeout.

For multiple addresses, each attempt has at most two seconds, bounded by the
remaining `proxy_connect_timeout` budget. A session tries at most four distinct
addresses from its pool. Refused connections, network failures and timeouts may
advance to the next address; local resource errors and unclassified failures stop
immediately. A zero total budget refuses the dial without opening an upstream socket.
These fixed alpha limits bound work; they are not nginx's unlimited retry defaults.
Local descriptor, memory/buffer and unavailable-address failures also produce
a process-wide warning at most once per 30 seconds. The warning uses a fixed
reason and OS error number, without a destination-derived metric label.

Selection returns once TCP connects. Even a server-first protocol or an immediate
post-connect reset cannot trigger replay to another peer. There is no passive
quarantine or active health checking, and no per-I/O selection work in the relay.

## 🌐 DNS dependency verification

The dynamic-upstream design requires asynchronous, cancelable DNS work before
new syntax can be exposed. Controlled wire tests in
`pingclair-l4/tests/resolver_contract.rs` exercise Hickory 0.26.3 without public
DNS, HTTP proxies, or the host's search domains.

The 2026-10-09 checks establish that `TokioResolver::lookup` preserves CNAME
records and their minimum TTL when `preserve_intermediates` is enabled, keeps
TTL zero, and makes fresh queries with `cache_size = 0`. `Ipv4Only` and
`Ipv6Only` issue only their selected family. Negative answers are distinguishable
from SERVFAIL, and a truncated UDP reply retries over TCP on the configured port.

Cancellation drops both the query and its scoped resolver. The TCP peer sees
EOF, and the runtime returns to its previous background-task count. Keeping a
resolver alive beyond a canceled job is outside that test's guarantee; scope
resolver ownership to the bounded job when using this evidence.

These dependency checks establish resolver behavior. Separate pool tests cover
address policy, deadlines, scheduler bounds and cancellation. Real-binary tests
in `pingclair/tests/integration/layer4_dynamic.rs` cover both DSLs, address updates,
reload, stale expiry, local route availability and TCP socket cleanup. They do
not establish Linux resource capacity. Static upstreams still resolve only at
load or reload.

## 🌐 Dynamic pool ownership

Dynamic preparation uses `DnsPreparation` and `PreparedListener::prepare_with_dns`.
It must receive every known local HTTP, TCP and Admin destination, including local
addresses covered by wildcard listeners. Failed preparation activates no work.
Publish the complete draft through the process-owned `DnsRuntime`; run its single
coordinator with the executable's shutdown future.

DNS jobs use Hickory's raw query interface so CNAME traversal has an explicit
eight-hop ceiling and A/AAAA share one five-second deadline. The task scope joins
transport workers before a normal or retired job releases its slot; dropping an
outer future still aborts that scope. Removed pools are revoked and canceled at
publication, with their draining jobs included in the eight-job process limit.

Address policy and deadlines apply before publication and every dial attempt.
Transient failures cannot extend the hard deadline; authoritative negatives and
invalid updates revoke the whole pool. Relay retains session logging and metrics
policy, but releases routing generations, pools and address snapshots after dial.
