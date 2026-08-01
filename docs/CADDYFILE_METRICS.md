# Metrics 需求文檔（對照 Caddy Monitoring with metrics）

> 📌 本專項以 Caddy 官方文檔（`docs/metrics`，本機
> `~/code/caddy-website`）為基準，對照 Pingclair 的
> `pingclair-proxy/src/metrics.rs`。

## 1. Caddy 官方語義（需求基準）

- 啟用：global `{ metrics }`（Caddyfile）或 JSON 的
  `"metrics": {}`；**不啟用就沒有 /metrics 成本**；
- `per_host`：HTTP(S) server 的 host 標籤；`observe_catchall_hosts`
  才觀察未設定 host（避免 infinite cardinality）；
- 輸出：admin API `/metrics`（Prometheus text / OpenMetrics 協商）；
  `metrics` directive 可另掛 port/path；
- OTLP push（`{ metrics { otlp } }`，`OTEL_*` env 設定）；
- 四類指標：

| 類別 | 前綴 | 內容 |
|---|---|---|
| Runtime | `go_*`／`process_*` | Go/process collector |
| Admin API | `caddy_admin_*` | 各 admin endpoint 的 request/error 計數 |
| HTTP middleware | `caddy_http_*` | in_flight、requests_total、request_errors_total、request_duration、request_size、response_size、response_duration（TTFB）——labels: server/handler/code/method |
| Reverse proxy | `caddy_reverse_proxy_upstreams_healthy` | 每 upstream 健康 gauge |

## 2. Pingclair 現況

`pingclair-proxy/src/metrics.rs`（9 個 metric family）：

| Metric | 型別 | labels | 備註 |
|---|---|---|---|
| `pingclair_requests_total` | counter | method/status/host | server.rs :4347 有打點 |
| `pingclair_request_duration_seconds` | histogram | method/status/host | server.rs :4351 |
| `pingclair_active_connections` | **counter** | host | **沒有任何人呼叫**（grep 只有定義處）；名字像 gauge |
| `pingclair_overload_rejections_total` | counter | host/route/reason | overload.rs ✅ |
| `pingclair_route_in_flight` / `route_pending` | gauge | host/route | overload.rs ✅ |
| `pingclair_upstream_in_flight` | gauge | host/route/upstream | overload.rs ✅ |
| `pingclair_circuit_transitions_total` / `circuit_state` | counter/gauge | 含 upstream | overload.rs ✅ |

暴露：admin API `GET /metrics`（固定存在）；`TextEncoder`，無
OpenMetrics 協商。

## 3. 已確認缺口

### 🟠 MT-1：`{ metrics }` global option 不存在，metrics 恆常啟用

Caddy 用 `{ metrics }` 開關（不開就沒有 /metrics）。Pingclair：

- `adapt_global` 對 `metrics` 回 `Unknown directive 'global: metrics'`
  （global options 文檔 G8 已列）；
- `main.rs` 啟動時無條件 `pingclair_proxy::metrics::init()`；
  admin `/metrics` 恆常暴露。

需求：實作 `{ metrics }`／`{ metrics { per_host } }`（JSON 對應
`"metrics"`），預設關閉或至少文件化「恆開」的決定。

### 🟠 MT-2：缺 runtime 指標（`go_*`／`process_*` 對應物）

`prometheus` crate 有 `process_collector`／`rust_collector`，但
Pingclair 的 REGISTRY 只註冊 9 個自訂 family——沒有 process
（RSS/VMS/CPU）或 runtime（GC/goroutine 對應）指標。查記憶體與
GC 行為只能靠外部工具。

### 🟠 MT-3：缺 admin API 指標

Caddy 的 `caddy_admin_http_requests_total`（code/handler/method/
path）與 errors counter 可監控 admin 端點使用量與錯誤。Pingclair
的 admin server（pingclair-api）完全沒有打點。

### 🟠 MT-4：HTTP 指標覆蓋不足

| Caddy | Pingclair |
|---|---|
| requests_total（server/handler/method/code） | ✅ 類似（method/status/host，無 server/handler） |
| request_duration histogram | ✅ 類似 |
| request_size_bytes histogram | ❌ |
| response_size_bytes histogram | ❌ |
| response_duration（TTFB）histogram | ❌ |
| request_errors_total counter | ❌ |
| requests_in_flight gauge | ❌ |

且 Pingclair 的 labels 用 `status`（Caddy 是 `code`）、`host`（Caddy
是 `server`/`handler`）——**不能直接套 Caddy 的 sample queries**
（`rate(caddy_http_requests_total{handler="file_server"}[5m])`），
遷移監控告警要改 query。若目標是 Caddy 相容，指標名與 labels 應
對齊或另給 alias。

### 🟠 MT-5：缺 reverse proxy upstream health gauge

Caddy 的 `caddy_reverse_proxy_upstreams_healthy`（0/1 per upstream）
是「後端健康」最直接的指標。Pingclair 有
`upstream_in_flight`／`circuit_state`（更細），但沒有「upstream
健康/可用」的 0/1 gauge；`BackendHealth`（load_balancer.rs）有
資料但沒暴露（admin 文檔 A10 同一根因）。

### 🟡 MT-6：`ACTIVE_CONNECTIONS` 是死指標且型別錯誤

`pingclair_active_connections` 宣告成 `IntCounterVec`、名字是
「active」、全 codebase 無人呼叫。Caddy 對應物是 in-flight gauge。
需求：改成 `IntGaugeVec` 並在 accept/release 處打點，或刪除。

### 🟡 MT-7：缺 OpenMetrics 協商與 OTLP push

- `TextEncoder` 固定回 text；Caddy 依 `Accept:
  application/openmetrics-text` 回 OpenMetrics；
- `{ metrics { otlp } }` 與 `OTEL_*` env 的 OTLP exporter 不存在
  （global options 文檔 G8 已列 `metrics` 為不支援）。

## 4. 驗證需求

1. `{ metrics }` 編譯（現況報錯）；`{ metrics { per_host
   observe_catchall_hosts } }` 語法；
2. `/metrics` 輸出含 process/runtime 指標；
3. `requests_total`／`duration` 在真 binary 請求後出現；
   `active_connections` 是 gauge 且會增減；
4. upstream health gauge 隨 `BackendHealth` 變化；
5. admin endpoint 打點後 `GET /metrics` 看得到 admin 計數；
6. 若宣稱 Caddy 相容，指標名/labels 對齊或文件化映射。

## 5. 明確不做（本文件範圍外）

- OTLP exporter 完整實作——列 v0.3（`opentelemetry` SDK 依賴重）。
- `metrics` directive（另掛 port/path 的 handler）——列 v0.3。
- per_host cardinality 保護策略——隨 `{ metrics }` 一起設計。
