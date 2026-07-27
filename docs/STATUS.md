# 📊 Pingclair 狀態表

> 這份文件記錄**已經做了什麼、驗證到什麼程度**，是證據存放處，不是計畫。
>
> - 接下來要做什麼 → `docs/TODO.md`
> - 環境限制與實作守則 → `docs/GUARDRAILS.md`
>
> 最後整理：2026-07-27

## 三種狀態的嚴格定義

功能「有程式碼」、「本機測試通過」與「Linux/VPS 實機驗證通過」是三件不同的事，
**不得混寫**：

| 標記 | 意義 |
|---|---|
| ✅ **完成** | 已在真實 Linux/VPS 以真 binary 驗證，且有結果或腳本可追溯。 |
| 🧪 **待遠端驗證** | 已實作並通過本機單元／整合測試，但**尚未**以目前版本在乾淨 Linux/VPS 驗證。 |
| ⬜ **未實作** | 功能或測試仍缺少。 |

> ⚠️ 已在**舊 commit** 驗證過的能力，仍須使用同一個 release-candidate commit
> 重新跑乾淨 Linux 驗證才能計入 v0.2。

---

## ✅ 已通過遠端驗證

### 2026-07-25 VPS 生產情境測試

環境：阿里雲深圳，Ubuntu 24.04，2 vCPU／1.6GB。
原始結果：`benchmarks/results/20260725_vps_onbox/`，方法與數據見 `benchmarks/README.md`。

- **具名虛擬主機與 listener 綁定** — `bench.local:8080` 綁 wildcard，依 Host 路由；
  靜態、gzip、range、反向代理、Admin API、TLS 均以真 binary 驗證。
- **靜態路徑安全** — `..` 逃逸已拒絕，使用無 syscall 的詞法正規化。
- **TLS 啟動與手動憑證** — rustls provider 啟動 panic 已修復；手動憑證可由 SNI 正確載入。
- **404 路由語意** — 不存在的檔案、未知 vhost、未匹配路由不再落成 `ConnectNoRoute` 500。
- **被動健康檢查與同請求 failover** — 兩個 upstream 中一個故障時 20/20 請求成功；
  冷卻後故障節點可重新加入。
- **大檔案串流** — 20MB 靜態檔不再全量緩衝；VPS 負載測試沒有 OOM。
- **程序生命週期** — SIGTERM／SIGINT 可停止服務，不再等到 SIGKILL。
- **Metrics 與轉發標頭** — Admin `/metrics` 有內容；代理請求帶 `X-Forwarded-For`／`X-Real-IP`。
- **`tls`／`admin` DSL 基線** — VPS 配置可啟動並完成實際請求。
- **worker threads 與靜態熱路徑** — `available_parallelism()` 與同步 `std::fs` 已同機重測；
  靜態約 50k req/s，20MB 串流約 17.7MiB RSS。
- **壓縮快取與冷快取 single-flight** — gzip 大 body 負載重測無先前的壓縮驚群／記憶體暴增。

### 2026-07-25 HTTP/3 VPS 冒煙測試

遠端腳本 `/root/h3_test.sh`；產物含 `/root/h3test/h3_big.out`。

- **quiche HTTP/3 基線** — UDP listener、H1 TLS baseline、Alt-Svc、H3 `respond` 均通過。
- **H3 靜態與反向代理大 body** — 10MB 靜態／代理回應逐位元組一致。
- **H3 request body 串流** — 有／無 Content-Length 的 300KB POST 均可轉發；5MB 超限回 413。
- **bare `:port` 正規化** — JSON 的 `:8443` 可在 Linux 啟動。

### 2026-07-26 乾淨 Linux 與公網修正驗收

- **乾淨 Linux 全流程（`57e10f9`）** — release build、全 workspace tests、
  20 輪 integration isolation、release binary／Admin loopback smoke 全過。
  證據：`benchmarks/results/20260726_v02_linux_57e10f92/`
- **H1／H2／H3 公網基線（`af497fd`）** — 三者均 200；H2 authority vhost 與 ALPN 通過，
  H3 連續 10 次 version 3／200。GitHub Rust workflow 同 commit 全綠。
- **H2 parity 與 LB 修正（`af497fd`）** — 自訂 404、CORS simple／preflight、
  非法 origin 不輸出允許標頭、UA deny、regex rewrite＋query、LB 30:10 與 backup 8/8。
  證據：`benchmarks/results/20260726_v02_remote_af497fdd/`
- **H3 access control 公網驗收（`40f78e9`）** — H1/H2/H3 對封鎖 UA 均回 403，
  H3 連續 10 次穩定，VPS tcpdump 捕獲 40 個 443/UDP 封包零 kernel drop。
  證據：`benchmarks/results/20260726_v02_remote_40f78e9b/`
- **fixture 清理** — 驗收後 80/443/2019/9001–9003 與 21209 均無殘留 listener 或幽靈程序。

### 2026-07-26 公網 80／443 生產情境（部分通過）

commit `0d2e05247e186ed205ad7c1a8c1c98de53282b5b`。
證據：`benchmarks/results/20260726_v02_remote_0d2e0524/`

- **公網 H1 與 H3 基線** — HTTP 80、HTTPS H1、真實 QUIC/H3 均 200。
- **Admin 未暴露公網** — 2019 僅綁 loopback。
- **本次發現並已修正** — H2 未協商 ALPN；LB 3:1 實測 20:20。兩者已在 `af497fd` 修正，
  舊目錄保留失敗證據。

### 測試基礎建設（`57e10f9`）

- **動態 listener 與可信 readiness** — 真 binary 測試不再用固定 port；
  每個 child 注入唯一 readiness token，不會把舊程序誤判為 ready。
- **程序群組與中止清理** — Pingclair、watchdog 各自獨立 process group；
  正常完成、失敗啟動、panic/timeout 都會 kill＋wait。
- **Linux 20 輪驗證** — Ubuntu 24.04 完成 20 輪×10 項並行測試，無殘留。
- **`scripts/validate-linux-commit.sh`** — 只接受完整 SHA，建立唯一暫存 checkout，
  執行 release build／tests／20 輪隔離／loopback smoke，保存完整證據，
  清理時只終止自己記錄的 process group。
- **`scripts/remote-production-fixture.sh`** — 啟動前確認 port 無占用；
  stop 前逐一核對 PID cmdline 的專屬 run directory，拒絕對非本次 fixture 的程序送 signal。

---

## 🧪 已實作，待乾淨遠端驗證

> 這些是 v0.2 驗證日（TODO 的 Day 7／15／19／22／23）要清掉的積欠。

### 安全與身分

- **可信代理 client identity**（本機，2026-07-26）— 全域 `trusted_proxies` IP/CIDR；
  只有受信任的直接上一跳可提供 `X-Forwarded-For`／`X-Real-IP`／`X-Forwarded-Proto`。
  XFF 最多 32 hops，由右向左跳過可信代理，畸形或過長鏈 fail closed。
  H1/H2/H3 的 route matcher、rate limit、IP hash、placeholder 與上游 forwarding
  共用 verified client IP。
  **仍缺**：RFC 7239 `Forwarded`、PROXY protocol v1/v2、IP／Referer 完整矩陣、VPS 驗證。
- **TLS／ACME 私密狀態強化**（本機，2026-07-26）— HTTP-01 challenge deploy 改為
  async durable contract；憑證續期改讀真實 X.509 `notAfter`；account、憑證與
  challenge snapshot 統一 temporary file＋fsync＋atomic rename，Unix 從建立起即 `0600`。
  **仍缺**：Let's Encrypt staging 與故障注入驗證。
- **持久化 internal CA**（本機，2026-07-27）— `tls internal` 支援行內與 block DSL、
  JSON 向後相容、衝突配置 fail closed；十年 CA cert/key 以單一 `0600` 原子檔保存，
  另發布 `root.crt`，90 天 leaf 於 30 天前自動續期。手動 → internal → ACME precedence、
  重啟重用、CA cert/key mismatch fail closed 均有測試。
  **仍缺**：乾淨 Linux release 與 production-like Docker 驗證。
- **Admin API 認證**（2026-07-25）— Bearer key；未配置 key 時僅允許 loopback。
- **Basic Auth 執行時校驗**（2026-07-25）— 正確憑據放行，缺少／錯誤回 401。
- **Basic Auth bcrypt 憑據**（2026-07-26）— DSL 對合法 `$2*` hash 自動設 `hashed: true`；
  bcrypt 移到 blocking pool，cost 上限 14，畸形／過高成本一律拒絕。
- **ACME 帳戶持久化**（2026-07-25）— staging／production 分開，0600 落盤。

### Caddy parity 第一波

基線 `dd1ed57`，`redir` DSL 與 H3 護欄追加於 `b624b0c`。

- **`error_page`** — 多狀態碼共用頁；檔案讀取失敗回退內建文字頁。
- **CORS 執行路徑與 DSL** — origin、method、header、expose header、credentials、max-age。
- **IP／Referer／UA 存取控制** — IP/CIDR、Referer host wildcard、UA regex；
  deny 優先，配置載入時預編譯，錯誤配置 fail closed。
- **正則 rewrite** — `$1` capture 與 query string 保留；載入時預編譯。
- **LB weight／backup** — 改用 Pingora 原生 `Backend.weight`（舊實作重複插入 set，
  實際仍為 1:1）；`af497fd` 公網 40 次精準通過 30:10。
- **H2 ALPN 修正** — `TlsSettings::with_callbacks` 預設未開 H2；顯式 `enable_h2()`
  後又揭露 vhost 只讀 HTTP/1.1 `Host`、忽略 H2 `:authority`。`af497fd` 已統一 authority 解析。

**公網 smoke 尚未覆蓋**：IP／Referer allow／deny 與 deny precedence、
死亡 upstream 502 自訂頁、代理 upstream 實收 URI、primary recovery。

### 協議與 H3

- **H3 middleware parity** — 新增 `pingclair-proxy/src/http_policy.rs`，H1/H2 與 H3
  共用 Request ID、CORS、downstream header policy 與 URI rewrite；H3 pipeline／
  handle／handle_path、Basic Auth、redirect、靜態、代理與自訂錯誤頁已接線。
  proxy 單元測試與本機真 H3 矩陣通過。**仍缺**：Linux release 與公網 QUIC 完整矩陣。
- **H3 structured cancellation** — 每個 request stream 有獨立取消訊號；client reset、
  QUIC connection drop 或 response write failure 都會丟棄 handler future 與 upstream session。
- **H3 request trailers fail-closed** — response 未 commit 時回 `501`，已 commit 時送
  request-cancelled reset；三語 README 已記錄限制。
- **上游 HTTP 協議選擇** — 裸位址／`http://` 為 H1、`https://` 以 ALPN 協商 H2/H1、
  `h2c://` 明文 H2-only、`h2://` TLS H2-only；不同協議隔離 connection pool。
  **仍缺**：真 TLS H2 fixture、mTLS。
- **協議矩陣已通過**：H1 SSE 增量傳輸／斷線取消、`Expect: 100-continue`、
  103 Early Hints、request／response trailer fail-closed、prior-knowledge h2c、
  H1 WebSocket 雙向 tunnel、H2 downstream → h2c upstream 的 gRPC DATA／trailers。
  **仍缺**：未宣告 request trailing HEADERS、TLS H2 upstream、真 H3 gRPC client。
- **h2c preface 辨識** — 明文 proxy listener 透過 Pingora 原生 `HttpServerOptions` 啟用；
  TLS listener 保持 ALPN 協商。H3 CONNECT／extended CONNECT 明確回 `501`。
- **0-RTT 預設停用** — reverse proxy 可接受非冪等方法且尚無 replay protection。

### 其他

- **SSE／流式反代 gzip gate**（2026-07-25）— `flush_interval: -1` 與 `text/event-stream`
  會跳過 gzip；H1 與本機真 H3 均驗證逐 event 增量抵達與 client disconnect cancellation。
- **Request ID**（2026-07-26）— 消毒後接受客戶端 ID，否則生成；上游與下游貫穿。
  H3 已本機驗證，待公網 QUIC 驗證。
- **反代 `gzip_types`**（2026-07-26）— 支援精確 MIME、`text/*`、`application/*+json`、`*/*`；
  自訂 `application/wasm` 已以真 binary 驗證。
- **`admin.api_key` DSL**、**`basic_auth` DSL**、**`redir`／`redirect` DSL**（2026-07-26）。
- **Workspace lint baseline**（2026-07-26）— 全 workspace 套用 Rust 1.88 rustfmt，
  通過 `cargo fmt --check` 與 clippy `-D warnings`；GitHub Actions 固定 Rust 1.88
  並在 build/test 前執行兩項 gate。

### 順帶修正的問題

- `handle_path` 現在真的改寫 upstream URI。
- route middleware headers 不會再被 `reverse_proxy.headers_down` 整份覆寫。
- local response 也套用 security headers。
- TLS/H3 啟動不再硬編碼只辨識 443/8443，明確 TLS 配置可用非標準埠。
- 提前回 413 時 stream state 會保留到 request drain 與 response FIN 都完成。
- H3 route planner 直接借用已發佈的 immutable handler tree，不再每請求 clone 整棵 pipeline。

---

## 🧹 已完成的非 runtime 維護

不適用「遠端功能驗證」，保留作為變更紀錄：

- 刪除未使用的 `pingclair-api/src/handlers.rs` 與 `mod handlers;`。
- 修正 `pingclair-core/src/config/loader.rs` 過時 TODO。
- 核實並改寫 proxy rate-limit 的過時 TODO 註釋。
- 修正 `HandlerConfig::Pipeline`／`Handle` 的 serde round-trip。
- README 三語版最低 Rust 更新為 1.88。

---

## ⬜ v0.3+ 候選

> 這些**不是** v0.2 blocker。放在這裡是為了不遺失分析，不是為了現在做。
> v0.2 的範圍邊界見 `docs/TODO.md` 的「明確不做」。

### 反向代理進階

> ⚠️ **`proxy_cache` 已於 2026-07-27 移出這份清單，改列入 v0.2 的 M3**
> （TODO Day 16–18）。原因：`pingora-cache` 已提供狀態機、cache lock、
> eviction、variance 與 predictor，我們只需寫策略與正確性。
> `stale-while-revalidate`／`stale-if-error` 仍留在 v0.3+。

- **Response interception pipeline** — 依 upstream status／header 執行 replace status、
  copy／drop headers、redirect、fallback handler；擴成 Caddy `handle_response`／
  nginx `proxy_intercept_errors` 等級，仍須保持串流。
- **動態 upstream 與服務發現** — A/AAAA/SRV 定期重解析、TTL／jitter、resolver override、
  last-known-good；再接 Consul、Docker、Kubernetes EndpointSlice／Gateway API。
- **Reload-free backend topology** — 參考 HAProxy 3.4 dynamic backends，Admin API
  可新增／下線／drain upstream。
- **進階 LB／session persistence** — consistent hash、sticky cookie（須簽章、可 rotation、
  Secure/HttpOnly/SameSite/TTL）、EWMA／least-latency、P2C、slow start、outlier ejection。
- **Traffic shadow／mirror**、**流量拆分（金絲雀）**。
- **L4 proxy 基線** — TCP／TLS passthrough、SNI routing、PROXY protocol。
- **上游 HTTP/3** — 需獨立 QUIC pool、0-RTT policy 與 gRPC／trailers 相容性。
- **gRPC-web 轉發／transcoding**、**回應體替換 `sub_filter`**（必須串流）。

### 可觀測性與運維

- **OpenTelemetry tracing** — W3C `traceparent`／`tracestate`／baggage、route/upstream spans、
  重試事件與可配置採樣；不得把敏感 body 當 span attribute。
- **配置歷史與一鍵回滾**、**零停機 graceful restart**（SO_REUSEPORT 或 fd 交接）。
- **配置 backend／control plane 抽象** — 檔案／etcd／HTTP、版本化 watch、last-known-good；
  Kubernetes Gateway API／xDS adapter 放外部 crate，不讓核心 hot path 綁死 orchestrator。
- **Web 管理介面** — 內嵌單頁 UI，避免引入前端建置鏈。

### 認證與擴充

- **外掛系統** — loader 仍是 stub；先寫生命週期、掛載、配置雜湊與熱更新 RFC。
- **更多認證方式** — JWT/JWKS、OIDC、API key、forward auth、client mTLS、RBAC、CSRF；
  token 預設只接受 Authorization/header/cookie，驗證 cache 需 bounded 並依 expiry 失效。
- **External auth／policy／processing hooks** — HTTP/gRPC ext-auth 與 bounded ext-process，
  供 OPA、WAF、DLP 使用；需定義 fail-open/closed、timeout、body 上限。
- **Secrets provider** — `${ENV}`、0600 file、systemd credentials，再抽象 Vault／KMS。
- **mock 回應與延遲**、**Fault injection**（僅限明確啟用的測試 route）。

### TLS 與發布

- **多 issuer／現代 TLS** — ACME issuer fallback、ARI、OCSP stapling、ECH、
  cluster-wide certificate storage/locking；不得破壞既有 BoringSSL／rustls 分工。
- **ACME DNS-01**（泛域名）、**ACME `from_credentials` staging 實測**。
- **Linux 發行相容矩陣** — musl 靜態二進位；CPU optimized variant 必須與通用相容版
  分開命名，並在較舊 CPU baseline runner 做 smoke。
- **免 root 安裝路徑** — `/usr/local/bin` 或 `~/.local/bin`，不依賴 systemd。

### 效能與雜項

- **H3 效能壓測** — 目前只有冒煙，沒有 QUIC 單 task／埠模型的吞吐、延遲與高並發數據。
- **目錄 autoindex**、**RequestContext 輕量化**（每請求多個空 HashMap，低優先）。

### AI Gateway（完整清單）

> 應做成可選 crate／plugin 與 transport-neutral middleware；一般反代 route
> 不得支付 JSON parse、tokenizer 或 body copy 成本。所有功能必須保留 SSE streaming、
> bounded memory 與 downstream disconnect cancellation。

- OpenAI-compatible pass-through profile、Provider credential broker、
  Model virtualization／allowlist、AI provider fallback、Token／cost accounting 與 quota、
  AI-aware observability、Prompt／response guardrails、Exact AI cache、
  AI request mutation、多租戶 virtual key／RBAC。
- 更遠：AI provider schema translation、AI 智慧路由、Semantic cache、MCP Gateway
  （須遵守 MCP OAuth 2.1、PKCE、resource audience binding；禁止 token passthrough）、
  OpenInference／AI tracing。

---

## 🔎 生態對照基準（2026-07-26）

納入條件是「主流產品已穩定提供、使用者會直接期待」與「AI workload 明顯改變 proxy
需求」；不追求把每個商業版功能都複製進核心。優先順序：
**安全／可靠性護欄 → 通用協議與動態 upstream → 可觀測性 → 可選 AI Gateway**。

- [Caddy 2.11.4](https://github.com/caddyserver/caddy/releases/tag/v2.11.4)／
  [reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)：
  dynamic A/AAAA/SRV、retry、主被動健康檢查、trusted proxies、upstream mTLS、
  buffering/streaming、response interception。
- [nginx 1.31.3 mainline](https://github.com/nginx/nginx/releases/tag/release-1.31.3)／
  [proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)：
  cache/stale/lock、request/response buffering、`proxy_next_upstream`、上游 TLS、
  trailers、response interception、細粒度 timeout。
- [HAProxy 3.4 LTS](https://www.haproxy.org/)／
  [circuit breaker](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/circuit-breakers/)／
  [retry](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/retries/)：
  dynamic backends、circuit breaker、redispatch、stick tables、slow start、
  runtime statistics、reload-free backend 管理。
- [Traefik 3.7](https://github.com/traefik/traefik/releases/tag/v3.7.1)／
  [HTTP services](https://doc.traefik.io/traefik/routing/services/)：
  provider-driven discovery、middleware chain、passive health、failover、mirroring、
  weighted services、circuit breaker、retry。
- [Envoy Gateway 1.8](https://gateway.envoyproxy.io/latest/tasks/traffic/)：
  circuit/connection/pending limits、global/local rate limit、traffic split/mirror、
  fault injection、session persistence、Gateway API、zone/utilization-aware LB。
- [Envoy AI Gateway 1.0](https://aigateway.envoyproxy.io/release-notes/)、
  [Kong AI Gateway](https://docs.konghq.com/gateway/latest/ai-gateway/)、
  [Cloudflare AI Gateway](https://developers.cloudflare.com/ai-gateway/features/)：
  unified model access、provider fallback、credential broker、token/cost quota、
  model routing、AI metrics、guardrails/DLP、prompt cache、多租戶、MCP。
- [MCP 2025-11-25 authorization spec](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)：
  OAuth 2.1、PKCE、Protected Resource Metadata、OIDC discovery、Resource Indicators／
  token audience validation；明確禁止把 client token 直接 passthrough 到下游服務。

---

## 📌 已知的環境現況

### 使用者的唯一生產站（2026-07-26 純讀取盤點）

`aqeonet-aws-tw-xray`：Amazon Linux 2023 ARM64。cloudflared 的 origin service 是
`https://caddy:6688`，設定 `noTLSVerify: true` 與正確 `originServerName`；
Caddyfile 與 cloudflared config 均唯讀掛載，Caddy `/data` 持久化。

> 盤點過程未修改、重啟或新增任何遠端資源。

### 遠端測試機

遠端 `/root/pingclair` 是歷史測試工作樹，HEAD 停在 `79c820a` 且有大量未提交變更。
STATUS 中的證據是**已保存的測試產物**，不代表目前 `main` 已在該工作樹重新驗證。

> ⚠️ 新的驗證必須使用**乾淨 clone/worktree** 並記錄 commit。
> 禁止對該目錄盲目 pull/reset/clean。
