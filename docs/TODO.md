# 📋 Pingclair 狀態與待辦

> 這是專案的持久狀態表。功能「有程式碼」、「本機測試通過」與「Linux/VPS
> 實機驗證通過」是三件不同的事，不得混寫。
>
> - ✅ **完成**：已在阿里雲深圳 VPS 以真實 binary 驗證，且有結果或腳本可追溯。
> - 🧪 **待遠端驗證**：已實作並通過本機單元／整合測試，但尚未以目前版本在乾淨
>   Linux/VPS 環境驗證。
> - ⬜ **未實作**：功能或測試仍缺少。
>
> nginx parity 審計見 `docs/AUDIT_NGINX_PARITY.md`；效能數據與壓測發現的 bug
> 見 `benchmarks/README.md`。
>
> 2026-07-26 另以 Caddy 2.11、nginx 1.31 mainline、HAProxy 3.4 LTS、
> Traefik 3.7、Envoy Gateway／AI Gateway、Kong AI Gateway 與 Cloudflare AI
> Gateway 的官方文件做過一輪功能對照。來源與取捨原則見文末「生態對照基準」。
>
> 最後整理：2026-07-26

---

## ✅ 完成：已通過遠端伺服器驗證

### 2026-07-25 VPS 生產情境測試

環境：阿里雲深圳，Ubuntu 24.04，2 vCPU／1.6GB。原始結果保存在
`benchmarks/results/20260725_vps_onbox/`，方法與數據見
`benchmarks/README.md`。

- [x] **具名虛擬主機與 listener 綁定** — `bench.local:8080` 綁 wildcard，
  依 Host 路由；靜態、gzip、range、反向代理、Admin API、TLS 均以真 binary 驗證。
- [x] **靜態路徑安全** — `..` 逃逸已拒絕，使用無 syscall 的詞法正規化。
- [x] **TLS 啟動與手動憑證** — rustls provider 啟動 panic 已修復；手動憑證可由
  SNI 正確載入。
- [x] **404 路由語意** — 不存在的檔案、未知 vhost、未匹配路由不再落成
  `ConnectNoRoute` 500。
- [x] **被動健康檢查與同請求 failover** — 兩個 upstream 中一個故障時，
  20/20 請求成功；冷卻後故障節點可重新加入。
- [x] **大檔案串流** — 20MB 靜態檔不再全量緩衝；VPS 負載測試沒有 OOM，
  RSS 與吞吐數據已留存。
- [x] **程序生命週期** — SIGTERM／SIGINT 可停止服務，不再等到 SIGKILL。
- [x] **Metrics 與轉發標頭** — Admin `/metrics` 有內容；代理請求帶
  `X-Forwarded-For`／`X-Real-IP`。
- [x] **`tls`／`admin` DSL 基線** — VPS 配置可啟動並完成實際請求。
- [x] **worker threads 與靜態熱路徑** — `available_parallelism()` 與同步
  `std::fs` 已在同機重測；靜態約 50k req/s，20MB 串流約 17.7MiB RSS。
- [x] **壓縮快取與冷快取 single-flight** — gzip 大 body 負載重測無先前的
  壓縮驚群／記憶體暴增。

### 2026-07-25 HTTP/3 VPS 冒煙測試

遠端腳本：`/root/h3_test.sh`；測試產物包含 `/root/h3test/h3_big.out`。

- [x] **quiche HTTP/3 基線** — UDP listener、H1 TLS baseline、Alt-Svc、H3
  `respond` 均通過。
- [x] **H3 靜態與反向代理大 body** — 10MB 靜態／代理回應逐位元組一致。
- [x] **H3 request body 串流** — 有／無 Content-Length 的 300KB POST 均可轉發；
  5MB 超限請求回 413。
- [x] **bare `:port` 正規化** — JSON 的 `:8443` 可在 Linux 啟動，未再出現
  `Name or service not known`。

> 遠端 `/root/pingclair` 是歷史測試工作樹，目前 HEAD 為 `79c820a` 且有大量
> 未提交變更。上列證據是已保存的測試情境與產物，不代表目前 `main` 已在該
> 工作樹重新驗證。新的驗證必須使用乾淨 clone/worktree 並記錄 commit。

---

## 🧪 已實作：本機通過，尚待乾淨遠端驗證

### 安全與正確性

- [x] **Admin API 認證**（2026-07-25）— Bearer key 已接入；未配置 key 時僅允許
  loopback。本機 auth 單元測試通過，尚未以目前 commit 做遠端拒絕／放行測試。
- [x] **Basic Auth 執行時校驗**（2026-07-25）— 正確憑據放行，缺少／錯誤憑據
  回 401；`test_basic_auth_end_to_end` 已通過。
- [x] **ACME 帳戶持久化**（2026-07-25）— staging／production 分開，0600 落盤；
  本機序列化與還原測試通過，尚待 Let's Encrypt staging 真實還原。

### 2026-07-26 Caddy parity 第一波

目前 commit：`dd1ed57`。`cargo build --workspace`、`cargo test --workspace`
與 7 項真 binary 整合測試均在本機通過，但下列項目尚未在乾淨 Linux/VPS
上跑過：

- [x] **`error_page`** — 多狀態碼共用頁；靜態 404 與上游 500/502 使用自訂頁，
  檔案讀取失敗時回退內建文字頁。
- [x] **CORS 執行路徑與 DSL** — origin、method、header、expose header、
  credentials、max-age；包含 preflight 驗證與一般回應標頭。
- [x] **IP／Referer／UA 存取控制** — IP/CIDR、Referer host wildcard、UA regex；
  deny 優先，規則於配置載入時預編譯，錯誤配置 fail closed。
- [x] **正則 rewrite 執行與 DSL** — 支援 `$1` capture 與 query string 保留；
  regex 於配置載入時預編譯。
- [x] **LB weight／backup** — 加權主池；僅在所有主節點不可選時使用 backup。

移入「完成」前需在乾淨遠端 commit 上跑一套 parity smoke：

- [ ] 靜態 404 與死亡 upstream 502 的自訂錯誤頁。
- [ ] CORS simple request、合法／非法 preflight。
- [ ] IP、Referer、UA 的 allow／deny 與 deny precedence。
- [ ] rewrite capture、query 保留、代理 upstream 實際收到的 URI。
- [ ] weight 分布，以及 primary 全掛時 backup 接手／primary 恢復。

### 其他已實作項目

- [x] **SSE／流式反代 gzip gate**（2026-07-25）— `flush_interval: -1` 與
  `text/event-stream` 會跳過 gzip；目前只有決策邏輯單元測試。
- [x] **Request ID（H1/H2）**（2026-07-26）— 消毒後接受客戶端 ID，否則生成；
  上游、下游與 access log 貫穿。H3 尚未支援。
- [x] **`admin.api_key` DSL**（2026-07-26）— `admin <listen> <token>`。
- [x] **`basic_auth` DSL**（2026-07-26）— 行內與 block＋realm 形式均可編譯。
- [x] **`redir`／`redirect` DSL**（2026-07-26）— 支援預設 302、數字 3xx、
  `temporary`／`permanent` 與 named matcher；配置 crate 的 66 項測試通過，
  尚未以真 binary 驗證。

---

## ⬜ 未實作

### P0：測試可靠性

- [ ] **整合測試動態 port／程序隔離** — 現有測試使用 9091–9098 固定埠；
  測試被中止時仍可能留下幽靈 Pingclair。新測試應使用動態埠或唯一 readiness
  token，並加入 PID／port owner 檢查。
- [ ] **測試程序群組清理** — `Drop` 只處理直接 child；需評估 process group 或
  kill-on-drop guard，確保子程序與被中止測試不殘留。
- [ ] **乾淨遠端驗證工作流** — 不可再直接使用髒的 `/root/pingclair`。
  補一個以指定 commit 建立暫存 clone/worktree、測試、收集結果、清理程序的腳本。
- [ ] **協議與解析安全回歸集** — 對 H1/H2/H3 建立 URI／header 正規化、
  hop-by-hop header、重複 `Content-Length`／`Transfer-Encoding`、oversized
  header、request smuggling 與 malformed frame 測試；可用 proptest／fuzzing，
  並與 nginx/Caddy 做差異測試。最新 Caddy/nginx 仍持續修補 rewrite、header、
  H2/H3 解析漏洞，這不能只靠一般功能測試。
- [ ] **真 binary 協議矩陣** — 動態 port 下覆蓋 WebSocket upgrade、gRPC/h2c
  trailers、SSE 斷線取消、HTTP trailers、`Expect: 100-continue`、103 Early
  Hints 與大 body backpressure；先用測試確認 Pingora 預設行為，再決定 DSL。

### P1：常用功能與協議缺口

- [ ] **可配置 retry／redispatch** — 現在只在「尚未送出 request」的 connect
  failure 安全重試；需加入最大次數、總時限、間隔／backoff、可重試狀態碼與方法。
  預設只重試冪等請求；POST／AI request 必須有明確 opt-in、Idempotency-Key，
  以及有上限的 memory／disk replay 策略，禁止悄悄全量緩衝無上限 body。
- [ ] **Circuit breaker／overload protection** — route／upstream 級
  max connections、in-flight requests、pending queue、連續失敗／錯誤比例與
  half-open recovery；超限快速回 503/429，並提供指標。這是 Envoy、Traefik、
  HAProxy 的標準生產護欄。
- [ ] **可信代理鏈與真實 client IP** — 配置 `trusted_proxies` CIDR，
  只信任指定上一跳的 `Forwarded`／`X-Forwarded-*`；未受信來源必須覆寫而非沿用。
  補 PROXY protocol v1/v2 listener，並讓 access control、rate limit、IP hash、
  log 共用同一個已驗證 client identity。
- [ ] **上游 TLS 完整化** — 明確的 CA 驗證、SNI／Host、ALPN、client certificate
  mTLS、憑證熱更新與可選 pinning；`insecure_skip_verify` 必須顯眼且預設關閉。
  HTTPS upstream 不應只以「能連上」作為完成標準。
- [ ] **Rate limit 語意補齊** — 現有 `burst` 未真正生效，key 只有 IP／global，
  remaining 也是估算值。補 token bucket／GCRA、burst、dry-run、route／API key／
  header／tenant key，輸出標準 `RateLimit-*` 與 `Retry-After`；再設計 Redis
  distributed backend，避免多 instance 各算各的。
- [ ] **健康檢查能力補齊** — 在 Host 之外加入 method、headers、request body、
  預期 status class、response body regex、follow redirect、不同 health port、
  positive／negative threshold、TLS probe 與 slow-start recovery；限制讀取 body
  大小，避免 health check 自己成為資源風險。
- [ ] **Client／upstream 資源時限** — header read、request body、idle、整體 request、
  upstream connect／first-byte／between-reads timeout，以及 header count／bytes、
  connection／bandwidth 限制；SSE/WebSocket 需可另外配置長連線策略。
- [ ] **反代 Brotli／Zstd** — 反代回應目前只有 gzip；靜態路徑已有 br/zstd。
- [ ] **bcrypt 憑據** — `BasicAuthCredential { hashed: true }` 目前永不匹配。
- [ ] **H3 middleware parity** — quiche 路徑目前只直接處理 terminal
  `FileServer`／`ReverseProxy` 等；CORS、存取控制、rewrite、`error_page`、
  Request ID 與 H1/H2 pipeline 尚未完整套用。
- [ ] **SSE 真 binary 端到端測試** — 慢速 upstream 逐 chunk 發送，斷言客戶端
  增量收到資料而非等待完整 body。
- [ ] **`gzip_types` 可設定** — 目前 MIME 清單硬編碼。

### P2：進階功能與可觀測性

- [ ] **`proxy_cache`** — 需定義 host＋path＋vary cache key、ETag／Cache-Control
  語意、negative cache、cache lock／single-flight、stale-while-revalidate、
  stale-if-error、background update、range 與 PURGE；memory/disk tier 都要有硬上限。
- [ ] **Response interception pipeline** — 依 upstream status／header 執行
  replace status、copy／drop headers、redirect、fallback handler 或自訂 error body；
  將現有 `error_page` 擴成 Caddy `handle_response`／nginx
  `proxy_intercept_errors` 等級，仍須保持串流。
- [ ] **動態 upstream 與服務發現** — A/AAAA/SRV 定期重解析、TTL／jitter、
  resolver override、last-known-good、靜態 fallback；再接 Docker、Kubernetes
  EndpointSlice／Gateway API。更新 backend pool 不得重建全部 listener。
- [ ] **Reload-free backend topology** — 參考 HAProxy 3.4 dynamic backends，
  Admin API 可新增／下線／drain upstream，顯示健康、連線、權重與最後錯誤；
  配置 reload 與 runtime override 的優先權必須明確。
- [ ] **進階 LB／session persistence** — header／cookie／query consistent hash、
  sticky cookie、EWMA／least-latency、P2C、slow start、outlier ejection、zone-aware
  與 backend utilization；保留目前 weight／backup 語意。
- [ ] **Traffic shadow／mirror** — 非阻塞複製請求到 shadow backend，response 不回客戶；
  body replay 必須有大小上限、採樣率、敏感 header 遮罩與獨立 timeout。
- [ ] **流量拆分** — 金絲雀／灰度比例路由，支援 header／cookie audience、
  deterministic hashing 與快速 rollback；不可只靠把同一 pool 的 weight 當發布策略。
- [ ] **L4 proxy 基線** — TCP／TLS passthrough、SNI routing、PROXY protocol 與
  upstream health check；UDP/QUIC generic proxy 延後，避免和現有 H3 listener 混成
  同一抽象。
- [ ] **自訂 access log 格式** — `LogConfig` 尚未真正驅動輸出；需補
  request ID、已驗證 client IP、upstream 位址／重試次數／連線／TTFB／回應耗時、
  status、bytes、cache／circuit 狀態；Authorization、Cookie、API key 與 AI prompt
  預設遮罩，並支援採樣與 log rotation。
- [ ] **Prometheus 指標擴充** — 上游連線／回應時間、route/status、TLS handshake、
  retry、circuit、queue、cache、H3 connections；定義 label cardinality 預算，
  禁止把原始 path、user ID 或模型 request ID 直接當無界 label。
- [ ] **OpenTelemetry tracing** — W3C `traceparent`／`tracestate`／baggage 傳遞、
  route/upstream spans、重試事件與可配置採樣；不得把敏感 body 當 span attribute。
- [ ] **運行診斷與 readiness** — `/live`、`/ready`、配置版本、upstream 狀態、
  connection pool／queue／circuit 統計、有限期 debug trace 與 profile；Admin API
  輸出需有權限分級。
- [ ] **外掛系統** — loader 仍是 stub；先寫生命週期、掛載、配置雜湊與熱更新 RFC。
- [ ] **更多認證方式** — JWT/JWKS、OIDC、API key、forward auth、client mTLS、
  RBAC 與 CSRF；外掛系統完成後優先以外掛實作。
- [ ] **External auth／policy／processing hooks** — HTTP/gRPC ext-auth 與 bounded
  ext-process 介面，供 OPA、WAF、企業 DLP 與自訂轉換使用；定義 fail-open/closed、
  timeout、body 上限、circuit breaker 與敏感資料規則，避免每種治理都硬寫進核心。
- [ ] **Secrets provider** — `${ENV}`、0600 file、systemd credentials，再抽象
  Vault／KMS；配置 dump、Admin API、log 與 panic 一律 redaction，支援無中斷 rotation。
- [ ] **回應體替換 `sub_filter`** — 必須串流，禁止全量緩衝。
- [ ] **mock 回應與可選延遲**。
- [ ] **Fault injection** — 僅限明確啟用的測試 route，支援 delay／abort／比例，
  Admin API 須顯示醒目狀態，避免生產誤開。
- [ ] **ACME DNS-01** — 泛域名與 DNS provider 抽象。
- [ ] **配置歷史與一鍵回滾**。
- [ ] **零停機 graceful restart** — 目前有 graceful shutdown／reload，但 listener
  變更仍需重啟；需 SO_REUSEPORT 或 fd 交接。
- [ ] **上游協議選擇** — HTTP/1.1、HTTPS、h2c、HTTP/2 TLS 與未來 H3 upstream
  的顯式 ALPN／pool；先完成 gRPC／trailers 相容性，再考慮 gRPC-web transcoding。
- [ ] **gRPC-web 轉發／transcoding**。
- [ ] **目錄 autoindex**。
- [ ] **Web 管理介面** — 內嵌單頁 UI，避免引入前端建置鏈。
- [ ] **RequestContext 輕量化** — 每請求多個空 HashMap，低優先。
- [ ] **配置 backend／control plane 抽象** — 檔案／etcd／HTTP、版本化 watch、
  last-known-good 與原子套用；Kubernetes Gateway API／xDS adapter 放在外部 crate，
  不讓核心 hot path 綁死某個 orchestrator。

### P2：AI Gateway 基礎

> AI 功能應做成可選 crate／plugin 與 transport-neutral middleware；一般反代 route
> 不得支付 JSON parse、tokenizer 或 body copy 成本。所有功能都必須保留 SSE
> streaming、bounded memory 與 downstream disconnect cancellation。

- [ ] **OpenAI-compatible pass-through profile** — 先支援 Chat Completions、
  Responses API、Embeddings 與 SSE usage chunk；圖片／音訊只做 body size 與
  content-type 安全轉發。先不急著做全 provider schema translation。
- [ ] **Provider credential broker** — client 只持 Pingclair virtual key，
  gateway 依 tenant／model 注入 OpenAI、Anthropic、Gemini、Azure／Bedrock 等
  upstream credential；secret 不可出現在 DSL 明文、log、metrics 或 Admin dump，
  並支援 rotation。
- [ ] **Model virtualization／allowlist** — 將公開 model alias 映射到 provider model，
  限制 tenant 可用模型與參數（例如 max tokens、tools、reasoning effort），避免
  client 任意選昂貴或未核准模型。
- [ ] **AI provider fallback** — 依 timeout、connect error、429、指定 5xx 與配額
  狀態切換 provider/model，記錄實際選擇原因；AI POST replay 必須沿用 P1 的有界
  replay／Idempotency-Key 設計，已開始 streaming 後不可偷偷換 provider。
- [ ] **Token／cost accounting 與 quota** — 從非 streaming response 與 SSE usage
  chunk 抽取 input、cached-input、output token，依 provider/model price table 換算
  成本；支援 virtual key／user／team／model 的 request、token 與金額日／月 budget，
  先做單機精確帳本，再做 Redis distributed quota。
- [ ] **AI-aware observability** — provider、公開／實際 model、fallback 次數、
  TTFT、生成時間、tokens/s、input/output/cache token、cost、client cancellation；
  prompts／responses 預設完全不記錄，只允許明確 opt-in、採樣、欄位 redaction。
- [ ] **Prompt／response guardrails** — JSON schema／大小／欄位 allowlist、
  regex secret/PII redaction、prompt allow/deny、外部 moderation hook；request-only
  規則優先，response DLP 會破壞 streaming，必須以獨立模式明示 latency 取捨。
- [ ] **Exact AI cache** — 先做 canonical JSON＋provider/model/parameters/tenant policy
  的精確 key、TTL、opt-out、stream replay 與 usage/cost 語意；不可快取含個資、
  tools、副作用或非 deterministic request。semantic cache 延後到 P3。
- [ ] **AI request mutation** — 可選 system-message prepend/append、default parameter、
  max token clamp 與 backend-specific header/body mutation；保留原始 request hash
  供審計，但不得保存原文。
- [ ] **多租戶 virtual key／RBAC** — key 雜湊儲存、scope、expiry、rotation、
  per-route/model permission、owner/team metadata 與即時 revoke；Admin API 操作需
  audit log。

### P3：AI 進階、發佈與生態

- [ ] **H3 效能壓測** — 目前只有 VPS 冒煙，沒有 QUIC 單 task／埠模型的吞吐、
  延遲與高並發數據。
- [ ] **AI provider schema translation** — OpenAI／Anthropic／Gemini／Azure／Bedrock
  等 request/response translation、tool calls、structured output、multimodal、
  prompt caching；以版本化 adapter 隔離 provider API 漂移。
- [ ] **AI 智慧路由** — least-cost／least-token-usage／least-latency、semantic routing、
  quality policy、quota-aware routing 與 inference-pool utilization；先有可重現
  benchmark 與 deterministic fallback，再引入語意模型。
- [ ] **Semantic cache** — 外部 embedding／vector store、相似度門檻、tenant 隔離、
  policy/version invalidation、DLP 順序與命中可解釋性；不可內嵌大型模型進核心。
- [ ] **MCP Gateway** — Streamable HTTP server multiplexing、tool/resource allowlist、
  per-tool rate limit、audit 與 upstream OAuth。遵守 MCP OAuth 2.1、PKCE、resource
  audience binding、Protected Resource Metadata 與 OIDC discovery；禁止 token
  passthrough，防 SSRF／DNS rebinding／tool poisoning。
- [ ] **OpenInference／AI tracing** — 在 OpenTelemetry 上增加標準 AI span attributes，
  預設只記 token/cost/latency metadata，不記 prompt；需 cardinality 與資料保留政策。
- [ ] **多 issuer／現代 TLS** — ACME issuer fallback、ARI、OCSP stapling、ECH、
  internal CA 與 cluster-wide certificate storage/locking；不得破壞既有
  BoringSSL／rustls 分工。
- [ ] **ACME `from_credentials` staging 實測**。
- [ ] **musl 靜態二進位**。
- [ ] **macOS x86_64／arm64 release artifact**。
- [ ] **官方 Docker image 發佈** — tag 時推 GHCR／Docker Hub。
- [ ] **免 root 安裝路徑** — `/usr/local/bin` 或 `~/.local/bin`，不依賴 systemd。

---

## 🧹 已完成的非 runtime 維護

這些項目不適用「遠端功能驗證」，保留作為變更紀錄：

- [x] 刪除未使用的 `pingclair-api/src/handlers.rs` 與 `mod handlers;`。
- [x] 修正 `pingclair-core/src/config/loader.rs` 過時 TODO。
- [x] 核實並改寫 proxy rate-limit 的過時 TODO 註釋。
- [x] 修正 `HandlerConfig::Pipeline`／`Handle` 的 serde round-trip。
- [x] README 三語版最低 Rust 更新為 1.88。

---

## 🔎 2026-07-26 生態對照基準

本輪以「主流產品已穩定提供、使用者會直接期待」與「AI workload 明顯改變 proxy
需求」為納入條件；不追求把每個商業版功能都複製進核心。優先順序是：
安全／可靠性護欄 → 通用協議與動態 upstream → 可觀測性 → 可選 AI Gateway。

- [Caddy 2.11.4 release](https://github.com/caddyserver/caddy/releases/tag/v2.11.4)
  與 [reverse_proxy](https://caddyserver.com/docs/caddyfile/directives/reverse_proxy)：
  dynamic A/AAAA/SRV、retry、主被動健康檢查、trusted proxies、upstream mTLS、
  buffering/streaming 與 response interception。
- [nginx 1.31.3 mainline](https://github.com/nginx/nginx/releases/tag/release-1.31.3)
  與 [proxy module](https://nginx.org/en/docs/http/ngx_http_proxy_module.html)：
  cache/stale/lock、request/response buffering、`proxy_next_upstream`、上游 TLS、
  trailers、response interception 與細粒度 timeout。
- [HAProxy 3.4 LTS](https://www.haproxy.org/) 與官方
  [circuit breaker](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/circuit-breakers/)／
  [retry](https://www.haproxy.com/documentation/haproxy-configuration-tutorials/reliability/retries/)
  文件：dynamic backends、circuit breaker、redispatch、stick tables、slow start、
  runtime statistics、OpenTelemetry 與 reload-free backend 管理。
- [Traefik 3.7](https://github.com/traefik/traefik/releases/tag/v3.7.1) 與
  [HTTP services](https://doc.traefik.io/traefik/routing/services/)：provider-driven
  discovery、middleware chain、passive health、failover、mirroring、weighted services、
  circuit breaker 與 retry。
- [Envoy Gateway 1.8 traffic capabilities](https://gateway.envoyproxy.io/latest/tasks/traffic/)：
  circuit/connection/pending limits、global/local rate limit、traffic split/mirror、
  fault injection、session persistence、Gateway API、gRPC 與 zone/utilization-aware LB。
- [Envoy AI Gateway 1.0](https://aigateway.envoyproxy.io/release-notes/)、
  [Kong AI Gateway](https://docs.konghq.com/gateway/latest/ai-gateway/) 與
  [Cloudflare AI Gateway](https://developers.cloudflare.com/ai-gateway/features/)：
  unified model access、provider fallback、credential broker、token/cost quota、
  model routing、AI metrics、guardrails/DLP、prompt cache、多租戶與 MCP。
- [MCP 2025-11-25 authorization specification](https://modelcontextprotocol.io/specification/2025-11-25/basic/authorization)：
  OAuth 2.1、PKCE、Protected Resource Metadata、OIDC discovery、Resource
  Indicators／token audience validation，以及明確禁止把 client token 直接
  passthrough 到下游服務。

---

## ⚠️ 環境與驗證守則

- 本機 macOS 有系統代理 `127.0.0.1:1082`；reqwest 整合測試必須 `.no_proxy()`。
- 遇到固定 404／502 或 readiness 異常，先用 `lsof`／`ss` 查 port owner，再查
  child 是否已因 bind failure 退出；不要先假設是路由邏輯錯誤。
- timeout 時必須先 kill＋wait，再讀 stdout/stderr 到 EOF，否則會永久阻塞並留下
  幽靈程序。
- CI 與 Dockerfile 使用 stable Rust；nightly 曾在 release profile 編譯 tokio ICE。
- reqwest dev dependency 必須維持 rustls；native-tls／OpenSSL 會與 quiche 的
  BoringSSL 產生連結衝突。
- 遠端 `/root/pingclair` 有歷史未提交變更；禁止盲目 pull/reset/clean。

### HTTP/3 實作護欄

- `quiche 0.29`、`boring 4.22` 與 Pingora `boringssl` feature 是同一套
  BoringSSL 鏈結設計。禁止引入 `pingora-openssl`、`openssl-sys` 或 reqwest
  `native-tls`；過去曾因 OpenSSL／BoringSSL 符號衝突造成啟動 SIGBUS 與 Linux
  link error。
- H3 是 `pingclair-proxy/src/quic.rs` 的 raw Tokio UDP／quiche 路徑，每個 HTTPS
  port 一個 task 與一個無鎖 connection map；不是 Pingora `ProxyHttp Session`
  的延伸。middleware parity 應抽出 transport-neutral 邏輯，不可硬把 H1/H2
  Session 塞進 H3。
- `pump_h3_events` 必須同時由收包與 maintenance pass 驅動。request body drain
  可能在沒有新 UDP packet 時產生 `Finished`；只在收包時 pump 會讓大型 POST
  永久卡住。
- H3 憑證表以 `ArcSwap` 發佈，透過 `TlsManager::peek_pem` 讀取既有憑證並每
  60 秒刷新；`peek_pem` 不可觸發 ACME 簽發。listener port、憑證 domain 清單
  等 topology 仍主要在啟動時擷取，新增項目不得假設 hot reload 已完整生效。
- H3 request／response body 必須維持 bounded channel、QUIC flow control 與串流；
  不可為了 middleware parity 改成全量緩衝。`enable_early_data()` 已開啟，擴充
  非冪等請求行為前須先審核 0-RTT replay 風險。
- 修改 H3 或 TLS dependency 後，至少以 Linux release binary＋quiche client
  重跑 Alt-Svc、SNI、多大小靜態／代理 body、含／不含 Content-Length 的 POST、
  413 與 upstream keepalive；macOS 單元測試不足以驗證鏈結與 QUIC 行為。
