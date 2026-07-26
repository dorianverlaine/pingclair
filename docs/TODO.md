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

## 🎯 v0.2.0 發布目標：可信的單機生產反向代理

目前 workspace 版本是 `0.1.7`。下一個正式版本直接定為 `0.2.0`，定位不是
「加入最多功能」，而是把 Pingclair 已公開的 HTTP reverse proxy、靜態服務、
自動 TLS、H3、熱更新與 Caddy-like DSL 做成可重現、可觀測、可安全升級的
**single-node production baseline**。

以下是 release blocker；下方 P0／P1 保留更完整的實作細節。只有全部勾選，
才可以改 workspace version、建立 `v0.2.0` tag。已在舊 commit 驗證過的能力，
仍須使用同一個 release-candidate commit 重新跑乾淨 Linux 驗證。

### R0：先讓測試結果可信

- [x] **整合測試隔離完成（`57e10f9`）** — 全部真 binary 測試使用
  動態 port／唯一 readiness token；child 與 process group 在成功、panic、
  timeout、Ctrl-C 後都會 reap，連續跑 20 次不得殘留 listener 或幽靈 Pingclair。
- [x] **乾淨 Linux 驗證腳本完成（`57e10f9`）** — 由指定 commit 建立暫存
  checkout，建置 release binary、啟動測試、收集 config/log/metrics/result，
  最後只清理自己建立的程序與目錄。
- [ ] **協議安全回歸集完成** — H1/H2/H3 的 URI/header 正規化、hop-by-hop headers、
  request smuggling、oversized headers、malformed input 與 body limit 都有負向測試。

### R1：既有功能成為真正的 shipped behavior

- [ ] **Caddy parity 第一波完成驗收** — `error_page`、CORS、IP/Referer/UA access
  control、regex rewrite、LB weight/backup 與 `redir` 在同一 RC commit 上通過
  H1/H2 真 binary 測試與乾淨 VPS smoke。
- [ ] **安全與配置完成驗收** — Admin API auth、Basic Auth、ACME account
  persistence、`tls`／`admin`／`basic_auth`／`redir` DSL、JSON round-trip 與 hot
  reload 都通過成功／拒絕／錯誤配置案例；`0.1.7` 的有效配置保持相容。
- [ ] **串流與壓縮完成驗收** — request/response 大 body、range、SSE、gzip/br/zstd、
  可配置 `gzip_types`、client disconnect cancellation 均保持 bounded memory；
  不得因 retry、middleware 或觀測功能重新引入全量 body buffering。

### R2：補齊單機生產可靠性護欄

- [ ] **可信 client identity** — 🧪 全域 `trusted_proxies`、受限代理鏈解析與
  H1/H2/H3 共用 verified client IP 已在本機完成；未受信 client 無法偽造
  `X-Forwarded-*`／`X-Real-IP`。PROXY protocol v1/v2、RFC 7239 `Forwarded`
  與 Linux/VPS 驗證仍缺，因此 R2 尚未完成。
- [ ] **安全 retry／redispatch** — 可配置 tries、總時限、backoff 與狀態碼；
  v0.2 預設且只保證尚未送出 body 或可安全重放的冪等請求。非冪等 body replay
  與 AI POST fallback 明確延後，不以隱式 buffering 假裝支援。
- [ ] **Circuit breaker／overload protection** — route/upstream 的 connection、
  in-flight request、pending queue 與連續失敗上限可配置；有 open/half-open
  recovery、503/429、metrics，以及 hot reload 狀態轉換測試。
- [ ] **上游 TLS／mTLS** — CA 驗證、SNI/Host、ALPN、client certificate、憑證
  rotation 與錯誤診斷完成；預設驗證憑證，insecure 模式必須明確 opt-in。
- [ ] **Basic Auth 雜湊憑據可用** — 🧪 本機已完成 `hashed: true` bcrypt 校驗、
  async blocking 隔離、錯誤 hash fail-closed、cost ≤ 14 與 DSL 自動辨識；單元、
  DSL 與真 binary 整合測試已通過，尚待目前 commit 的 Linux／VPS 驗證。
- [ ] **健康檢查與 rate limit 可相信** — active/passive health 支援 Host、method、
  headers、status/body、positive/negative threshold 與 slow start；單機 rate limit
  的 GCRA/token-bucket、burst、key scope、`RateLimit-*`／`Retry-After` 語意正確。
  Redis distributed limit 不列入 v0.2。
- [ ] **資源邊界完整** — client header/body/idle、整體 request、upstream connect/
  first-byte/between-reads timeout，以及 header bytes/count、connection、bandwidth
  上限可配置；SSE/WebSocket 有獨立長連線策略。

### R3：協議與 H3 不再是兩套產品

- [ ] **H3 middleware parity** — Request ID、access control、rewrite、CORS、
  `error_page`、redirect 與必要 pipeline 語意和 H1/H2 一致；抽出
  transport-neutral policy，不把 Pingora `Session` 硬塞進 quiche 路徑。
- [ ] **協議矩陣通過** — WebSocket upgrade、gRPC/h2c＋trailers、SSE、
  `Expect: 100-continue`、HTTP trailers、103 Early Hints 與 downstream cancellation
  在支援的 H1/H2/H3 組合有明確測試；不支援的組合必須 fail clearly 並寫入文件。
- [ ] **H3 Linux release smoke 通過** — SNI、Alt-Svc、靜態/代理大 body、
  Content-Length/chunked POST、413、keepalive、middleware parity 與 0-RTT
  非冪等拒絕策略均使用 quiche client 驗證。

### R4：操作與可觀測性達到可值班程度

- [ ] **Access log 真正由配置驅動** — text/JSON、stdout/stderr/file、rotation、
  request ID、verified client IP、route/upstream、tries、TTFB/duration、status/bytes
  完整；Authorization、Cookie、API key 與其他 secret 預設 redaction。file output
  支援依大小／時間 rotation、retention、壓縮及 access/error 分流；非同步寫入必須
  有 bounded queue、明確 backpressure/drop 策略與 dropped-log metric。
- [ ] **Metrics 與健康端點完整** — `/live`、`/ready`、config version、route/status、
  upstream latency/error、retry、circuit/queue、pool、TLS 與 H3 指標可用；所有
  label 有 cardinality 上限。systemd service 使用 `Type=notify`，只在 listener、
  初始配置與必要依賴真正可用後送出 `READY=1`，並支援 watchdog。
- [ ] **Reload／shutdown 可操作** — 配置更新原子套用，錯誤配置保留
  last-known-good；SIGHUP、SIGTERM、systemd restart 與 upstream drain 有真 binary
  測試。手動憑證目錄的新增／更新／刪除需原子刷新 H1/H2/H3 certificate table，
  畸形或半寫入檔案保留 last-known-good 並輸出可操作診斷。v0.2 可明示 listener
  topology 變更需要 restart，不假裝已經 zero-downtime。

### R5：發布閘門

- [ ] **品質閘門全綠** — Linux/macOS 的 `cargo build --workspace`、
  `cargo test --workspace`、`cargo fmt --all --check`、clippy `-D warnings` 通過；
  dependency audit 沒有未處理的 high/critical advisory，例外需有書面風險接受。
- [ ] **RC soak／chaos 通過** — 同一 release binary 至少 1 小時混合 static、
  proxy、SSE、reload、backend failure/recovery 與 TLS/H3 流量；零 crash、零卡死、
  零幽靈程序、無單調 RSS 成長，結果保存在 `benchmarks/results/`。
- [ ] **效能沒有不可解釋回退** — 同一 VPS／同一 harness 的 static plain/gzip、
  reverse proxy 與 20MB streaming 對比 2026-07-25 baseline；吞吐或 p99 回退超過
  10% 必須修復或在 release notes 以數據解釋，streaming RSS 必須維持 bounded。
- [ ] **發布產物可驗證** — Linux glibc x86_64/aarch64、macOS x86_64/arm64 binary，
  GHCR image、SHA-256 checksums、SBOM 與 provenance/signature 自動產生；x86_64
  通用產物不得依賴建置機的 native CPU features，每個 binary 都需在乾淨 runner
  啟動 smoke，且 `pingclair --version` 必須等於 tag。
- [ ] **安裝與升級 smoke 通過** — 全新安裝、`0.1.7 → 0.2.0` 升級、systemd
  start/reload/stop、uninstall、Docker 啟動及最小 Pingclairfile 都在乾淨環境驗證。
- [ ] **發布文件完成** — `CHANGELOG.md`、三語 README、所有 examples、配置參考、
  安全限制、H3 支援矩陣、已知問題與 migration notes 同步；所有範例可由
  `pingclair validate` 驗證。
- [ ] **最後發布動作** — 只在上述項目全綠後將 workspace version 改為 `0.2.0`，
  建立帶 emoji 的 release commit、signed `v0.2.0` tag，確認 GitHub Release／GHCR
  完成後再把本目標移入完成區。

### v0.2 明確不做

以下不是 v0.2 blocker，保留在 P2/P3 或排入 v0.3+：

- AI Gateway、provider translation、token/cost quota、semantic routing/cache、MCP。
- `proxy_cache`、DNS/Kubernetes discovery、reload-free dynamic backend control plane。
- L4 TCP/TLS passthrough、通用 UDP、Gateway API/xDS、正式 plugin runtime。
- Redis distributed rate limit、非冪等 request body retry、traffic mirror/canary。
- OpenTelemetry/OpenInference、Web UI、ACME DNS-01、ECH、zero-downtime listener handoff。

### 建議執行順序

1. R0 測試隔離與乾淨遠端腳本。
2. R1 把已實作項目在同一 RC 基線上驗完，先清掉「有程式碼但未驗證」。
3. R2 trusted proxies／timeouts／bcrypt，再做 retry、circuit、TLS、health/rate
   limit。
4. R3 先建立協議矩陣，再逐步做 H3 transport-neutral parity。
5. R4 logs／metrics／readiness／reload 操作面。
6. R5 soak、效能回歸、release workflow、文件、版本與 tag。

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

### 2026-07-26 整合測試隔離

- [x] **動態 listener 與可信 readiness** — 10 項真 binary 測試不再使用
  9091–9098；每個 server/admin port 先由 OS 保留，啟動前才釋放。每個 child
  都注入唯一 readiness path/token，Admin 測試也會等待 `/health`，不再把舊程序
  或尚未完成 bind 的 listener 誤判為 ready。
- [x] **程序群組與中止清理** — Pingclair、watchdog 各自使用獨立 process group；
  正常完成、失敗啟動、panic/timeout Drop 都會 kill＋wait。harness 因 Ctrl-C
  或外部中止消失時，獨立 watchdog 會清理 Pingclair group；stdout/stderr 改寫入
  per-test 暫存目錄，避免 pipe 塞滿後互相等待。
- [x] **本機重複驗證** — `scripts/test-integration-isolation.sh` 可重現隔離測試；
  macOS 最終版本連跑 20 輪、每輪 10 項並行測試全過，結束後沒有新增 Pingclair、
  listener 或 watchdog。
- [x] **Linux 20 輪驗證** — `57e10f9226bf39ef190ad8007ff2c936a8d385e8`
  在 Ubuntu 24.04 完成 20 輪、每輪 10 項並行真 binary 測試；watchdog 的 Linux
  `/bin/kill` 負 PGID 解析差異已加 `--` 修正，GitHub Rust workflow 與 VPS
  均通過，結束後沒有殘留 listener 或程序。
- [x] **乾淨 Linux 內層驗證腳本** — `scripts/validate-linux-commit.sh` 僅接受完整
  commit SHA，建立唯一暫存 checkout，依序執行 release build、workspace tests、
  20 輪隔離測試與 release binary loopback smoke，保存 metadata、config、log、
  metrics、listener 與 SHA-256；清理時只終止自己記錄的 process group。
- [x] **公網生產 fixture** — `scripts/remote-production-fixture.sh` 在確認
  80/443/2019/9001–9003 無占用後啟動真實 release binary、三個 upstream 與
  80 TCP／443 TCP+UDP listener；stop 前逐一核對 PID cmdline 的專屬 run directory，
  拒絕對不屬於本次 fixture 的程序送 signal。

### 安全與正確性

- [x] **可信代理 client identity（本機，2026-07-26）** — JSON 與 Pingclair DSL
  已支援全域 `trusted_proxies` IP/CIDR；只有受信任的直接上一跳可提供
  `X-Forwarded-For`／`X-Real-IP`／`X-Forwarded-Proto`。XFF 最多 32 hops，
  由右向左跳過可信代理，畸形或過長鏈 fail closed；未受信來源會以 socket peer
  覆寫。H1/H2/H3 的 route matcher、rate limit、IP hash、placeholder 與上游
  forwarding 共用 verified client IP，H1/H2 另已接入 access control／access
  log。單元、DSL 與兩項真 binary 整合測試通過；H3 access-control middleware、
  RFC 7239 `Forwarded`、PROXY protocol v1/v2 與 Linux/VPS 驗證仍待完成。
- [x] **TLS／ACME 私密狀態強化（本機，2026-07-26）** — HTTP-01 challenge
  deploy 改為 async durable contract，token 完成原子落盤並可由 handler 讀取後才
  通知 ACME ready；失敗會回滾，polling 失敗也會 cleanup。憑證續期改讀 CA
  簽發 leaf 的真實 X.509 `notAfter`，account、certificate/private key 與 challenge
  snapshot 統一採同目錄 temporary file＋fsync＋atomic rename，Unix 從建立起即為
  `0600`。TLS crate 20 項測試及 clippy `-D warnings` 通過；尚待 Let's Encrypt
  staging 與 Linux/VPS 故障注入驗證。
- [x] **Admin API 認證**（2026-07-25）— Bearer key 已接入；未配置 key 時僅允許
  loopback。本機 auth 單元測試通過，尚未以目前 commit 做遠端拒絕／放行測試。
- [x] **Basic Auth 執行時校驗**（2026-07-25）— 正確憑據放行，缺少／錯誤憑據
  回 401；`test_basic_auth_end_to_end` 已通過。
- [x] **Basic Auth bcrypt 憑據**（2026-07-26）— Pingclair DSL 對合法 `$2*`
  hash 自動設定 `hashed: true`；JSON 亦可明確設定。bcrypt 工作移到 blocking
  pool，cost 上限 14，畸形／過高成本 hash 一律拒絕；正確、錯誤、畸形、
  成本上限、DSL 與真 binary 測試均在本機通過，尚待 VPS 驗證。
- [x] **反代 `gzip_types`**（2026-07-26）— JSON 與 Pingclair DSL 可設定精確
  MIME、`text/*`、`application/*+json` 與 `*/*`；未設定時保留相容的預設清單，
  自訂 `application/wasm` 已以真 binary＋臨時 upstream 驗證壓縮與解壓內容，
  尚待 Linux／VPS 驗證。
- [x] **ACME 帳戶持久化**（2026-07-25）— staging／production 分開，0600 落盤；
  本機序列化與還原測試通過，尚待 Let's Encrypt staging 真實還原。

### 2026-07-26 Caddy parity 第一波

第一波功能基線為 `dd1ed57`，`redir` DSL 與 H3 護欄追加於 `b624b0c`。
`cargo build --workspace`、`cargo test --workspace` 與 7 項真 binary 整合測試
均在本機通過，但下列項目尚未在乾淨 Linux/VPS 上跑過：

- [x] **`error_page`** — 多狀態碼共用頁；靜態 404 與上游 500/502 使用自訂頁，
  檔案讀取失敗時回退內建文字頁。
- [x] **CORS 執行路徑與 DSL** — origin、method、header、expose header、
  credentials、max-age；包含 preflight 驗證與一般回應標頭。
- [x] **IP／Referer／UA 存取控制** — IP/CIDR、Referer host wildcard、UA regex；
  deny 優先，規則於配置載入時預編譯，錯誤配置 fail closed。
- [x] **正則 rewrite 執行與 DSL** — 支援 `$1` capture 與 query string 保留；
  regex 於配置載入時預編譯。
- [x] **LB weight／backup** — 加權主池；僅在所有主節點不可選時使用 backup。
  公網測試發現舊實作把同一 backend 重複插入 set，實際仍為 1:1；目前已改用
  Pingora 原生 `Backend.weight`；`af497fd` 公網 40 次精準通過 30:10，兩個
  primary 停止後 backup 8/8 接手。
- [x] **H2 ALPN 修正** — 公網測試發現 `TlsSettings::with_callbacks` 預設未開 H2，
  TLS handshake 沒有協商 ALPN；顯式 `enable_h2()` 後又揭露 vhost 只讀
  HTTP/1.1 `Host`、忽略 H2 `:authority` 的 404。`af497fd` 已統一 authority
  解析，公網 curl version 2／200 與 OpenSSL ALPN `h2` 均通過。

移入「完成」前需在乾淨遠端 commit 上跑一套 parity smoke：

- [x] 靜態 404 自訂錯誤頁已在 `0d2e052` 公網通過；死亡 upstream 502 尚未跑。
- [x] CORS simple request、合法 preflight 已在 `0d2e052` 公網通過；非法
  preflight 尚未跑。
- [ ] IP、Referer、UA 的 allow／deny 與 deny precedence。
- [x] UA deny 已在 `0d2e052` 公網通過；IP、Referer 與 deny precedence 尚未跑。
- [x] rewrite capture、query 保留已在 `0d2e052` 公網靜態路徑通過；代理
  upstream 實際收到的 URI 尚未跑。
- [x] weight 3:1 與 primary 全掛時 backup 已在 `af497fd` 公網通過；primary
  恢復尚未跑。

### 2026-07-26 公網 80／443 生產情境（部分通過）

精確 commit：`0d2e05247e186ed205ad7c1a8c1c98de53282b5b`。阿里雲深圳 VPS
實際執行 release Pingclair，綁定 80 TCP、443 TCP+UDP；本機以公網 IP 發送
HTTP/1.1、HTTP/2、HTTP/3 請求。證據保存在
`benchmarks/results/20260726_v02_remote_0d2e0524/`。

- [x] **公網 H1 與 H3 基線** — HTTP 80、HTTPS H1、真實 QUIC/H3 均回 200；
  H3 連續 10 次成功，VPS tcpdump 亦看到外網 UDP exchange。
- [x] **Admin 未暴露公網** — 2019 僅綁 loopback，從本機對 VPS 公網連線失敗。
- [x] **Caddy parity 部分路徑** — H1 的自訂 404、CORS simple/preflight、
  UA deny、regex rewrite＋query 與 LB backup 通過。
- [x] **本次發現並已於新 commit 修正** — H2 未協商 ALPN；LB 3:1 實測 20:20。
  兩者已在 `af497fd` 修正並通過新一輪公網驗收，舊目錄保留失敗證據。
- [ ] **H3 middleware parity 仍未完成** — CORS、access control 與 rewrite 路徑
  回 501；404 使用內建頁而非 `error_page`。這是 R3 的真實缺口，不得把 H3
  baseline 200 誤寫成 parity 完成。

### 2026-07-26 乾淨 Linux 與公網修正驗收

- [x] **乾淨 Linux 全流程（`57e10f9`）** — release workspace build、全 workspace
  tests、20 輪 integration isolation、release binary／Admin loopback smoke
  全過。結果保存在 `benchmarks/results/20260726_v02_linux_57e10f92/`。
- [x] **H1／H2／H3 公網基線（`af497fd`）** — H1、H2、H3 均為 200；H2
  authority vhost 與 ALPN 通過，H3 連續 10 次 version 3／200。GitHub Rust
  workflow 同 commit 全綠。
- [x] **H2 parity 與 LB 修正（`af497fd`）** — 自訂 404、CORS simple／preflight、
  非法 origin 不輸出允許標頭、UA deny、regex rewrite＋query、LB 30:10 與
  backup 8/8 均由本機透過公網請求 VPS 通過。結果保存在
  `benchmarks/results/20260726_v02_remote_af497fdd/`。
- [x] **fixture 清理** — 驗收後 80/443/2019/9001–9003 與 21209 均無本次
  listener，沒有 Pingclair、upstream 或 watchdog 幽靈程序。
- [ ] **尚未覆蓋** — IP／Referer 完整 allow／deny 與 precedence、死亡
  upstream 502 自訂頁、代理 rewrite URI、primary recovery，以及 R3 的 H3
  middleware parity。

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

- [ ] **Workspace lint baseline** — `cargo fmt --all --check` 目前仍有大量歷史格式差異；
  `pingclair-tls` 已可通過 clippy `-D warnings`，workspace 下一批 blocker 位於
  `pingclair-core/src/server/router.rs` 與 `handlers.rs` 的 nested-if、manual-strip、
  argument count 與 question-mark lint。需以獨立、可審查的格式／lint commit
  清乾淨並加入 CI，不能把 R5 的品質閘門寫成假綠。
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
- [ ] **可信代理鏈與真實 client IP** — 🧪 全域 `trusted_proxies`、受限 XFF
  解析、未受信 forwarding header 覆寫，以及跨 H1/H2/H3 的 verified identity
  已在本機完成。剩餘工作是 RFC 7239 `Forwarded`、PROXY protocol v1/v2
  listener、H3 access-control middleware 與乾淨 Linux/VPS 驗證。
- [ ] **上游 TLS 完整化** — 明確的 CA 驗證、SNI／Host、ALPN、client certificate
  mTLS、憑證熱更新與可選 pinning；`insecure_skip_verify` 必須顯眼且預設關閉。
  HTTPS upstream 不應只以「能連上」作為完成標準。
- [ ] **Rate limit 語意補齊** — 現有 `burst` 未真正生效，key 只有 IP／global，
  remaining 也是估算值。補 token bucket／GCRA、burst、dry-run、route／API key／
  header／tenant key，輸出標準 `RateLimit-*` 與 `Retry-After`；再設計 Redis
  distributed backend，避免多 instance 各算各的。
- [ ] **健康檢查能力補齊** — 在 Host 之外加入 method、headers、request body、
  預期 status class、response body regex、follow redirect、不同 health port、
  positive／negative threshold、TLS probe、標準 gRPC Health Checking Protocol
  與 slow-start recovery；限制讀取 body 大小，為 discovery 與 probe 加 jitter/
  backoff，避免 health check 自己成為資源或同步尖峰風險。
- [ ] **Client／upstream 資源時限** — header read、request body、idle、整體 request、
  upstream connect／first-byte／between-reads timeout，以及 header count／bytes、
  connection／bandwidth 限制；SSE/WebSocket 需可另外配置長連線策略。
- [ ] **反代 Brotli／Zstd** — 反代回應目前只有 gzip；靜態路徑已有 br/zstd。
- [ ] **H3 middleware parity** — quiche 路徑目前只直接處理 terminal
  `FileServer`／`ReverseProxy` 等；CORS、存取控制、rewrite、`error_page`、
  Request ID 與 H1/H2 pipeline 尚未完整套用。
- [ ] **SSE 真 binary 端到端測試** — 慢速 upstream 逐 chunk 發送，斷言客戶端
  增量收到資料而非等待完整 body。

### P2：進階功能與可觀測性

- [ ] **`proxy_cache`** — 需定義 host＋path＋vary cache key、ETag／Cache-Control
  語意、negative cache、cache lock／single-flight、stale-while-revalidate、
  stale-if-error、background update、range 與 PURGE；Authorization／Cookie 預設
  bypass，SSE／upgrade／不可安全快取的 streaming response 必須排除。memory/disk
  tier 都要有硬上限，並提供 hit/miss/stale/bypass/eviction 指標及受權限保護的
  inspect／purge API。
- [ ] **Response interception pipeline** — 依 upstream status／header 執行
  replace status、copy／drop headers、redirect、fallback handler 或自訂 error body；
  將現有 `error_page` 擴成 Caddy `handle_response`／nginx
  `proxy_intercept_errors` 等級，仍須保持串流。
- [ ] **動態 upstream 與服務發現** — A/AAAA/SRV 定期重解析、TTL／jitter、
  resolver override、last-known-good、靜態 fallback；再接 Consul health service、
  Docker、Kubernetes EndpointSlice／Gateway API。provider 請求需有 TLS 驗證、
  token rotation、timeout/backoff 與 stale snapshot，更新 backend pool 不得重建
  全部 listener。
- [ ] **Reload-free backend topology** — 參考 HAProxy 3.4 dynamic backends，
  Admin API 可新增／下線／drain upstream，顯示健康、連線、權重與最後錯誤；
  配置 reload 與 runtime override 的優先權必須明確。
- [ ] **進階 LB／session persistence** — header／cookie／query consistent hash、
  sticky cookie、EWMA／least-latency、P2C、slow start、outlier ejection、zone-aware
  與 backend utilization；sticky cookie 必須簽章、可 rotation，具 Secure/
  HttpOnly/SameSite/TTL 設定，backend drain 或消失時可安全重映射。保留目前
  weight／backup 語意。
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
  預設遮罩，並支援採樣、access/error 分流、依大小／時間 rotation、retention、
  壓縮及 bounded async writer；磁碟寫滿或 writer 落後不得拖死 request hot path。
- [ ] **Prometheus 指標擴充** — 上游連線／回應時間、route/status、TLS handshake、
  retry、circuit、queue、cache、H3 connections；定義 label cardinality 預算，
  禁止把原始 path、user ID 或模型 request ID 直接當無界 label。
- [ ] **OpenTelemetry tracing** — W3C `traceparent`／`tracestate`／baggage 傳遞、
  route/upstream spans、重試事件與可配置採樣；不得把敏感 body 當 span attribute。
- [ ] **運行診斷與 readiness** — `/live`、`/ready`、配置版本、upstream 狀態、
  connection pool／queue／circuit 統計、有限期 debug trace 與 profile；Admin API
  輸出需有權限分級。systemd `sd_notify`／watchdog、容器 healthcheck 與 readiness
  probe 必須共用同一套狀態判定，避免程序存活卻尚未可接流量。
- [ ] **外掛系統** — loader 仍是 stub；先寫生命週期、掛載、配置雜湊與熱更新 RFC。
- [ ] **更多認證方式** — JWT/JWKS、OIDC、API key、forward auth、client mTLS、
  RBAC 與 CSRF；token 預設只接受 Authorization/header/cookie，不鼓勵放 query
  string，所有驗證 cache 都需 bounded 並依 expiry/revocation 失效。外掛系統完成後
  優先以外掛實作。
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
- [ ] **Linux 發行相容矩陣** — x86_64/aarch64 的 musl 靜態二進位；如需提供
  CPU optimized variant，必須與不依賴 AVX2/新指令集的通用相容版分開命名，
  並在乾淨、較舊 CPU baseline runner 做啟動與 TLS/H1 smoke。
- [ ] **v0.2 R5：macOS x86_64／arm64 release artifact**。
- [ ] **v0.2 R5：官方 Docker image 發佈** — tag 時至少推 GHCR；Docker Hub 可延後。
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
