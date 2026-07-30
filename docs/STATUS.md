# 📊 Pingclair 狀態表

> 這份文件記錄**已經做了什麼、驗證到什麼程度**，是證據存放處，不是計畫。
>
> - 接下來要做什麼 → `docs/TODO.md`
> - 環境限制與實作守則 → `docs/GUARDRAILS.md`
>
> 最後整理：2026-07-30

## 三種狀態的嚴格定義

功能「有程式碼」、「本機測試通過」與「Linux/VPS 實機驗證通過」是三件不同的事，
**不得混寫**：

| 標記 | 意義 |
|---|---|
| ✅ **完成** | 已在真實 Linux/VPS 以真 binary 驗證，且有結果或腳本可追溯。 |
| 🧪 **待遠端驗證** | 已實作並通過本機單元／整合測試，但**尚未**以目前版本在乾淨 Linux/VPS 驗證。 |
| ⬜ **未實作** | 功能或測試仍缺少。 |

> 🔴 **2026-07-30：本文件所有 H3 條目的證據都早於傳輸層抽換。**
> `561d802` 把手寫的 QUIC 事件迴圈換成 `tokio-quiche`，下面每一筆 H3 驗收
> （2025-07-25 VPS 冒煙、公網基線、access control⋯⋯）跑的都是**舊實作**。
> 它們記錄的是當時為真的事，**不認證現在的程式碼**。
> H3 目前的實際狀態是 🧪，不是 ✅——重跑 Day 28 之後才能改回來。
>
> 這一條不刪除舊證據：失敗與過期的證據都要留著，只是要標清楚它證明的是哪一版。

> ⚠️ 已在**舊 commit** 驗證過的能力，仍須使用同一個 release-candidate commit
> 重新跑乾淨 Linux 驗證才能計入 v0.2。

---

## ✅ 已通過遠端驗證

### 2026-07-28 M1 真站驗收（RC `8294116`）

**北極星驗收達成。** 不是 production-like，是使用者唯一的生產站本身：
`aqeonet-aws-tw-xray`，Amazon Linux 2023 aarch64，
`Cloudflare Tunnel → :6688 → app:8080`。生產 Caddyfile 逐 directive 譯成
Pingclairfile（`benchmarks/configs/production/Pingclairfile`），
image `pingclair:rc-8294116`（linux/arm64）。

- **主演練 27/27**，全部是**差分**驗證——同一請求問 pingclair 也問 Caddy：
  `admin off`、自訂 HTTPS port + `tls internal`、安全標頭 set/remove
  （**CSP 與 Caddy byte-identical**、`-Server` 真的移除）、三類 Cache-Control
  與 `not path` AND 語意、壓縮協商（zstd/gzip/identity，**gzip 解出來 byte-exact**）、
  真實 client IP、JSON log 與 redaction（query token／Cookie／Authorization／
  Referer `?code=` 全數未進 log）、internal CA 重啟後 **leaf 重用而非重簽**、
  `/` 與 `/api/ping` body byte-identical、H2 協商、SIGTERM exit 0。
- **DNS 恢復**在 Linux arm64 真 image 上全過；**reload** 套用好配置、
  拒絕壞配置並保持 last-known-good 續服務。
- **真實切換**：隧道切到 pingclair，4 條連線乾淨註冊，reconnect 後 origin
  錯誤數 0；真瀏覽器已登入 session（IPv6 client）實際使用正常。
  **回滾 8.9 秒**一條命令，Caddy 全程沒停。目標「起著但服務不了」時**拒絕切換**。
- 工具：`benchmarks/scripts/run_m1_production_drill.sh`、
  `run_m1_reload_drill.sh`、`deployment/switch-proxy.sh`。
  證據：`benchmarks/results/20260728_m1_production_8294116/`。

> ⚠️ **範圍界線**：隧道那一跳實測是 **HTTP/1.1**（cloudflared 對 origin 預設
> 不開 h2）；**H2 是在 origin 直接驗的**，不是經隧道驗的。公網路徑無法用 curl
> 驗——Cloudflare managed challenge 在邊緣就回 403，請求到不了源站，改用真
> 瀏覽器加源站 access log 交叉確認。client IP 偽造的**否定面**沿用 2026-07-27
> 的專用 fixture，本次未在受信網段內重驗。

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

### 2026-07-30 M2 生產護欄驗證（RC `a554477`）

**Days 8–14 全部遠端驗證通過。** 兩個環境,因為它們回答不同的問題。

**故障注入矩陣 — 23/23**（`benchmarks/scripts/run_m2_matrix.sh`,
linux/arm64 release image,真 HAProxy `send-proxy` 在前）。M2 的每一條護欄
都只在上游出事時才作用,所以 origin 是**可從外部改變故障模式**的
（`benchmarks/fixtures/m2/origin.py`）,proxy 全程不重啟——觀察到的是 proxy
在反應,不是 proxy 在重來。每條 route 只隔離一項護欄,否則 503 會有多個成因。

- Day 8：靜默 origin 觸發 first-byte timer（2050ms → 504）、超過
  `max_headers`／`max_header_bytes` → 431、慢速 header client 被 header timer
  釋放（3ms）
- Day 9：503 origin 被重新派送、候選耗盡回 503 而非卡住、帶 body 的請求不重放
- Day 10：超過 route 上限快速回 429、slot 釋放後恢復、open circuit 15ms 快速
  失敗、half-open 探測後關閉
- Day 12：**停掉一個 origin 的健康狀態且完全不送流量**,後續 8 個請求全部落到
  另一個且全 200——被動標記做不到這件事
- Day 13：`rate_limit 3 10s { burst 2 }` 精確 5 通過第 6 個拒絕;
  `ratelimit-limit: 5`／`remaining: 0`／`reset: 17`／`retry-after: 4` 是實數
- Day 14：直連 listener 不需 header 照常服務、PROXY listener 經 HAProxy 服務
  同一條 route、無 header 直連被拒;**身分是差分驗的**——未受信來源偽造的
  `X-Forwarded-For: 203.0.113.99` 被換成 socket peer,受信 balancer 的宣告保留
- 證據：`benchmarks/results/20260730_m2_a554477_final/`

**生產原站 M1 回歸 — 27/27**（`aqeonet-aws-tw-xray`,aarch64 2vCPU/916MB）。
這是本次最重要的一項:這個 RC 改動了**所有** route 的請求路徑,不只用到新功能的。
CSP 與 `/`、`/api/ping` 的 body 仍與 Caddy **byte-identical**;internal CA 重啟
後重用 leaf;H2 照常協商;SIGTERM exit 0。

**已切換上線**：`pingclair:rc-3d4dd53` → `rc-a554477`,原地換、同一個位址
（172.18.0.5,隧道連重新解析都不需要）,cloudflared 零 origin error。
舊容器保留為 `aqeo-pingclair-rollback`,回滾只是改名重啟。
RSS 8.81MiB（舊版跑 39 小時是 10.07MiB）。

**浸泡 4.1 小時：不是洩漏,它到頂之後掉回來了。** 兩個獨立儀器
（`docker stats` 的 cgroup 記憶體、`/proc` 的 `VmRSS`）在大約同一點轉向:

| | 起 | 峰 | 末 |
|---|---|---|---|
| VmRSS | 18.98 MiB | 19.29（min 150） | **17.66 MiB** |
| docker MemUsage | 8.77 MiB | 10.47（min 132） | **9.48 MiB** |

洩漏的導數是正的;這條變負了。VmRSS 淨值比起點低 1.32 MiB,最後一小時在
0.32 MiB 的帶子內震盪。Thread 全程 11–12,50/50 取樣皆 200,
`RestartCount=0`、`OOMKilled=false`。形狀是暖機→到頂→allocator 還 page,
就是 jemalloc 的行為;前 80 分鐘只看到上升段所以誤讀成線性。

Idle CPU 平均 **0.332%**（舊版 0.23%）——約 0.1 個百分點,對應
health-check driver **不論有沒有配置探測都每 100ms 醒一次**。小,但真實,
而且每個部署都在付。改成睡到下一次該探測即可移除,已列入 backlog。

> ⚠️ **這不能證明什麼**：4.1 小時不是 24 小時,而且這台流量很輕。它排除了
> 上升段暗示的那種快速洩漏,但排除不了週期超過四小時的東西,也排除不了
> 「新功能真的被配置之後」才出現的東西——線上這份配置四個新 map 是空的。
> **Day 30 的 soak 必須在負載下實際配置 `rate_limit`、`health_check` 與
> `proxy_protocol`**,那才是這次留空的部分。
> 證據：`benchmarks/results/20260730_m2_vps_a554477/`

---

## 🧪 已實作，待乾淨遠端驗證

> 這些是 v0.2 驗證日（TODO 的 Day 7／15／19／22／23）要清掉的積欠。

### M2 生產護欄

- **資源邊界與 timeout（Day 8，本機 2026-07-29）** — `limits` DSL 與 JSON
  default 已涵蓋 header read、request body、idle、整體 request、header
  count／bytes、listener connection、upload／download bandwidth；
  `reverse_proxy transport http` 涵蓋 connect、first-byte、between-reads。
  body 與 bandwidth 逐 chunk 執行，不新增完整 request／response buffer；
  靜態、本機 response、反代與獨立 H3 bridge 均已接線。SSE、
  `flush_interval -1` 與 H1 WebSocket 使用獨立 long-connection policy。
- **本機證據** — 真 binary 超限矩陣 27/27 integration tests 全綠；完整 locked
  gate 共 **362 tests** 全綠。修正前的 header slowloris 與 connect-timeout
  status 失敗保留於
  `benchmarks/results/20260729_day8_local_failed_header_timeout/`、
  `benchmarks/results/20260729_day8_local_failed_connect_status/`、
  `benchmarks/results/20260729_day8_local_failed_sse_content_type/`。
- **仍缺** — 乾淨 Linux release、VPS 與真 QUIC client 矩陣留到 Day 15；
  所以仍是 🧪，不是 ✅。H3 extended CONNECT／WebSocket 仍為既有 501。
  Pingora 0.8 對 H1/H2 只有一個 upstream read timer，兩階段採較嚴格值；
  pre-routing header／H2 field-section／H1/H2 connection 上限變更目前需要 restart。
- **可配置 retry／redispatch（Day 9，本機 2026-07-29）** —
  `reverse_proxy retry` 已涵蓋最大嘗試次數、總時限、固定 backoff、狀態碼與方法；
  舊 JSON 未出現該欄位時維持最多 16 次 connect-before-send failover，且不因 status
  重試。H1/H2 與獨立 H3 bridge 共用 policy；status redispatch 只接受設定允許的
  冪等方法與實際無 body 的 request，connect-before-send 則仍可安全切換。
- **本機證據** — 真 binary 覆蓋嘗試上限、503→200、最終 503、backoff、總時限、
  POST 不重送，以及已允許的 PUT 帶 20 MiB body 仍只串流一次；四種 LB strategy
  的 request-local 排除與 H3 503→200 另有單元測試。完整 locked gate 共
  **368 tests** 全綠。修正前的 status regression 保留於
  `benchmarks/results/20260729_day9_local_failed_status_retry/`；另外五個獨立目錄
  保留 20 MiB 上限、backend 順序、closed downstream reuse 與 large-enum clippy
  等 fixture／gate 失敗。
- **Circuit breaker／overload protection（Day 10，本機 2026-07-29）** —
  `reverse_proxy overload` 提供 route in-flight、bounded pending queue／timeout
  與每 backend request occupancy cap；queue full 回 429，queue timeout、容量耗盡
  或 open circuit 回 503。`circuit_breaker` 依 backend 追蹤連續失敗與 bounded
  rolling error-rate window，支援 open／受限 half-open probes／closed recovery。
  H1/H2 與獨立 H3 bridge 共用狀態與 metrics，等待不會引入 request body replay
  或完整 buffering。相容的 Admin／SIGHUP reload 保留 circuit 狀態，政策或設定
  upstream 集合改變才重建。真 binary 已覆蓋 429／503、容量釋放、狀態復原、
  metrics 與 open state 跨 Admin reload；H3 bridge 另有 open-circuit 負向測試。
  完整 locked gate 共 **375 tests** 全綠。
  修正前 reload 意外清空 open state 的證據保留於
  `benchmarks/results/20260729_day10_local_failed_admin_reload_state/`。
- **上游 TLS／mTLS（Day 11，本機 2026-07-29）** — `transport http` 新增
  `tls`、`tls_server_name`、`tls_trusted_ca_certs`、`tls_client_auth`、
  `tls_insecure_skip_verify`（Caddy 相容）。TLS 素材在**設定載入時編譯一次**
  （`pingclair-proxy/src/upstream_tls.rs`），request path 只 clone `Arc`。
  預設維持驗證憑證與 hostname，走 system trust store；`trusted_ca_certs`
  是**取代**該 store 而非疊加。載入失敗的 route 標記 `Broken`，H1/H2 與 H3
  bridge 都回 500 並記 ERROR，**不會**退回 system trust ＋ 無 client cert。
  矛盾組合（skip verify ＋ pinned CA／SNI、半套 `tls_client_auth`）在 DSL 與
  **JSON 兩條路**都拒絕。診斷一律帶檔案路徑與角色，另外自己驗 cert/key 配對，
  因為 BoringSSL 要到 handshake 才會發現不匹配。
  修掉一個信任外洩：`HttpPeer` 的 reuse hash 不含 CA bundle，同位址同 SNI
  但 trust roots 不同的 route 會共用 pooled connection；改為把 TLS identity
  打包進 `group_key` 高位（protocol group 保留低 8 bits）。
  真 handshake 整合測試以同一份 self-signed origin 做三段對照：預設拒絕 →
  pin 憑證後 200 → `insecure_skip_verify` 200，**連跑 30 次全綠**。
  完整 locked gate 共 **408 tests** 全綠（`cargo +1.88.0` 與預設 1.97.1 各一次）。
  範圍外：沒有檔案 watcher（輪替只在 reload 生效）、沒有 `alternative_cn`、
  憑證到期只在 log 顯示 `notAfter` 字串而不做比較。
- **仍缺** — 乾淨 Linux release、VPS 與真 QUIC client 矩陣留到 Day 15；
  所以仍是 🧪，不是 ✅。非冪等 body replay、AI POST fallback、exponential／jitter、
  `Retry-After` 與有上限的 memory／disk replay policy 未實作。
  `upstream_max_connections` 是 request occupancy cap（包含 H2 multiplex），
  不是 Pingora 實體 socket pool 的直接計數。

### 安全與身分

- **可信代理 client identity**（本機，2026-07-29）🧪 — 全域 `trusted_proxies` IP/CIDR；
  只有受信任的直接上一跳可提供 `X-Forwarded-For`／`X-Real-IP`／`X-Forwarded-Proto`。
  XFF 與 RFC 7239 `Forwarded` 都有 32 hops／8 KiB 上限，由右向左跳過可信代理；
  兩者並存但 client 不一致、語法畸形或超過上限時 fail closed。
  `proxy_protocol on` 會在 TLS／HTTP 之前要求 v1 或 v2 TCP header；外層 ingress
  先按實際 transport peer 驗證 `trusted_proxies`，未受信來源直接斷線。合法流量
  進入只綁 loopback 的私有 Pingora listener，沒有對應 registry identity 的旁路
  request 仍會被拒絕。tunnel 結束即刪除 identity，register／lookup 另有 10 分鐘
  stale-entry pruner。
  H1/H2/H3 的 route matcher、rate limit、IP hash、placeholder 與上游 forwarding
  共用 verified client IP；轉送到 upstream 的 `Forwarded` 會重建為已驗證值，
  不保留未受信任輸入。
  真 binary 測試涵蓋 v1、v2、XFF／Forwarded 一致與衝突、以及從 `127.0.0.2`
  嘗試偽造的未受信 transport peer，並以 Rust 1.88 **連跑 30 次全綠**。
  locked local gate 全綠，總測試數 **422 → 431**。
  **仍缺**：IP／Referer 完整矩陣、乾淨 Linux／VPS 驗證；留到 Day 15。
- **TLS／ACME 私密狀態強化**（本機，2026-07-26）— HTTP-01 challenge deploy 改為
  async durable contract；憑證續期改讀真實 X.509 `notAfter`；account、憑證與
  challenge snapshot 統一 temporary file＋fsync＋atomic rename，Unix 從建立起即 `0600`。
  **仍缺**：Let's Encrypt staging 與故障注入驗證。
- **持久化 internal CA**（本機，2026-07-27，已提交 `4b8d204`）— `tls internal`
  支援行內與 block DSL、JSON 向後相容、衝突配置 fail closed；十年 CA cert/key 以
  單一 `0600` 原子檔保存，另發布 `root.crt`，90 天 leaf 於 30 天前自動續期
  （24h clock-skew allowance）。手動 → internal → ACME precedence、重啟重用、
  CA cert/key mismatch fail closed、非法 domain 拒絕、H3 憑證表可見，均有測試。
  啟動時 eager issuance，不讓第一次 handshake 才發現 CA 壞掉。
  **仍缺**：乾淨 Linux release 與 production-like Docker 驗證（TODO Day 7）。
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
- **反代 zstd／gzip 協商**（2026-07-27）— `encode zstd gzip` 的參數順序即 server 偏好順序；
  協商遵守 q-value、`q=0` 拒絕與 `*` wildcard，client 的明確偏好勝過 server 順序。
  `encode off` 可關閉壓縮；`encode br` 在 compile time 報錯而非靜默降級。
  zstd 與 gzip 共用同一條 bounded-memory streaming 路徑：真 binary 下 40 併發
  × 9.4MB（367MB in flight）RSS 僅成長 21MB（zstd）／9MB（gzip），
  body byte-exact 還原，SSE 仍逐筆增量抵達。
- **`Via` 標頭**（2026-07-28，`3d4dd53`）— RFC 9110 §7.6.3 的 MUST：
  gateway 必須在每個轉發的請求上宣告自己。請求與回應兩個方向都送，
  **附加而非覆寫**（這個 header 記錄的是整條鏈，覆寫等於抹掉前面的 Cloudflare），
  version token 取**收到這一跳時**的協議版本，所以 H2 進 H1 出會是請求
  `2.0 Pingclair`／回應 `1.1 Pingclair`。本機自產的回應（`respond`、靜態檔、
  錯誤頁）**不送** Via——那些沒有經過中介，宣稱有等於謊報路徑。
  `-Via` 可關閉並連上游的值一起丟。H1/H2 與 H3 兩條路徑都覆蓋。
  真站驗證：瀏覽器經 Cloudflare 收到 `via: 1.1 Pingclair`。
- **matcher JSON／TOML round-trip**（2026-07-28）— `Matcher` 改為 externally
  tagged（`{"not": {"path": {...}}}`），`not`／`or`／`query`／`remote_ip`／
  `protocol` 不再在 round-trip 中被讀成別的 variant；`0.1.7` 舊格式仍可載入，
  有歧義的舊形狀保留當時的讀法。無法辨識的 matcher fail closed。
  **同時修掉一個可遠端觸發的 DoS**：untagged 的 `Not` newtype variant 會對
  任何無法辨識的值無限遞迴，Admin API `POST /config` 送一個亂寫的 matcher
  即可讓程序 stack overflow 中止。真 binary 驗證（Admin dump→post 迴圈）與
  修復前的失敗證據：`scripts/test-matcher-roundtrip.sh`、
  `benchmarks/results/20260728_matcher_roundtrip_pass/`、
  `benchmarks/results/20260728_matcher_roundtrip_FAILED_prefix/`。
- **上游 hostname 重解析**（2026-07-28）— hostname upstream 依 `dns_refresh`
  間隔（預設 30s，`off` 可關）重解析並整批 publish 新 pool；解析失敗保留
  last-known-good，開機時解析不到的名稱會在成功後自動加入。IP 字面位址完全
  不進 resolver。真 Docker network + 真 release image 驗證：容器換 IP 後 3s
  內跟上、拔掉 alias 後舊位址持續服務 12s、`dns_refresh off` 維持釘死。
  腳本與證據：`benchmarks/scripts/run_dns_refresh_e2e.sh`、
  `benchmarks/results/20260728_dns_refresh_pass/`。
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
> （TODO Day 17–19）。原因：`pingora-cache` 已提供狀態機、cache lock、
> eviction、variance 與 predictor，我們只需寫策略與正確性。
> `stale-while-revalidate`／`stale-if-error` 仍留在 v0.3+。

- **Response interception pipeline** — 依 upstream status／header 執行 replace status、
  copy／drop headers、redirect、fallback handler；擴成 Caddy `handle_response`／
  nginx `proxy_intercept_errors` 等級，仍須保持串流。
- **動態 upstream 與服務發現** — 定期重解析與 last-known-good 已於 2026-07-28 完成
  （見上）。**仍缺**：一個名稱展開成多個 backend、SRV、TTL／jitter、resolver
  override；再接 Consul、Docker、Kubernetes EndpointSlice／Gateway API。
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

### 憑證能力的已知缺口（2026-07-27）

- **ACME 只有 HTTP-01，沒有 DNS-01。** 這擋掉兩類使用者：需要 **wildcard 憑證**的
  （`*.example.com` 只能靠 DNS-01 簽發），以及 **80 埠不可用**的環境
  （雲端 LB 後方、ISP 封鎖、純內網）。已在 `TODO.md` 列為 v0.3 具名優先項。
- 已解掉、不要退化的三項：ACME challenge token 跨重啟存活
  （`persistent_challenge_handler.rs`——純記憶體的話重啟即簽發失敗）、
  internal CA 跨重啟同一把（`internal_ca.rs`——每次啟動重簽會讓已信任的
  客戶端斷鏈）、TLS store 路徑可經 `PINGCLAIR_TLS_STORE` 覆寫
  （寫死路徑在不可寫環境會直接 panic）。

### 主動健康檢查已在本機接線（Day 12，2026-07-29）🧪

- Day 12 commit：`e5efe2384d484cbe646b5792e1abd4f0c4aa1c31`。
- Pingora background service 現在驅動全域 weak pool registry；hot reload 會讓舊
  pool 自然釋放，DNS publish 後每輪讀取新 generation，不會持續探測已淘汰的 IP。
  registry 與 recovery map 都有明確 pruner，長期狀態不會隨 reload／DNS 輪替無限成長。
- Pingclairfile 與 JSON 支援 path、interval、timeout、method、Host、header、
  status 集合、body fragment、health port、success／failure threshold、
  connection reuse、bounded response body 與 slow-start；同一組 core validation
  保護 Admin API 直入路徑，錯誤設定 fail closed。
- health peer 經 `PingclairProxy::build_http_peer` 建立，沿用正常回源的 pinned CA、
  client certificate、SNI、protocol group 與 timeout；self-signed TLS origin 的
  pinned-CA 主動探測已以真 binary 驗證。
- 探測加入時間 jitter；全 pool 不可用時做 bounded exponential backoff。恢復節點
  經連續成功門檻後，以 lock-free recovery timestamp slow-start 漸進承接流量；
  DNS publish 會剪除離開 pool 的 recovery slots。
- Pingora 0.8.1 原生 `HttpHealthCheck` 的 validator 只收到 response header，且其
  body drain 沒有 byte cap；直接使用會違反本專案 bounded-body 守則。因此保留其
  `HealthCheck`／`Backends` 驅動模型與 Pingora HTTP connector，但在
  `pingclair-proxy/src/health_check.rs` 實作 bounded streaming validator。
- red test 先證明：停止 upstream 後完全不送代理流量，等待兩個 interval，第一個
  request 仍命中死亡節點並回 502。修復後同一真 binary 測試證明節點會在無流量時
  摘除，原址恢復後主動重新加入；另有 pinned-CA TLS probe 測試。兩條新增整合測試
  以 Rust 1.88、`--test-threads=2` **連跑 30 次全綠**。
- locked local gate 全綠，總測試數 **408 → 415**。尚未做乾淨 Linux release、
  VPS 或真 QUIC client 驗證；留到 Day 15，因此本項是 🧪，不是遠端 ✅。

### 精確 rate limit 已在本機接線（Day 13，2026-07-29）🧪

- Day 13 commit：`6eefe808cfee987aefe985e1bbc29ea508a1115f`。
- 以有鎖但短臨界區的精確 token bucket 取代 Count-Min Sketch 機率估算；
  `requests + burst` 是可立即使用的容量，按 `requests / window` 速率補回。
- H1／H2／H3 共用同一份 limiter 狀態與 verified client IP，可依 IP、global、
  route、Bearer／`X-API-Key`、任意 header 或 tenant header 分桶；敏感 key
  只保留 hash，不會把 token 原文留在長期 map。
- 每 1,024 次檢查由 request-path pruner 清除閒置超過兩個 window 的 bucket；
  map 硬上限為 65,536 keys，達上限且無閒置項可清時 fail closed，避免攻擊者用
  高基數 header 讓記憶體無界成長。
- 一般與 dry-run 回應都輸出精確 `RateLimit-Limit`、`RateLimit-Remaining`、
  `RateLimit-Reset`；超額另輸出 `Retry-After`，dry-run 只計數與報告而不回 429。
- Pingclairfile 與 JSON 共用 compiler validation；requests、window、burst 與
  header name 的錯誤設定會在載入時拒絕，Admin API 不能繞過 adapter。
- red unit test 先證明舊實作在 `5 + burst 2` 時第六個 request 就錯誤拒絕。
  修復後真 binary 整合測試驗證容量邊界、header、獨立 key、429 與一個 window
  後 refill，並以 Rust 1.88 **連跑 30 次全綠**。
- locked local gate 全綠，總測試數 **415 → 422**。Redis／distributed limit
  按 v0.2 範圍明確不做；Linux／VPS 驗證留到 Day 15，所以本項仍是 🧪。

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
