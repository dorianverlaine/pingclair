# 🎯 Pingclair v0.2.0 執行計畫

> 這份文件只回答一個問題：**今天做什麼**。
>
> - 已完成的項目與驗證證據 → `docs/STATUS.md`
> - 環境限制與實作守則（動手前必讀）→ `docs/GUARDRAILS.md`
> - nginx 功能對照 → `docs/AUDIT_NGINX_PARITY.md`
> - 效能數據與壓測發現 → `benchmarks/README.md`
>
> 最後整理：2026-07-27

---

## 發布目標

目前 workspace 版本 `0.1.7`，下一個正式版本直接定為 `0.2.0`。

定位**不是**「加入最多功能」，而是把已公開的 HTTP reverse proxy、靜態服務、
自動 TLS、H3、熱更新與 Caddy-like DSL 做成可重現、可觀測、可安全升級的
**單機生產基線**。

**北極星驗收**：能安全替換使用者目前唯一的個人生產站
（`Cloudflare Tunnel → HTTPS caddy:6688 → app:8080`，三容器同一 Docker
network，源站不發布任何 host port）。不是「相似 DSL 能通過 parser」，
而是真的切過去、跑得住、能回滾。

---

## 工作節奏

每天只做一個 Day。兩種日子分開，不要混：

| 標記 | 類型 | 說明 |
|---|---|---|
| 🔨 | **寫程式日** | 改程式碼＋補本機測試。結束時 local gate 必須全綠。 |
| ✅ | **驗證日** | **不改程式碼**。凍結一個 commit，在乾淨 Linux／VPS／Docker 上驗證。 |

**為什麼驗證要集中、不要每天穿插**：驗證必須針對一個凍結的 commit 才有意義。
一邊改一邊驗，等於每次都在驗不同的東西，證據無法累積。所以寫程式日成批推進，
到里程碑邊界才用同一個 RC commit 一次驗完。

**每個 🔨 日的收工條件**（缺一不可）：

```
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo build --locked --workspace
cargo test --locked --workspace
```

**每個 ✅ 日的收工條件**：結果寫進 `benchmarks/results/<date>_<commit>/`，
並更新 `docs/STATUS.md`。失敗的證據**不可覆寫**，另開目錄保留。

---

## M1 — 讓唯一生產站可被替換（Day 1–7）

這是最高價值的里程碑：它是真實世界的驗收，不是自訂指標。
2026-07-26 逐項追蹤程式碼後，確認以下缺口讓那份 Caddyfile **尚不能原樣替換**。

### 🔨 Day 1 — 收尾並提交 internal CA ✔ `4b8d204`

~~目前 worktree 有一批未提交的 internal CA 工作。~~ **已完成 2026-07-27。**

- ✅ 修正 `cargo fmt` 差異（`pingclair/src/main.rs`、`pingclair/tests/integration.rs`）。
- ✅ Gate 四項全綠：fmt、clippy `-D warnings`、build `--locked`、
  test `--locked`（**270 passed / 0 failed / 1 ignored**）。
- ✅ 已提交並 push（`4b8d204`），worktree 乾淨。
- 順帶納入 AGENTS.md 的 TODO／STATUS／GUARDRAILS 拆分引用。

> 尚待 Day 7 驗證：乾淨 Linux release 與 production-like Docker。
> 在那之前不得宣稱 `tls internal` 已完成。

### 🔨 Day 2 — per-server access log 真正由配置驅動 ✔ `7e9eb86`

**已完成 2026-07-27。** 新增 `pingclair-proxy/src/access_log.rs`。

- ✅ text／JSON、stdout／stderr／file；同路徑的多個 server 共用一個 handle
  與一把鎖（否則會交錯寫壞行），append 不截斷。
- ✅ 欄位齊全：request_id、client_ip（verified）、route、upstream、status、
  bytes、ttfb_ms、duration_ms、protocol、user_agent、referer、error。
- ✅ 真 binary 驗證：兩個 server 一個 JSON 進檔案、一個 text 進另一檔案並
  刪掉 `user_agent`，分流正確、`bytes` 精確（21／404 頁 13）。
- ✅ Gate 四項全綠，270 → **284 tests**。

> 順帶修掉三個 bug：`format filter { wrap text }` 無法表達（永遠變 JSON）、
> `fields { x delete }` 編譯時被丟棄、靜態檔與錯誤頁的 `bytes` 恆為 0。
> 詳見 commit message。

- **範圍外（仍留 Day 21）**：rotation／retention／壓縮／bounded async writer。
  目前寫入是同步的，磁碟卡住會擋住呼叫端——這正是 Day 21 存在的理由。

### 🔨 Day 3 — secret redaction 與 Cloudflare client identity ✔ `81aabc5`

**已完成 2026-07-27。** 新增 `pingclair-proxy/src/redaction.rs`。

- ✅ `CF-Connecting-IP` 只在 `trusted_proxies` 分支內讀取，優先於 XFF chain
  （Cloudflare 定義它是唯一的原始訪客位址，不需走鏈也不會歧義）。
  畸形值退回正常 chain，不退回攻擊者同樣可控的東西。
- ✅ 預設遮罩：query 參數（token／key／secret／password／credential／auth／
  signature／session／code 家族）與 **Referer**。access log 現在記錄完整
  request target 而非只有 path——operator 需要 query，而它只有先遮罩才安全。
- ✅ header 比對用精確匹配而非子串，`x-cookie-preference` 不會被誤判為 `cookie`。
- ✅ 真 binary 雙向驗證：可信 peer 的 `CF-Connecting-IP` 生效
  （client_ip = 203.0.113.77）；把 127.0.0.1 移出 `trusted_proxies` 後，
  偽造的 `CF-Connecting-IP` + `XFF` + `X-Real-IP` **全部被忽略**。
- ✅ Gate 四項全綠，284 → **299 tests**。

> ⚠️ **Referer 是最隱蔽的洩漏面**：它帶的是*前一頁*的 URL，所以 OAuth 的
> `?code=` 可能在本次請求 URI 完全乾淨的情況下照樣進 log。

- **範圍外**：`Authorization`／`Cookie` 目前不會進 access log（沒有 header
  logging 功能），`is_sensitive_header()` 已備妥供 Day 21 記錄 header 時使用。

### 🔨 Day 4 — 反代 zstd／gzip 協商 ✔

**已完成 2026-07-27。** 新增 `pingclair-proxy/src/encoding.rs`。

- ✅ algorithm list 編譯進 runtime（`ServerConfig::encodings`），directive 的
  **參數順序就是 server 偏好順序**。
- ✅ 協商遵守 RFC 9110：q-value 優先於 server 偏好、`q=0` 視為拒絕、
  `*` wildcard、顯式提及永遠勝過 wildcard（不論先後）。畸形 q 當作可接受
  而非拒絕——這個 header 是建議性的，client 送垃圾不該換來壞掉的回應。
- ✅ `encode off` 讓 directive 真正能**關掉**壓縮；沒寫 directive 時預設 gzip，
  所以 `0.1.7` 的既有配置行為完全不變。
- ✅ `encode br` 在 **compile time 直接報錯**，不靜默降級成 gzip。
  parser 仍接受 `br`（野生 Caddyfile 會寫），但 proxy 沒有 streaming Brotli
  encoder，假裝支援只會在很久以後從一個沒人要求過的 `Content-Encoding` 被發現。
- ✅ zstd 走**同一條 bounded-memory 路徑**：每個 chunk 寫入 → sync flush →
  `mem::take` 排空，記憶體由 chunk 大小決定而非 body 大小。
- ✅ 真 binary 驗證（見下表）：13 種 `Accept-Encoding` × 4 種 server 配置全部
  符合預期；zstd/gzip body **byte-exact** 還原；SSE 仍以來源的 400ms 節奏
  逐筆抵達；40 併發 × 9.4MB（367MB in flight）RSS 只成長 21MB／9MB。
- ✅ Gate 四項全綠，299 → **320 tests**。

| 場景 | `Accept-Encoding` | 結果 |
|---|---|---|
| 現代瀏覽器 | `gzip, deflate, br, zstd` | `zstd` |
| 舊瀏覽器 | `gzip, deflate, br` | `gzip` |
| 只收 br | `br` | identity（我們不產 Brotli） |
| client 用 q 表態 | `zstd;q=0.1, gzip;q=1.0` | `gzip` |
| client 拒絕 zstd | `zstd;q=0, gzip` | `gzip` |
| `encode off` | `gzip, zstd` | identity |
| `< 256` bytes／已編碼／`text/event-stream` | 任意 | identity |

> ⚠️ **bounded memory 必須是測試而非註解**。`encoding.rs` 的
> `memory_stays_bounded_by_chunk_size_not_body_size` 對兩種 coding 各推 64MiB，
> 斷言單一 chunk 輸出不接近 body 大小。寫這個測試時第一版自己踩了坑：
> 每個 chunk 餵**同一塊** 64KiB，zstd 的 window 直接把 64MiB 去重成 15KB，
> 於是「輸出有在流動」的斷言假性失敗——payload 必須逐 chunk 唯一且不可壓縮。

- **範圍外**：Brotli（需要 streaming encoder，排 v0.3）；靜態檔案路徑的協商
  仍走 `pingclair-static` 既有的預壓縮邏輯，本日未動。

### 🔨 Day 5 — Docker DNS 重解析

目前 hostname 只在配置載入／reload 時以 blocking resolver 取第一個 IP，
沒有 TTL 重解析，app 容器換 IP 後不會更新。

- 依 TTL／受控間隔重解析，更新 backend。
- 解析暫時失敗時保留 last-known-good，不可直接讓站台掛掉。
- **完成判定**：app 容器換 IP 後 backend 能跟上；resolver 失效時舊 backend 仍可用。

### 🔨 Day 6 — matcher JSON round-trip

遞迴 `Not` matcher 目前無法安全通過 core config 的 untagged JSON round-trip。
直接讀 Pingclairfile 不受影響，但 JSON 配置與 Admin hot reload 會壞。

- 定義可辨識且向後相容的 matcher JSON 表示。
- **完成判定**：`not path` 等遞迴 matcher 能 round-trip；`0.1.7` 既有 JSON 配置
  仍可載入。

### ✅ Day 7 — M1 驗證日：production-like Docker 演練

凍結一個 RC commit，用**真 release binary**在 production-like Docker network
跑完整替換演練。

- 覆蓋：`admin off`、自訂 HTTPS port、internal CA 重啟／續期、三類 Cache-Control、
  安全標頭 set/remove、`not path` AND 語意、壓縮協商、真實 client IP、
  JSON log／redaction、app restart／DNS recovery、reload、shutdown、**回滾**。
- 經 Cloudflare Tunnel 路徑驗證 TLS 與 H1/H2。
- **完成判定**：以上全過才可宣稱「可以替換那台 Caddy」。在此之前不得宣稱。

---

## M2 — 生產護欄（Day 8–15）

讓它在壓力、故障與惡意流量下不會失控。

### 🔨 Day 8 — 資源邊界與 timeout

- client header read／request body／idle／整體 request timeout。
- upstream connect／first-byte／between-reads timeout。
- header count／bytes、connection、bandwidth 上限。
- SSE／WebSocket 需可另外配置長連線策略（不能被一般 idle timeout 砍掉）。
- **完成判定**：每個上限都有超限測試，且超限行為明確（不是掛住）。

### 🔨 Day 9 — 可配置 retry／redispatch

目前只在「尚未送出 request」的 connect failure 安全重試。

- 加入最大次數、總時限、backoff、可重試狀態碼與方法。
- **v0.2 預設且只保證冪等請求**。非冪等 body replay 與 AI POST fallback 明確延後，
  **不以隱式 buffering 假裝支援**。
- **完成判定**：重試邊界有測試；非冪等請求確實不被重放。
- **未來方向（不在 v0.2）**：POST／AI request 若要支援重試，必須有明確 opt-in、
  `Idempotency-Key`，以及**有上限的** memory／disk replay 策略。
  禁止悄悄全量緩衝無上限 body。

### 🔨 Day 10 — Circuit breaker／overload protection

- route／upstream 級的 max connections、in-flight requests、pending queue、
  連續失敗／錯誤比例上限。
- open／half-open recovery、超限快速回 503/429、metrics。
- **完成判定**：狀態轉換有測試，含 hot reload 下的狀態處理。

### 🔨 Day 11 — 上游 TLS／mTLS

- CA 驗證、SNI／Host、ALPN、client certificate、憑證 rotation、錯誤診斷。
- **預設驗證憑證**，`insecure_skip_verify` 必須顯眼且預設關閉。
- **完成判定**：憑證錯誤時有可操作的診斷訊息，不是無聲失敗。

### 🔨 Day 12 — 健康檢查補齊

> 💡 **這天比預期便宜**：`pingora-load-balancing::health_check::HttpHealthCheck`
> 已經提供 `req`（自訂 Host／method／headers）、`validator`（status／body 檢查）、
> `port_override`（不同 health port）、`consecutive_success/failure` 門檻、
> `reuse_connection` 與 `health_changed_callback`。主要工作是**接線與 DSL**，
> 不是從零實作。

- 把上述 Pingora 能力接進 DSL 與 runtime。
- 限制讀取 body 大小；為 probe 加 jitter／backoff，避免 health check 自己
  變成同步尖峰。
- slow start recovery（Pingora 未提供，需自己做）。
- **完成判定**：故障節點能被正確摘除並在恢復後重新加入。

### 🔨 Day 13 — Rate limit 語意補齊

現有 `burst` 未真正生效，key 只有 IP／global，remaining 是估算值。

- 補 token bucket／GCRA、burst、dry-run、route／API key／header／tenant key。
- 輸出標準 `RateLimit-*` 與 `Retry-After`。
- **範圍外**：Redis distributed limit 不列入 v0.2。
- **完成判定**：burst 行為與 header 數值正確，不是估算。

### 🔨 Day 14 — PROXY protocol 與 RFC 7239

`trusted_proxies` 與受限 XFF 解析已完成（見 STATUS）。剩下：

- PROXY protocol v1／v2 listener。
- RFC 7239 `Forwarded` header 解析。
- **完成判定**：三種來源（XFF／Forwarded／PROXY protocol）的 verified client IP
  一致，且未受信來源無法偽造。

### ✅ Day 15 — M2 驗證日

凍結 RC，在乾淨 Linux／VPS 驗證 Day 8–14 全部項目，加上先前積欠的
🧪 項目：bcrypt basic auth、`gzip_types`、上游協議選擇。

---

## M3 — 接上 Pingora 已提供的能力（Day 16–20）

> 盤點 `pingora 0.8.1` 全家桶後發現：**`pingora-cache` 完全沒被引入**，
> 而它提供的正是審計裡估「1 週+」的 `proxy_cache`。`boringssl` feature 明確
> 包含 `pingora-cache?/boringssl`，**與現有 BoringSSL 鏈結相容**，沒有
> GUARDRAILS 裡那類符號衝突風險。
>
> `pingora-cache` 已提供：HTTP caching 狀態機、**cache lock**（single-flight，
> 與我們手寫的壓縮 coalescing 同類）、LRU／simple-LRU eviction、
> **variance**（`Vary` 處理）、**predictor**（記住不可快取資產、提前 bypass）、
> cache put/purge 介面、`max_file_size`、memory storage 與 storage trait。
> `ProxyHttp` trait 更已內建 7 個 cache 掛鉤
> （`request_cache_filter`、`cache_key_callback`、`cache_hit_filter`、
> `response_cache_filter`、`cache_vary_filter` 等）。
>
> 因此把 `proxy_cache` 從 v0.3+ **提前到 v0.2**：不是因為變簡單了，
> 而是因為最難的狀態機與併發控制別人已經寫好且測過。
> 我們要寫的是**策略與正確性**，那仍然不便宜——所以給它三天。

### 🔨 Day 16 — 接上 pingora-cache 骨架

- 加入 `pingora-cache` 依賴與 `cache` feature，確認 BoringSSL 鏈結無衝突
  （這是 GUARDRAILS 明列的高風險區，先驗證再往下做）。
- 接上 `request_cache_filter`／`cache_key_callback`：定義 host＋path＋query
  的 cache key，memory storage 先跑通。
- **完成判定**：同一 URL 第二次請求命中快取，且有測試證明沒有回源。

### 🔨 Day 17 — 快取策略與正確性

**這天是整個 M3 的風險所在**，快取的 bug 不會讓服務掛掉，只會安靜地回錯內容。

- `ETag`／`Cache-Control`／`Vary` 語意（用 pingora 的 `cache_control` 與
  `variance`）。
- **預設 bypass**：`Authorization`、`Cookie`。
- **必須排除**：SSE、upgrade、`flush_interval: -1` 的串流回應。
- range 請求與 negative cache（404/5xx 的短 TTL）。
- **完成判定**：每一條 bypass／排除規則都有負向測試——證明它**沒有**被快取。

### 🔨 Day 18 — 快取運維面

- cache lock（single-flight）與 predictor 接線，避免回源驚群。
- eviction 策略與 **memory/disk tier 硬上限**。
- hit／miss／stale／bypass／eviction 指標。
- 受權限保護的 inspect／purge API。
- **完成判定**：上限確實生效（超過會 evict 而不是無限長大）；purge 需認證。

### 🔨 Day 19 — 一致性雜湊 LB

> 💡 `pingora-ketama` 與 `pingora-load-balancing::selection::consistent`
> 已提供 ketama 一致性雜湊；`selection::weighted` 提供加權。

- 接上 consistent hash，支援 header／cookie／query 作為 hash key。
- **範圍外**：sticky cookie 簽章／rotation 留到 v0.3（那部分 Pingora 不提供，
  且做錯有安全後果）。
- **完成判定**：backend 增減時 key 重映射比例符合一致性雜湊預期。

### ✅ Day 20 — M3 驗證日

凍結 RC，在乾淨 Linux 驗證快取正確性（尤其是 bypass／排除規則）、
上限、purge 與一致性雜湊。

> ⚠️ 快取驗證必須包含**壓測**：確認快取沒有把 20MB 串流變回全量緩衝
> （這是專案歷史上出現過兩次的同類 bug，見 GUARDRAILS）。

---

## M4 — 可觀測性與運維（Day 21–24）

讓它可以被值班的人操作。

### 🔨 Day 21 — Access log 完整化

Day 7 做了輸出，這天做生產級韌性。

- file output 支援依大小／時間 rotation、retention、壓縮、access/error 分流。
- 非同步寫入必須有 bounded queue、明確 backpressure／drop 策略與
  dropped-log metric。
- **完成判定**：磁碟寫滿或 writer 落後時**不得拖死 request hot path**（要有測試）。

### 🔨 Day 22 — Metrics 與 readiness

- `/live`、`/ready`、config version、route/status、upstream latency/error、
  retry、circuit/queue、pool、TLS、H3 指標。
- **所有 label 有 cardinality 上限**：禁止把原始 path、user ID 直接當無界 label。
- systemd `Type=notify`：只在 listener、初始配置與必要依賴真正可用後才送
  `READY=1`，並支援 watchdog。
- **完成判定**：程序存活但尚未可接流量時，`/ready` 必須是 not ready。

### 🔨 Day 23 — Reload／shutdown 可操作

- 配置更新原子套用；錯誤配置保留 last-known-good。
- 手動憑證目錄的新增／更新／刪除需**原子刷新** H1/H2/H3 certificate table；
  畸形或半寫入檔案保留 last-known-good 並輸出可操作診斷。
- **v0.2 可明示 listener topology 變更需要 restart**，不假裝已經 zero-downtime。
- **完成判定**：SIGHUP／SIGTERM／systemd restart／upstream drain 有真 binary 測試。

### ✅ Day 24 — M4 驗證日

凍結 RC，驗證 log rotation／redaction、metrics、readiness、reload／shutdown
在乾淨 Linux 的實際行為。

---

## M5 — 協議安全與 H3（Day 25–28）

### 🔨 Day 25 — 協議安全回歸集

**這是 v0.2 唯一還沒動的 R0 項目，優先度其實很高**——最新 Caddy／nginx 都still
在修 rewrite、header、H2/H3 解析漏洞，一般功能測試抓不到這類問題。

- H1/H2/H3 的 URI／header 正規化、hop-by-hop headers、重複
  `Content-Length`／`Transfer-Encoding`、oversized headers、request smuggling、
  malformed frame 的**負向測試**。
- 可用 proptest／fuzzing，並與 nginx／Caddy 做差異測試。
- **完成判定**：每一類都有明確的拒絕行為與測試。

### 🔨 Day 26 — 協議矩陣補完

已通過的見 STATUS。剩餘缺口：

- 未宣告的 request trailing HEADERS。
- TLS H2 upstream fixture。
- 真 H3 gRPC client 矩陣。
- **完成判定**：不支援的組合必須 **fail clearly 並寫入文件**，不是靜默失敗。

### ✅ Day 27 — H3 Linux release smoke

用 quiche client 驗證：SNI、Alt-Svc、靜態／代理大 body、
Content-Length/chunked POST、413、keepalive、middleware parity、
0-RTT 非冪等拒絕策略。

> 依 GUARDRAILS：改動 H3 或 TLS dependency 後，**macOS 單元測試不足以驗證
> 鏈結與 QUIC 行為**，必須跑這一關。

### ✅ Day 28 — 公網協議矩陣

補完 STATUS 中列為「尚未覆蓋」的項目：IP／Referer 完整 allow／deny 與
precedence、死亡 upstream 502 自訂頁、代理 rewrite URI、primary recovery、
H3 CORS／rewrite／error_page parity。

---

## M6 — 發布（Day 29–34）

### ✅ Day 29 — RC 凍結與品質閘門

- Linux／macOS 的 build／test／fmt／clippy `-D warnings` 全綠。
- dependency audit 沒有未處理的 high／critical advisory；例外需**書面風險接受**。

### ✅ Day 30 — Soak／chaos

- 同一 release binary 至少 **1 小時**混合 static、proxy、SSE、reload、
  backend failure/recovery 與 TLS/H3 流量。
- **完成判定**：零 crash、零卡死、零幽靈程序、**無單調 RSS 成長**。

### ✅ Day 31 — 效能回歸

- 同一 VPS／同一 harness，對比 2026-07-25 baseline：static plain/gzip、
  reverse proxy、20MB streaming。
- **完成判定**：吞吐或 p99 回退超過 10% 必須修復，或在 release notes 以數據解釋；
  streaming RSS 必須維持 bounded。

### 🔨 Day 32 — 發布產物與安裝驗證

- Linux glibc x86_64/aarch64、macOS x86_64/arm64 binary、GHCR image、
  SHA-256 checksums、SBOM、provenance／signature 自動產生。
- x86_64 通用產物**不得依賴建置機的 native CPU features**。
- 每個 binary 在乾淨 runner 啟動 smoke，`pingclair --version` 必須等於 tag。
- 全新安裝、`0.1.7 → 0.2.0` 升級、systemd start/reload/stop、uninstall、
  Docker 啟動與最小 Pingclairfile 都在乾淨環境驗證。

### 🔨 Day 33 — 發布文件

- `CHANGELOG.md`、三語 README、所有 examples、配置參考、安全限制、
  H3 支援矩陣、已知問題、migration notes。
- **完成判定**：所有範例可由 `pingclair validate` 驗證通過。

### 🚀 Day 34 — 發布

只在上述全綠後：改 workspace version 為 `0.2.0` → 帶 emoji 的 release commit
→ signed `v0.2.0` tag → 確認 GitHub Release／GHCR 完成 → 把本目標移入
`docs/STATUS.md`。

---

## v0.2 明確不做

寫在這裡是為了**防止規劃時 scope creep**。以下留到 v0.3+：

- AI Gateway、provider translation、token/cost quota、semantic routing/cache、MCP。
- DNS/Kubernetes discovery、reload-free dynamic backend control plane。
- L4 TCP/TLS passthrough、通用 UDP、Gateway API/xDS、正式 plugin runtime。
- Redis distributed rate limit、非冪等 request body retry、traffic mirror/canary。
- OpenTelemetry/OpenInference、Web UI、ACME DNS-01、ECH、zero-downtime listener handoff。
- 上游 HTTP/3、gRPC-web transcoding、`sub_filter`、目錄 autoindex、fault injection。
- JWT/OIDC/forward auth、external auth/policy hooks、secrets provider 抽象。
- **sticky cookie session persistence**（簽章／rotation／SameSite 做錯有安全後果，
  且 Pingora 不提供這部分；一致性雜湊本身已在 Day 19）。

> `proxy_cache` 原本在這份清單裡，2026-07-27 盤點後**移入 v0.2 的 M3**：
> `pingora-cache` 已提供狀態機、cache lock、eviction、variance 與 predictor，
> 剩下的是策略與正確性。理由見 M3 開頭。

完整的長期功能清單與生態對照理由見 `docs/STATUS.md` 的「v0.3+ 候選」。

---

## 進度追蹤

| 里程碑 | 範圍 | 狀態 |
|---|---|---|
| M1 生產站可替換 | Day 1–7 | 🔨 進行中（Day 1–3 ✔） |
| M2 生產護欄 | Day 8–15 | ⬜ 未開始 |
| M3 接上 Pingora 能力（含 `proxy_cache`） | Day 16–20 | ⬜ 未開始 |
| M4 可觀測性與運維 | Day 21–24 | ⬜ 未開始 |
| M5 協議安全與 H3 | Day 25–28 | ⬜ 未開始 |
| M6 發布 | Day 29–34 | ⬜ 未開始 |

> 完成一天就在對應 Day 標題後標上 `✔ <commit>`；完成一個里程碑就更新這張表，
> 並把驗證證據路徑寫進 `docs/STATUS.md`。
