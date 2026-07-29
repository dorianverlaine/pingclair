# 🎯 Pingclair v0.2.0 執行計畫

> 這份文件只回答一個問題：**今天做什麼**。
>
> - 已完成的項目與驗證證據 → `docs/STATUS.md`
> - 環境限制與實作守則（動手前必讀）→ `docs/GUARDRAILS.md`
> - nginx 功能對照 → `docs/AUDIT_NGINX_PARITY.md`
> - 效能數據與壓測發現 → `benchmarks/README.md`
>
> 最後整理：2026-07-30

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
cargo +1.88.0 fmt --all -- --check
cargo +1.88.0 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.88.0 build --locked --workspace
cargo +1.88.0 test --locked --workspace
```

> ⚠️ `+1.88.0` 不是裝飾。CI 釘這個版本,workspace 也宣告 `rust-version = "1.88"`,
> 而新編譯器的型別推論更寬鬆、rustfmt 換行決策也不同。本機四項全綠然後 CI
> 全紅,2026-07-29 已經發生過一次。

**外加一條**：**這天加的東西,文件當天改**。README／examples／設定參考裡任何
會因為今天的改動而變成假話的地方,今天就改掉。

> 📌 **為什麼不是留到最後一起寫**：2026-07-30 查出來,
> `examples/full_featured.pingclair` 已經壞了三天沒人發現（Day 4 把
> `encode br` 改成編譯錯誤,但沒改用到它的範例）,三份 README 也還在教
> 前一天剛被刪掉的 `proxy_protocol on`。**文件不會在自己變成假話時通知你。**
> 現在有 `pingclair-config/tests/documentation.rs` 會編譯每個範例與每個
> 文件裡的設定區塊,所以「今天改」的成本只有寫字,不用自己找哪裡壞了。

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

- **範圍外（仍留 Day 22）**：rotation／retention／壓縮／bounded async writer。
  目前寫入是同步的，磁碟卡住會擋住呼叫端——這正是 Day 22 存在的理由。

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
  logging 功能），`is_sensitive_header()` 已備妥供 Day 22 記錄 header 時使用。

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

### 🔨 Day 5 — Docker DNS 重解析 ✔

**已完成 2026-07-28。** 新增 `pingclair-proxy/src/dns.rs`；`upstream.rs` 拆出
`UpstreamSpec`／`Resolve`；`load_balancer.rs` 的 selector set 移到 `ArcSwap` 之後。

- ✅ **hostname 才是穩定身分，IP 是會過期的部分**。upstream 不再只保留開機當下
  解析到的位址，而是保留 spec；refresher 依間隔重解析並整批 publish 新 pool，
  request path 讀到的永遠是完整快照，不會看到半更新的 backend list。
- ✅ **解析失敗一律非破壞性**：lookup 失敗時保留前一個位址繼續服務。resolver
  故障（DNS 容器重啟、`resolv.conf` 短暫消失）不該讓站台跟著掛掉——舊位址
  通常還在好好服務。單一名稱失敗也不會連累同 pool 的其他 backend。
- ✅ **開機解析不到的名稱不再被永久丟棄**，會在解析成功後自動加入 pool。
  代理因此可以先於 app 容器啟動，這在 Compose 裡是常態而非例外。
- ✅ **IP 字面位址完全不進 resolver**，literal-only 的 pool 根本不會註冊，
  沒有 hostname 的配置一次 lookup 都不會發。
- ✅ 多筆 A record 的挑選是**確定性**的（IPv4 優先、再依數值排序）。
  `to_socket_addrs` 不保證順序且 glibc 會刻意輪替，直接取第一筆會讓 refresher
  對一個根本沒搬家的名稱每輪都重建 pool。
- ✅ 重解析**不會偷偷讓故障 backend 復活**：沒搬家的位址沿用同一個 down-until
  slot；搬走的位址則整個丟掉，map 不會隨重解析次數無限成長。
- ✅ 重解析後 weight、scheme 與**設定的 hostname**（SNI 與上游 `Host` 都靠它）
  全部保留。
- ✅ `dns_refresh` 全域指令：預設 `30s`，`off` 把 upstream 釘在開機位址。
  單位是必填的——grammar 其他地方把裸數字讀成毫秒，接受 `dns_refresh 30`
  等於默默裝了一場 30ms 的 lookup 風暴。
- ✅ 真 Docker network E2E（`benchmarks/scripts/run_dns_refresh_e2e.sh`，
  真 release image + Docker 內建 resolver）：見下表。
- ✅ Gate 四項全綠，320 → **338 tests**。

| 場景 | 手法 | 結果 |
|---|---|---|
| 開機時 upstream 不存在 | 先起代理再起 app | 502（非 crash／hang），app 起來後 3s 內接管 |
| 容器換 IP | `.10` 容器換成 `.20` 容器（`--ip` 明確指定） | 3s 內跟上，log 有 `from=…10:80 to=…20:80` |
| resolver 失效但舊位址仍健康 | 拔掉 network alias、同容器同位址續跑 | 12s 內持續 200，log 有 `keeping the last known address` |
| 名稱恢復 | 重新掛回 alias | 立即恢復 |
| `dns_refresh off` | 同樣換容器 | 位址維持釘死，不跟隨 |

> ⚠️ **為什麼是受控間隔而不是 TTL**。std resolver 只回位址、不回 TTL，要讀 TTL
> 就得引入完整 DNS client 與它的 transport 依賴；而在最該生效的場景它也買不到
> 什麼——Docker 內建 resolver 回的是 **600s TTL**，遠長於「重啟的容器需要被
> 發現」的時間窗。固定且可設定的間隔既是更小的依賴，也是更緊的上界。

> ⚠️ **順帶修掉一個一直存在的錯誤語意**：route 匹配到 `reverse_proxy` 但沒有
> 可選 backend 時原本回 **500**（`ConnectNoRoute`），與 `load_balancer.rs`
> 自己的註解（「all down → 502, nginx-style」）矛盾，也等於告訴 operator
> 和前面的 LB「是代理壞了」。改成 `HTTPStatus(502)`。這在本日之後更要緊：
> 「名稱還沒解析出來」現在是**正常的暫態**。失敗證據保留在
> `benchmarks/results/20260728_dns_refresh_FAILED_500_not_502/`。

- **範圍外**：一個名稱多筆 A record 目前只取一個位址（不會展開成多個 backend），
  SRV／服務發現、resolver override、TTL/jitter 仍在 v0.3+ 清單。
  每個 listener 各自持有一份 ProxyState，所以同一個 upstream 名稱的 lookup
  次數與 listener 數成正比（本日 E2E 是 2）；量級很小，未動。

### 🔨 Day 6 — matcher JSON round-trip ✔

**已完成 2026-07-28。** `Matcher` 由 `untagged` 改為 **externally tagged**，
並手寫 `Deserialize` 保留 `0.1.7` 舊格式的讀法。

- ✅ **問題比原本記的更大**。untagged 表示法用 payload 形狀辨識 variant，
  而這個 enum 有一半的 variant 形狀根本不可區分：
  - `Not(inner)` 序列化後**就是 inner 本身**，round-trip 直接把否定弄丟 ——
    這是唯一一個會**反轉**路由決策的變換。
  - `Or` 與 `And` 都是二元陣列 → 每個 `Or` 都變成 `And`。
  - `Query` 與 `Header` 都是 `{name, condition}` → 每個 `Query` 都變成 `Header`。
  - `RemoteIp`／`Protocol` 與 `Host` 都是字串陣列。
- ✅ 新表示法：`{"not": {"path": {"patterns": ["/admin/*"]}}}`。tag 就是可還原性。
- ✅ **向後相容**：反序列化先試 tagged，再退回 `0.1.7` 真正能寫出的五種形狀。
  兩者不會混淆——legacy 的 key 是 `patterns`／`methods`／`name`／`condition`，
  沒有一個跟 tag 名撞。
- ✅ 有歧義的 legacy 形狀**保留 `0.1.7` 當時的讀法**而不是猜意圖：
  `{name, condition}` 仍然讀成 `Header`。一份一直被當 `Header` 用的配置，
  不該因為這份程式碼現在分得清楚了就悄悄改成 `Query`——要指定就寫 tag。
- ✅ 無法辨識的 matcher **fail closed**（400／載入失敗），不會退化成 match-all。
- ✅ 真 binary E2E（`scripts/test-matcher-roundtrip.sh`）：Admin `GET /config`
  的 dump 原樣 `POST` 回去後路由行為不變；手寫的 untagged legacy matcher 仍可載入；
  無法辨識的 matcher 回 400。**同一支腳本在修復前的 binary 上會失敗**，
  證據保留在 `benchmarks/results/20260728_matcher_roundtrip_FAILED_prefix/`。
- ✅ Gate 四項全綠，338 → **349 tests**。

> 🚨 **順帶修掉一個可遠端觸發的 DoS**。`Not(Box<Matcher>)` 是 untagged enum 的
> **newtype** variant，所以測試它等於「把整個 payload 再當成一次 `Matcher` 解」
> ——**沒有消耗任何輸入**。任何對不上其他 variant 的值都會無限遞迴；而 serde 的
> untagged replay 不會再走一次 serde_json 的 parser，所以 serde_json 自己的
> recursion limit 從來看不到它。release profile 的 `panic = "abort"` 讓它直接變成
> 程序中止。實測：對 Admin API `POST /config` 送一個
> `{"matcher": {"nonsense": ["/x"]}}` 就能打掛整個 pingclair。
> 證據：`.../FAILED_prefix/server_stack_overflow.txt`。

- **範圍外**：`Query` matcher 的執行期求值仍然是 `true`（router 尚未解析 query
  string）——本日只修表示法，沒有動語意。

### ✅ Day 7 — M1 驗證日：production 演練 ✔

**已完成 2026-07-28。RC = `8294116`（`pingclair:rc-8294116`，linux/arm64）。**
不是 production-like，是**真的那一台**：`aqeonet-aws-tw-xray`，
Amazon Linux 2023 aarch64，`Cloudflare Tunnel → :6688 → app:8080`。

演練分三段，前兩段對線上**零影響**——pingclair 以第四個容器掛進同一個
`aqeo_default`，用同一份配置打同一個 app，Caddy 全程照常服務隧道。

**① 主演練 27/27**（`benchmarks/scripts/run_m1_production_drill.sh`）。
每一項都是**差分**的：同一個請求問 pingclair 也問 Caddy，該相同的地方逐 byte 比。

- ✅ `admin off`（容器內無 admin listener）、自訂 HTTPS port 6688、`tls internal`。
- ✅ 安全標頭：4 條 set 正確、**CSP 與 Caddy byte-identical**、`-Server` 真的移除。
- ✅ 三類 Cache-Control 與 `not path` AND 語意（`/api`、`/assets` 都沒漏進 `@rest`）。
- ✅ 壓縮協商 zstd／gzip／identity 全對，**gzip 解出來與 Caddy byte-exact**。
- ✅ 真實 client IP：受信隧道網段的 `CF-Connecting-IP` 被採用。
- ✅ JSON log 與 redaction：query token、Cookie、Authorization、Referer 的 `?code=`
  **全數未進 log**。
- ✅ internal CA 重啟：root 同一把、**leaf 重用而非重簽**。
- ✅ `/` 與 `/api/ping` body 與 Caddy byte-identical；H2 協商成功；
  SIGTERM exit 0 沒被 SIGKILL。

**② DNS 恢復與 reload**，同樣零影響：

- ✅ `run_dns_refresh_e2e.sh` 在 Linux arm64 真 image 上全過。
- ✅ SIGHUP 套用新配置且 listener 不斷；**壞配置被拒且 last-known-good 續服務**。

**③ 真實切換與回滾**（`deployment/switch-proxy.sh`）：

- ✅ 切到 pingclair 後隧道 4 條連線乾淨註冊，**reconnect 之後 origin 錯誤數 0**。
- ✅ 真瀏覽器實際使用（已登入 session、IPv6 client）：`/`、`/api/*`
  路由正確，`client_ip` 是 CF 給的訪客位址而非隧道容器位址，
  `referer` 的 query 被剝掉。
- ✅ **回滾 8.9 秒**，一條命令；Caddy 全程沒停過。
- ✅ 目標「起著但服務不了」時**拒絕切換**並保持現況（用壞配置實測）。

**完成判定達成**：可以宣稱「可以替換那台 Caddy」——因為它現在就在替換。

> ⚠️ **必須說清楚的範圍**：
> - 隧道那一跳實測是 **HTTP/1.1**（cloudflared 對 origin 預設不開 h2，
>   要 `http2Origin: true`）。**H2 是在 origin 直接驗的**，不是經隧道驗的。
> - 公網路徑無法用 curl 驗——Cloudflare 的 managed challenge 在**邊緣**就回 403，
>   請求根本到不了源站。改用真瀏覽器加源站 access log 交叉確認。
> - client IP 偽造的**否定面**（未受信來源不得偽造）沿用 2026-07-27 的專用
>   fixture，本次未在受信網段內重驗。
> - `aqeo-pingclair` **不在 `docker-compose.yml` 裡**，由 `switch-proxy.sh` 管理
>   （有 `--restart unless-stopped`）。要長期留著就該收進 compose。

> 🤡 這天踩到的三個雷**全部在測試腳本裡，一個都不在產品**，其中
> `sed -i` 換 inode 那個造成**兩條假性通過**。三條都已寫進 GUARDRAILS。

---

## M2 — 生產護欄（Day 8–15）

讓它在壓力、故障與惡意流量下不會失控。

### 🔨 Day 8 — 資源邊界與 timeout ✔

**已完成 2026-07-29，本機 gate 全綠，尚待 Day 15 遠端驗證。**

- ✅ 新增 fail-closed `limits` DSL、compiler 與向後相容 JSON default：
  header read、request body、idle、整體 request timeout，header count／bytes、
  listener connection、upload／download bytes-per-second。
- ✅ `reverse_proxy transport http` 新增 connect、first-byte、between-reads timeout；
  舊 `read_timeout`／`write_timeout` JSON 行為保留。H1/H2 因 Pingora 0.8 只暴露
  一個 upstream read timer，採兩階段中較嚴格者；H3 在 response header 後
  切換到 between-reads timer。
- ✅ H1/H2 在 parser 前限制 header slowloris 與 connection 數；選定 vhost 後
  再限制 decoded header count／bytes。H3 共用同一份配置，並維持既有 bounded
  request／response channels，不新增完整 body buffer。
- ✅ request body、靜態／本機 handler 與反代 body 都以 chunk 計數並套用
  timeout／bandwidth；large body 的記憶體上限仍由既有 chunk/channel 邊界決定。
- ✅ `flush_interval -1`、`text/event-stream`、H1 WebSocket upgrade 會切換到
  可獨立設定的 `long_connections` idle／request policy；`off` 可明確取消期限。
- ✅ **完成判定**：真 binary 測試實際超過 header read、body、idle、整體 request、
  upstream connect／first-byte／between-reads、header count／bytes、connection、
  upload／download bandwidth 上限；分別得到 431、413、408、504、503 或明確
  transport close，沒有任何 case 掛住。SSE 與 WebSocket 均在一般 100–150 ms
  deadline 後仍成功傳輸。總測試數 354 → **362**。
- ✅ regression 先紅後綠：h2c preface peek 原本繞過 header timeout；connect timeout
  經安全 redispatch 後原本退化為 502。失敗證據保留於
  `benchmarks/results/20260729_day8_local_failed_header_timeout/` 與
  `benchmarks/results/20260729_day8_local_failed_connect_status/`；
  content-type 才辨識出的 SSE regression 則保留於
  `benchmarks/results/20260729_day8_local_failed_sse_content_type/`。
- ✅ Gate：`cargo fmt --all -- --check`、locked clippy、locked workspace build、
  locked workspace tests 全綠。

- **範圍外／尚未驗證**：
  - 尚未做乾淨 Linux release、VPS 或真 QUIC client 矩陣；不得列為遠端完成。
  - H3 extended CONNECT／WebSocket 原本即不支援，仍明確回 501；本日長連線
    WebSocket policy 只涵蓋已支援 tunnel 的 H1/H2 路徑。
  - H1/H2 的 first-byte 與 between-reads 無法比 Pingora 公開 API 更細分；
    採較嚴格值可保證不超限，但可能比 H3 提早中止。若未設定 phase timer、
    卻配置 long-connection idle policy，H1/H2 upstream read 會先採該 long
    bound，讓 response header 可依 content type 升級；一般 request deadline
    仍於每個 proxy phase 邊界 fail closed，而非中途改寫 Pingora 的 read future。
  - H1/H2 的 pre-routing header timeout、H2 field-section cap 與 connection
    semaphore 在 listener 建立時擷取；修改這三項目前需要 restart。其他選定
    vhost 後套用的 body／request／bandwidth policy 可隨 hot reload 更新。

### 🔨 Day 9 — 可配置 retry／redispatch ✔

**已完成 2026-07-29，本機 gate 全綠，尚待 Day 15 遠端驗證。**

- ✅ `reverse_proxy retry` 新增最大嘗試次數（含第一次）、總時限、固定 backoff、
  可重試狀態碼與方法；DSL、compiler、JSON 與舊設定 default 均有測試。
- ✅ H1/H2 的 Pingora lifecycle 與獨立 H3 bridge 共用同一份 policy。
  connect failure 只在尚未送出 request 時安全切換後端；status redispatch 則必須是
  設定允許的冪等方法，而且 request 實際沒有 body。
- ✅ 每個 request 追蹤已嘗試位址，Round Robin、Random、Least Conn 與 IP Hash
  都會先避開該集合；候選全部走過後，只有 status policy 可以在剩餘 budget 內
  重新走一輪。原有 passive health cooldown 仍負責跨 request 排除 connect failure。
- ✅ **完成判定**：真 binary 覆蓋 `max_attempts` 1／2、503→200、最終 503、
  固定 backoff 與總時限；POST body 只送一次，已列入 methods 的 PUT 帶 20 MiB
  body 也只串流一次。H3 bridge 另以單元整合測試確認 503→200。
  總測試數 362 → **368**。
- ✅ regression 先紅後綠：暫時移除 status 判斷後，真 binary 的 `/success`
  固定停在 503；失敗證據保留於
  `benchmarks/results/20260729_day9_local_failed_status_retry/`。測試 fixture 與
  locked clippy 途中發現的失敗也各自保留，未覆寫。
- ✅ Gate：`cargo fmt --all -- --check`、locked clippy、locked workspace build、
  locked workspace tests 全綠。

- **範圍外／尚未驗證**：
  - 非冪等 body replay、AI POST fallback、`Idempotency-Key` 與 memory／disk replay
    policy 均未實作；v0.2 不會為 retry 緩衝完整 request body。
  - backoff 目前只有固定間隔，沒有 exponential、jitter 或 `Retry-After`。
  - 尚未做乾淨 Linux release、VPS 或真 QUIC client 矩陣；留到 Day 15，
    因此本日仍是 🧪，不是遠端 ✅。
  - **未來方向（不在 v0.2）**：POST／AI request 若要支援重試，必須有明確
    opt-in、`Idempotency-Key`，以及**有上限的** memory／disk replay 策略；
    禁止悄悄全量緩衝無上限 body。

### 🔨 Day 10 — Circuit breaker／overload protection ✔

**已完成 2026-07-29，本機 gate 全綠，尚待 Day 15 遠端驗證。**

- ✅ `reverse_proxy overload`：route `max_in_flight`、bounded `max_pending`、
  `pending_timeout`，以及每個 backend 的 `upstream_max_connections` request
  occupancy cap；queue 滿快速回 429，等待逾時或 backend 全部滿載回 503。
- ✅ `reverse_proxy circuit_breaker`：每個具體 backend 分開計算連續失敗與 bounded
  rolling error-rate window；open 到期後只放行受限 half-open probes，成功關閉、
  失敗重新 open。
- ✅ H1/H2 與獨立 H3 bridge 共用同一份 admission/circuit state；沒有新增 body
  buffering，等待期間仍由既有 transport backpressure 與 bounded H3 channel 控制。
- ✅ 相容的 Admin／SIGHUP hot reload 保留 active/open/half-open 狀態；政策或設定的
  upstream 集合改變時重建，避免舊門檻污染新政策與舊位址狀態無限累積。
- ✅ Prometheus 輸出 route in-flight/pending、upstream occupancy、拒絕原因、circuit
  狀態與轉換；真 binary 覆蓋 queue full／timeout、upstream cap、open → half-open
  → closed，以及 open state 跨 Admin reload 保留。
- ✅ 總測試數 368 → **375**。
- ✅ regression 先紅後綠：Admin API 原先走 `add_server` 重建 state，open circuit
  reload 後意外回源；修正後同一真 binary 測試通過。失敗證據保留於
  `benchmarks/results/20260729_day10_local_failed_admin_reload_state/`。
- ✅ Gate：`cargo fmt --all -- --check`、locked clippy、locked workspace build、
  locked workspace tests 全綠。

- **範圍外／尚未驗證**：
  - `upstream_max_connections` 是保守的 request occupancy cap（也限制 H2
    multiplex），不是實體 socket pool 計數；Pingora 0.8 未公開可可靠掛接的
    per-route physical connection counter。
  - 尚未做乾淨 Linux release、VPS 或真 QUIC client 矩陣；留到 Day 15，
    因此本日仍是 🧪，不是遠端 ✅。

### 🔨 Day 11 — 上游 TLS／mTLS ✔

**已完成 2026-07-29，本機 gate 全綠（1.88.0 與 1.97.1 各跑一次），尚待 Day 15 遠端驗證。**

- ✅ 新增 `pingclair-proxy/src/upstream_tls.rs`：**設定載入時編譯一次**，
  request path 只 clone `Arc`。PEM 解析不上熱路徑，也不會讓憑證輪替在
  route 之間半生效。
- ✅ DSL（Caddy 相容）：`transport http { tls, tls_server_name, tls_trusted_ca_certs,
  tls_client_auth, tls_insecure_skip_verify }`。
- ✅ **預設就是驗證的**：Pingora `verify_cert`／`verify_hostname` 預設為 true，
  且 `pingora-proxy` 一定帶 `ConnectorOptions`，所以 system trust store 有被載入。
  這次確認過而不是假設——真 handshake 測試證明未受信的 self-signed origin
  會被拒，body 不會外流。
- ✅ **trust roots 是「取代」不是「疊加」**：`SSL_set1_verify_cert_store` 覆蓋整個
  store，所以 pin 內部 CA 的 route 不會同時接受公開 CA 簽的同名憑證。已寫進 doc。
- 🐛 **修掉一個信任外洩**：`HttpPeer` 的 reuse hash 有算 client cert／verify flags，
  **但沒有算 CA bundle**。同位址、同 SNI、不同 trust roots 的兩條 route 會共用
  pooled connection，嚴格的那條會沿用寬鬆那條驗過的 session。改成把 TLS identity
  打包進 `group_key` 高位、protocol group 留低 8 bits（`peer_protocol_group()`）。
- ✅ **可操作的診斷**：每個錯誤都帶檔案路徑與角色（trust root／client certificate／
  client key）。額外做了 **cert/key 配對檢查**（`public_eq`）——BoringSSL 在設定期
  接受不匹配的一對，只在 handshake 才爆，而上游的 `bad certificate` alert 跟十幾種
  無關的網路問題長得一模一樣。
- ✅ **fail closed**：TLS 素材載入失敗的 route 標記為 `Broken`，H1/H2 與 H3 bridge
  **都**回 500 並記 ERROR，絕不退回「system trust ＋ 無 client cert」——那正是
  operator 寫這個 block 要防的連線。其他 route 照常服務。
- ✅ **矛盾組合一律拒絕**：`tls_insecure_skip_verify` 不可與 `tls_trusted_ca_certs`
  或 `tls_server_name` 併用；`tls_client_auth` 必須兩個檔案。**DSL 與 JSON 兩條路
  都擋**——Admin API 直接吃 config document，只擋 adapter 等於沒擋（Day 6 教訓）。
- ✅ 憑證輪替：reload 重讀同一批路徑；輪替後 `pool_key` 改變，舊憑證開的連線不會
  被新身分沿用；只換憑證沒換 key 的半套輪替會在 reload 當下失敗並同時點名兩個檔案。
- ✅ `tls` 只加密不擴 ALPN：scheme-less upstream 升級成 TLS 但仍只 offer HTTP/1.1，
  `h2c://` 不動。要 h2 over TLS 就寫 `h2://`／`https://`。
- ✅ 真 handshake 整合測試（self-signed origin，同一份 origin 程式碼三段對照）：
  預設拒絕 → pin 該憑證後 200 → `insecure_skip_verify` 也 200。
  **連跑 30 次全綠**（`--test-threads=2`）。
- ✅ 總測試數 377 → **408**。
- ✅ Gate：fmt、clippy `-D warnings`、`build --locked`、`test --locked` 在
  `cargo +1.88.0` 與預設工具鏈上各跑一次全綠。

- **範圍外／尚未驗證**：
  - **沒有做檔案 watcher**：輪替只在 reload（SIGHUP／Admin）時生效，不是自動偵測。
  - 沒有暴露 `alternative_cn`（送 SNI X 但接受憑證名 Y）——Caddy 沒有對應語法，
    不想自創；`tls_server_name` 已覆蓋實際需求。
  - 憑證到期只以 `notAfter` 字串呈現在 log，沒有做「快過期」比較：
    `pingora_core::tls` 沒有 re-export `asn1`，為此加 `boring` 直接依賴不划算。
  - 尚未做乾淨 Linux release、VPS 或真 mTLS 上游矩陣；留到 Day 15，本日是 🧪。

### 🔨 Day 12 — 健康檢查補齊 🧪

> 💡 **這天比預期便宜**：`pingora-load-balancing::health_check::HttpHealthCheck`
> 已經提供 `req`（自訂 Host／method／headers）、`validator`（status／body 檢查）、
> `port_override`（不同 health port）、`consecutive_success/failure` 門檻、
> `reuse_connection` 與 `health_changed_callback`。主要工作是**接線與 DSL**，
> 不是從零實作。

> 🚨 **但比預期少了一塊**（2026-07-28 於 Day 5 改動時發現）：主動健康檢查
> 目前**根本沒有在跑**。`HealthChecker` 有被建出來、`health_check_frequency`
> 有被設定，但驅動它的 Pingora background service **從來沒有註冊**——
> 全 workspace 沒有任何 `background_service`／`run_health_check` 呼叫，
> `LoadBalancer::native()` 的呼叫者數量是 **0**。也就是說今天能運作的只有
> `fail_to_connect` 的被動標記，`select` 讀到的 `ready` 永遠是初始值。
> 這天的第一件事是把 background service 接上，不是調 DSL。

- **先把 background service 註冊起來**，讓已經配置好的主動檢查真的執行；
  加測試證明「upstream 掛掉但沒有流量打過去」時也會被摘除——這正是被動
  標記做不到、而主動檢查存在的理由。
- 把上述 Pingora 能力接進 DSL 與 runtime。
- 注意 DNS 重解析會重建 pool（Day 5），健康檢查設定必須跟著新 pool 一起重建；
  `LoadBalancer` 已保存設定並在 `publish` 時重套，接線時不要繞過它。
- 限制讀取 body 大小；為 probe 加 jitter／backoff，避免 health check 自己
  變成同步尖峰。
- slow start recovery（Pingora 未提供，需自己做）。
- **完成判定**：故障節點能被正確摘除並在恢復後重新加入，**且該摘除發生在
  沒有請求經過該節點的情況下**（否則就只是驗到被動標記）。

**已完成 2026-07-30（Codex 實作，本機 gate 全綠）。**

- ✅ `HealthCheckDriver` 是真的 Pingora `BackgroundService`，經 `Weak` registry
  驅動所有 pool（與 `dns.rs` 同一個模式），DNS 換代後 checker 狀態跟著重建。
- ✅ probe peer 套用該 route 的 Day 11 TLS policy，pin 私有 CA 的 route 不會被
  健康檢查全數標成 down。TLS policy 載入失敗時**不啟動**健康檢查並記 ERROR。
- ✅ 紅燈先行證據：`benchmarks/results/20260729_day12_local_failed_active_health/`
  ——停掉一個 origin、**完全不送流量**、兩個 probe 週期後第一個請求回 502。
- ✅ probe body 有上限、jitter、全滅時 backoff（上限 8×）、slow start。
- 🐛 **review 時修掉一個可用性 bug**：`check_inner` 只替換位址，
  `sni`／`Host` 沿用 **first backend** 的名字。`to https://a.internal` ＋
  `to https://b.internal` 這種 pool 會用 a 的 SNI 去探 b，hostname 驗證必失敗，
  b 被永久標成 down，而它其實服務得好好的（正常流量走 `build_http_peer`，
  用的是各自的名字）。現在改讀每個 backend 自己的 `HostName` ext，
  operator 明寫的 `health_check.host`／`tls_server_name` 優先。
  失敗證據：`benchmarks/results/20260730_day12_review_failed_probe_sni/`。

### 🔨 Day 13 — Rate limit 語意補齊 🧪

現有 `burst` 未真正生效，key 只有 IP／global，remaining 是估算值。

- 補 token bucket／GCRA、burst、dry-run、route／API key／header／tenant key。
- 輸出標準 `RateLimit-*` 與 `Retry-After`。
- **範圍外**：Redis distributed limit 不列入 v0.2。
- **完成判定**：burst 行為與 header 數值正確，不是估算。

### 🔨 Day 14 — PROXY protocol 與 RFC 7239 🧪

`trusted_proxies` 與受限 XFF 解析已完成（見 STATUS）。剩下：

- PROXY protocol v1／v2 listener。
- RFC 7239 `Forwarded` header 解析。
- **完成判定**：三種來源（XFF／Forwarded／PROXY protocol）的 verified client IP
  一致，且未受信來源無法偽造。

**已完成 2026-07-30（Codex 實作，本機 gate 全綠）。**

- ✅ PROXY protocol v1／v2 有界解析，未受信 transport peer 在 accept 後立即丟棄。
- ✅ RFC 7239 `Forwarded` 有界解析；與 XFF 衝突時**兩邊都不信**，退回 socket
  peer（不可偽造的那個值）。信任閘門在讀任何 header 之前。
- ✅ 身分 registry 有 TTL 與雙路徑修剪，`register` 在轉發第一個 byte 之前完成。
- 🐛 **review 時修掉一個 Day 8 保證的回歸**：ingress 完全沒有 admission
  control，`limits { max_connections }` 只再管內部那一跳，外部連線無上限。
  已補上同一個上限，信任檢查排在取 permit 之前。證據：
  `benchmarks/results/20260730_day14_review_failed_ingress_limit/`。

> ⚠️ **架構限制（Pingora 0.8 沒有更好的路）**：PROXY protocol 是「公開 ingress
> ＋ 本機 loopback 中繼 → 私有 Pingora listener」。Pingora 0.8 的 listener 不懂
> PROXY protocol，也不接受既有 FD，所以無法在 listener 上原地解析。代價是
> 每條外部連線多一個 fd、一個 task 與一次 userspace copy。
>
> 另有一個 TOCTOU：私有位址是先 bind `127.0.0.1:0` 取得再釋放給 Pingora 綁。
> 窗口極小且是 loopback ephemeral port，但**本機上的對手若搶到該 port，
> ingress 會把外部流量轉給它**。同樣受限於 Pingora 0.8 沒有 FD 傳遞。
> Day 15 要在真機確認一次；長期解法是等上游或改用 socket activation。

- ✅ **改成 per-listener（2026-07-30）**：`listen :8443 proxy_protocol`，
  就是 nginx 的寫法。全域開關**整個移除**——它從未進過任何 release，
  所以不留相容包袱。這個介面一旦隨 `0.2.0` 發布就改不動了，所以趕在凍結 RC
  之前修完，而不是拿一個已知是錯的設定介面去做遠端驗證。
  - `listen` 的多餘參數以前被靜默丟棄，`listen :443 proxy_protocol` 會產生一個
    「名字寫了但其實不要求」的 listener。現在未知 flag 一律拒絕。
  - core config 用 `proxy_protocol_listen: Vec<String>`（`listen` 的子集），
    `listen` 的形狀不動,所以 Admin dump→post 原樣往返，舊文件照常載入。
  - 三種寫錯法全部 fail closed：位址不在 `listen` 裡（打錯字）、同一個 port
    被兩個 server 給出不同答案（一個 socket 不能有兩個答案）、要求 header
    但沒有 `trusted_proxies`（那會拒絕所有連線）。DSL 與 JSON 兩條路都擋。
  - 真 binary 測試：同一個 process 兩個 listener，直連的那個不帶 header 回 200，
    L4 那個帶 header 回同一條 route、不帶 header 被拒。連跑 30 次全綠。

### ✅ Day 15 — M2 驗證日

凍結 RC，在乾淨 Linux／VPS 驗證 Day 8–14 全部項目，加上先前積欠的
🧪 項目：bcrypt basic auth、`gzip_types`、上游協議選擇。

---

## M2.5 — 協議硬化（Day 16）

### 🔨 Day 16 — 協議安全回歸集

**這是 v0.2 唯一還沒動的 R0 項目，優先度其實很高**——最新 Caddy／nginx 仍然
在修 rewrite、header、H2/H3 解析漏洞，一般功能測試抓不到這類問題。

> 📌 **2026-07-30 從 Day 25 提前到這裡。** 原本排在 M5,結論是排錯了。
>
> 理由一:**這個 codebase 的嚴重問題目前都是「撞到」的,不是「找出來」的。**
> Day 6 在修 matcher 表示法時順手撞到一個可由 Admin API 遠端觸發的
> stack-overflow DoS(畸形 matcher → untagged newtype variant 無限遞迴);
> Day 14 的 PROXY ingress 讓 `limits { max_connections }` 失效,是 review
> 時看出來的,沒有任何功能測試會抓到。兩個都不是被搜出來的。
> 同類還有多少沒人知道——而這一天正是把「畸形輸入打進 parser」這整類
> 系統性覆蓋掉的日子。
>
> 理由二:**M3 是加速功能,不是安全功能。** 快取讓它更快,不讓它更穩。
> 先護欄後加速,順序不該倒過來。
>
> 理由三:**這一天會給 Day 18 打地基。** 快取正確性要跟 URI 正規化、
> header 語意、hop-by-hop 規則同時成立;先把那些邊界釘死,Day 18 才有
> 可以依賴的東西。

- H1/H2/H3 的 URI／header 正規化、hop-by-hop headers、重複
  `Content-Length`／`Transfer-Encoding`、oversized headers、request smuggling、
  malformed frame 的**負向測試**。
- 可用 proptest／fuzzing，並與 nginx／Caddy 做差異測試。
- **完成判定**：每一類都有明確的拒絕行為與測試。


## M3 — 接上 Pingora 已提供的能力（Day 17–21）

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

> ✅ **鏈結相容性已實測（2026-07-28，macOS arm64）**，不再是推論。
> 在 `40d3b20` 上開丟棄分支加入
> `pingora-cache = { version = "0.8", default-features = false, features = ["boringssl"] }`
> 並強制一個 `pingora_cache::CachePhase` 符號進入鏈結：
> debug 與 release 都連得起來、`--version` 正常、349 tests 全綠、
> 沒有 SIGBUS；依賴圖仍然只有一份 BoringSSL
> （`boring-sys 4.22.0` + `pingora-boringssl 0.8.1`），**沒有 `openssl-sys`**。
> 實驗後已完整還原。
>
> ⚠️ **只驗了 macOS**。GUARDRAILS 記錄的失敗模式包含 *Linux link error*，
> 這一半還沒關掉。Day 7 本來就會建 Linux release image，順手在那個環境
> 補建一次帶 `pingora-cache` 的 binary 即可關閉——不需要額外開一天。
>
> 📦 **新發現的依賴面**：`pingora-cache` 會**無條件**帶進
> `cf-rustracing` 與 `cf-rustracing-jaeger`。不是 blocker，但 v0.2 的
> 「明確不做」把 OpenTelemetry 排除在外，這等於從側門進來一套 tracing 依賴。
> Day 29 的 dependency audit 與產物大小要把它算進去。

### 🔨 Day 17 — 接上 pingora-cache 骨架

- 加入 `pingora-cache` 依賴與 `cache` feature。BoringSSL 鏈結已於
  2026-07-28 在 macOS 實測通過（見上），這天只需確認 Linux 那一半。
- 接上 `request_cache_filter`／`cache_key_callback`：定義 host＋path＋query
  的 cache key，memory storage 先跑通。
- **完成判定**：同一 URL 第二次請求命中快取，且有測試證明沒有回源。

### 🔨 Day 18 — 快取策略與正確性

**這天是整個 M3 的風險所在**，快取的 bug 不會讓服務掛掉，只會安靜地回錯內容。

- `ETag`／`Cache-Control`／`Vary` 語意（用 pingora 的 `cache_control` 與
  `variance`）。**要跟 Day 4 的壓縮協商一起想**,不是分開想。
- **預設 bypass**：`Authorization`、`Cookie`。
- **必須排除**：SSE、upgrade、`flush_interval: -1` 的串流回應。

> 🔁 **這個錯誤這個專案已經犯過兩次,而且是在兩個不同的 crate 各犯一次**:
> `ecf7b45` 靜態檔的冷快取 gzip 驚群(20MB benchmark 峰值 RSS
> **374 MiB → 21 MiB**),以及 `7100e83` 反代把 SSE／`flush_interval: -1`
> 的回應送進 gzip filter 而緩衝掉。同一個形狀、獨立犯兩次——所以它是護欄
> 而不只是兩個修好的 bug。**快取會是第三個可以犯同一個錯的地方**,
> 而且這次它還疊在壓縮之上:存壓過的還是沒壓的、`Vary: Accept-Encoding`
> 漏了會讓 zstd client 拿到 gzip body。
- range 請求與 negative cache（404/5xx 的短 TTL）。
- **完成判定**：每一條 bypass／排除規則都有負向測試——證明它**沒有**被快取。
  ⚠️ 2026-07-30 的教訓:**一條不可能失敗的否定斷言不是測試**。當時
  `trusted_proxies` 寫得太寬,涵蓋了測試 client 的來源,於是「未受信來源
  不能偽造 header」那條斷言永遠會過。這一天整天都是否定斷言,每一條都要
  先確認它**能夠**失敗。

### 🔨 Day 19 — 快取運維面

- cache lock（single-flight）與 predictor 接線，避免回源驚群。
- eviction 策略與 **memory/disk tier 硬上限**。
- hit／miss／stale／bypass／eviction 指標。
- 受權限保護的 inspect／purge API。
- **完成判定**：上限確實生效（超過會 evict 而不是無限長大）；purge 需認證。

### 🔨 Day 20 — 一致性雜湊 LB

> 💡 `pingora-ketama` 與 `pingora-load-balancing::selection::consistent`
> 已提供 ketama 一致性雜湊；`selection::weighted` 提供加權。

- 接上 consistent hash，支援 header／cookie／query 作為 hash key。
- **範圍外**：sticky cookie 簽章／rotation 留到 v0.3（那部分 Pingora 不提供，
  且做錯有安全後果）。
- **完成判定**：backend 增減時 key 重映射比例符合一致性雜湊預期。

### ✅ Day 21 — M3 驗證日

凍結 RC，在乾淨 Linux 驗證快取正確性（尤其是 bypass／排除規則）、
上限、purge 與一致性雜湊。

> ⚠️ 快取驗證必須包含**壓測**：確認快取沒有把 20MB 串流變回全量緩衝
> （這是專案歷史上出現過兩次的同類 bug，見 GUARDRAILS）。

---

## M4 — 可觀測性與運維（Day 22–25）

讓它可以被值班的人操作。

### 🔨 Day 22 — Access log 完整化

Day 2 做了配置驅動的輸出，這天做生產級韌性。

- file output 支援依大小／時間 rotation、retention、壓縮、access/error 分流。
- 非同步寫入必須有 bounded queue、明確 backpressure／drop 策略與
  dropped-log metric。
- **完成判定**：磁碟寫滿或 writer 落後時**不得拖死 request hot path**（要有測試）。

### 🔨 Day 23 — Metrics 與 readiness

- `/live`、`/ready`、config version、route/status、upstream latency/error、
  retry、circuit/queue、pool、TLS、H3 指標。
- **所有 label 有 cardinality 上限**：禁止把原始 path、user ID 直接當無界 label。
- systemd `Type=notify`：只在 listener、初始配置與必要依賴真正可用後才送
  `READY=1`，並支援 watchdog。
- **完成判定**：程序存活但尚未可接流量時，`/ready` 必須是 not ready。

### 🔨 Day 24 — Reload／shutdown 可操作

- 配置更新原子套用；錯誤配置保留 last-known-good。
- 手動憑證目錄的新增／更新／刪除需**原子刷新** H1/H2/H3 certificate table；
  畸形或半寫入檔案保留 last-known-good 並輸出可操作診斷。
- **v0.2 可明示 listener topology 變更需要 restart**，不假裝已經 zero-downtime。
- **完成判定**：SIGHUP／SIGTERM／systemd restart／upstream drain 有真 binary 測試。

### ✅ Day 25 — M4 驗證日

凍結 RC，驗證 log rotation／redaction、metrics、readiness、reload／shutdown
在乾淨 Linux 的實際行為。

---

## M5 — 協議矩陣與 H3（Day 26–28）

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

## M6 — 發布（Day 29–36）

### ✅ Day 29 — RC 凍結與品質閘門

- Linux／macOS 的 build／test／fmt／clippy `-D warnings` 全綠。
- dependency audit 沒有未處理的 high／critical advisory；例外需**書面風險接受**。
  含 `site/` 的 `npm audit`——文件站的依賴樹也是這個專案發布出去的東西。

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

### 🔨 Day 33 — 設定參考手冊

原本 Day 33 是「一天寫完所有文件」,2026-07-30 拆成三天。理由：光是設定表面
就有 `limits`（10 條）、`reverse_proxy` 底下 7 個子區塊、`rate_limit`、
`upstream_tls`、listen flags、tls、encode、matchers、handle/handle_path、
access_control、cors、basic_auth、rewrite、error_page、log,再加 M3 的快取與
M4 的 metrics。一天寫完的品質會是「能交差」而不是「能用」。

- 每個 directive：語法、預設值、有效範圍、**錯誤時的行為**、與 Caddy 的差異。
- 補完 M1–M2 積欠的部分（Day 1–15 加的東西目前只有 commit message 講過）。
- 安全限制與 H3 支援矩陣；**明確寫出不支援什麼**,不是留白。
- **完成判定**：`cargo test -p pingclair-config --test documentation` 全綠,
  且參考手冊裡每個 directive 都能在 `examples/` 找到一個可驗證的用例。

### 🔨 Day 34 — 官網與 README

- **Astro ＋ Starlight**。選它不是因為好看（雖然是）,而是因為這個專案
  **已經是三語的**,而 Starlight 的 i18n 是一級支援——語言切換、per-locale
  導航、缺翻譯 fallback 全內建。mdBook 每翻一次痛一次。
  上游 Cloudflare 的開發者文件也是這套,對一個蓋在 Pingora 上的東西算順。
- **必須關住的四件事**（Rust repo 裡多一棵 Node 依賴樹不是零成本）：
  - `site/` 自己的 `package.json` 與 lockfile,**不進 cargo workspace**；
  - CI 獨立 job,site 壞掉**不得**擋 Rust 的 merge；
  - `npm audit` 併進 Day 29 的 dependency audit；
  - **設定範例單一來源**——把 `site/src/content/` 加進
    `tests/documentation.rs` 的掃描範圍。站上出現一份繞過守衛的範例,
    2026-07-30 修的問題三個月後會原樣長回來。
- landing page 依賴的是**效能數字**,所以它必須在 Day 31 之後才寫。
- 三語 README 收斂成「入口 ＋ 連到站上」,不再各自維護一份完整文件。
- **完成判定**：站可離線建置；三語導航皆可用；站上每個設定區塊都被守衛編譯過。

### 🔨 Day 35 — CHANGELOG 與 migration

- `CHANGELOG.md`：`0.1.7 → 0.2.0` 的完整條目,含**行為變更**與**移除的設定**。
- migration notes：`proxy_protocol` 從全域改成 per-listener、`encode br` 變成
  編譯錯誤、global block 不再吞未知 directive——這三個都會讓舊設定**啟動失敗**,
  必須逐條寫出「舊寫法 → 新寫法」。
- 已知問題清單。
- **完成判定**：拿一份 `0.1.7` 的真實設定,照 migration notes 改完能通過
  `pingclair validate`。

### 🚀 Day 36 — 發布

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
- OpenTelemetry/OpenInference、Web UI、ECH、zero-downtime listener handoff。
- **ACME DNS-01（v0.3 具名優先項）** — 2026-07-27 上調優先級。
  目前只有 HTTP-01，這直接擋掉 **wildcard 憑證**（`*.example.com` 只能走 DNS-01）
  與 **80 埠不可用**的部署（雲端 LB 後方、ISP 封鎖、純內網）。
  兩者都不是邊緣情境，使用者會第一天就踩到。至少需要主流 DNS provider
  與 manual 模式。詳見 `STATUS.md`「憑證能力的已知缺口」。
- 上游 HTTP/3、gRPC-web transcoding、`sub_filter`、目錄 autoindex、fault injection。
- JWT/OIDC/forward auth、external auth/policy hooks、secrets provider 抽象。
- **sticky cookie session persistence**（簽章／rotation／SameSite 做錯有安全後果，
  且 Pingora 不提供這部分；一致性雜湊本身已在 Day 20）。

> `proxy_cache` 原本在這份清單裡，2026-07-27 盤點後**移入 v0.2 的 M3**：
> `pingora-cache` 已提供狀態機、cache lock、eviction、variance 與 predictor，
> 剩下的是策略與正確性。理由見 M3 開頭。

完整的長期功能清單與生態對照理由見 `docs/STATUS.md` 的「v0.3+ 候選」。

---

## 進度追蹤

| 里程碑 | 範圍 | 狀態 |
|---|---|---|
| M1 生產站可替換 | Day 1–7 | ✅ **完成**（`8294116`，2026-07-28 真站驗收） |
| M2 生產護欄 | Day 8–15 | ✅ **完成**（矩陣 23/23、原站 M1 回歸 27/27、已上線;浸泡進行中） |
| M2.5 協議硬化 | Day 16 | ⬜ 未開始（**由 M5 提前**：先護欄後加速） |
| M3 接上 Pingora 能力（含 `proxy_cache`） | Day 17–21 | ⬜ 未開始 |
| M4 可觀測性與運維 | Day 22–25 | ⬜ 未開始 |
| M5 協議矩陣與 H3 | Day 26–28 | ⬜ 未開始 |
| M6 發布 | Day 29–36 | ⬜ 未開始 |

> 完成一天就在對應 Day 標題後標上 `✔ <commit>`；完成一個里程碑就更新這張表，
> 並把驗證證據路徑寫進 `docs/STATUS.md`。
