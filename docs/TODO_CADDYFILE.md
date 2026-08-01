# 🎯 Caddyfile 相容性專項執行計畫（獨立 TODO）

> 📌 本文件是**獨立的工作計畫**，只處理 Caddyfile 相容性補齊。
> `docs/TODO.md`（v0.2 主計畫）目前**暫停**，不與本文件混排。
> 完整需求清單與來源 → `docs/CADDYFILE_COMPATIBILITY_MASTER.md`
> （95+ 項）；各專項細節 → `docs/CADDYFILE_*.md`；官方文檔快照 →
> `vendor/caddy-docs/`。

## 工作節奏

- 一次只做一個 Part；Part 內可以拆多次 commit。
- 每個 Part 結束時跑完「Part 收工條件」（見 §3），再進下一個。
- 一個 Part 內不混「修 bug」與「加新功能」以外的類型；驗證與修復
  在同一個 Part 內完成（本專項是逐項補齊，不採 v0.2 的
  「寫程式日／驗證日」分離制）。

## Part 總覽（依賴順序）

| Part | 名稱 | 核心內容 | 依賴 |
|---|---|---|---|
| P1 | 止血與 fail-closed | 所有靜默吞錯改明確拒絕 | — |
| P2 | 位址與 vhost 基礎 | 解鎖 `tls auto`、vhost 語義 | P1 |
| P3 | 語法與 matcher | 簡寫、env、placeholder、matcher 全語義 | P2 |
| P4 | directive 順序與 middleware | Caddy 排序、middleware chain | P3 |
| P5 | Automatic HTTPS 完整化 | eager issuance、challenge、fallback | P2 |
| P6 | API／CLI／Logging／Metrics／部署 | 管理面補齊 | P2、P4 |
| P7 | 進階（v0.3+） | 已列不排期的項目 | 全部 |

```
P1 ──> P2 ──> P3 ──> P4 ──> P6
              └────> P5 ────┘
                              └──> P7
```

---

## 🔧 P1 — 止血與 fail-closed

> 原則：**未實作的功能一律編譯期明確拒絕**；錯誤訊息能與一般 typo
> 區分。本 Part 不改語義，只消滅「編譯過但行為錯／沒有行為」。

### P1.1 所有 catch-all 靜默吞錯 → 明確錯誤

- [x] `adapt_reverse_proxy` 未知子指令（現況 `_ => {}`）→ 報錯。
  影響：`handle_response`、`replace_status`、`copy_response_headers`、
  `dynamic`、`lb_try_duration`、`fail_duration` 等（R1、E-5）
- [x] `file_server` block 未知子指令（`precompressed`、`fs`）→ 報錯
  （E-1）
- [x] `adapt_log_block` 未知子指令／未知參數（`format jsno`、
  `output stdoutd`、`output file` 缺路徑）→ 報錯（L1）
- [x] `adapt_global` 已列不支援選項的錯誤訊息加「Caddy 相容但
  不支援」提示（G8）：`http_port`、`https_port`、`default_bind`、
  `order`、`grace_period`、`storage`、`metrics`、`local_certs`、
  `acme_*`、`pki`、`on_demand_tls`、`frankenphp`、`filesystem`、
  `events`、`log`
- [x] 不支援 directive 的錯誤訊息加提示：`acme_server`、
  `templates`、`try_files`、`php_fastcgi`、`abort`、`handle_path`、
  `handle_errors`、`uri`、`vars`、`request_header`、`method`、
  `fs`、`push`、`intercept` 等（D6、U5、E-7）
- [x] 同類靜默吞錯一併處理：`header_up` 第三參數、inline
  `header X-Only` 無值（審查時發現的額外兩處）

### P1.2 已知錯的輸入 → 編譯期拒絕（不再放任 runtime 壞）

- [x] `unix//` upstream 位址：實作或明確拒絕（H1）
- [x] port range（`localhost:8080-8085`）：展開或明確拒絕（V1）
- [x] `tcp/`／`tcp4/`／`tcp6/` network 前綴：剝離或明確拒絕（V2）
- [x] `debug` 只收無參數（`debug fales` 報錯）（G4）
- [x] `auto_https` 無參數報錯（G5）
- [x] `method` matcher 未知 verb 報錯（`method HEAD` 要支援；
  `method FOO` 要報錯）（M2）
- [x] `header` matcher 第三個以上參數報錯或實作多值 OR（M8）

### P1.3 安全相關 fail-open 修正

- [x] Query matcher runtime 不再 `true`：實作 query string 評估
  （`?q=1` 命中、其他不命中、非法 query 不匹配）（M6）
- [x] `admin <addr> { origins ... }` block 不再靜默丟棄：
  實作 origins/enforce_origin 或 fail closed（G2）

**P1 收工**：以上每項都有「編譯失敗 + 錯誤訊息」的負面測試；
`docs/CADDYFILE_COMPATIBILITY_MASTER.md` 對應項改 ✅。
✅ **2026-08-01 完成**：`fail_closed_tests` 模組 24 個負面測試
（含 Query matcher runtime 測試）；四項 gate 全綠（fmt、clippy
`-D warnings`、`cargo build --workspace`、`cargo test --workspace`）。

---

## 🔧 P2 — 位址與 vhost 基礎

> 本 Part 修完後，`example.com { tls auto }` 才能自動開 443。

### P2.1 隱式 listen 語義（B0/B1/B2 根因）

- [x] `parse_server_address`：純 hostname（無顯式 scheme/port）不再
  預設 `0.0.0.0:80` 並 push 進 `server.listens`；只有顯式
  `http://`／`https://`／`:port` 才產生 listen（方案 A/B 見
  `CADDYFILE_ADDRESS_SEMANTICS.md` §2.4）
- [x] site 隱式 listen 與顯式 `listen` 去重（B1：
  `listen :80` 不再出現兩次）
- [x] `listen :8443` + hostname site 不再被偷加隱式 80（B2）
- [x] `compiler.rs` 的 bind 預填不會把 listen 塞回非空（:201；
  `ServerConfig` 新增 `bind` 欄位，bind 只命名介面）
- [x] 驗證：`example.com { tls auto }` 編譯後 `listen` 為空（或
  「無顯式 listen」旗標），main.rs 走 443 分支

### P2.2 vhost 語義

- [x] 多 listener 不再塌 `server.name` 成 `_`（B3）；`_` 只留給
  裸 port／catch-all 位址
- [x] `localhost` 與 `http://localhost` 可共存（E-3）
- [x] 裸 `:443` 預設 TLS；`:8443` 慣例寫成 core 層規則（B4）
- [x] 多位址 block（`example.com, www.example.com`）單一 site
  共用設定（B9；`ServerConfig.names` + `add_server` 逐名註冊）
- [x] `example.com/app`（位址帶 path）：待 P3 處理（B8，明確拒絕
  已由 P1 的 unsupported 路徑涵蓋）
- [x] `https://`／`http://` catch-all 位址語義（443/80、無 Host
  matcher、name 不含字面 scheme）（E-4）

### P2.3 port 設定與檔名

- [x] global `http_port`／`https_port`（G6）：影響隱式 443/80、
  `AUTOMATIC_HTTP_LISTEN`、`server_requires_tls` 的 443/8443 判斷
- [x] `run`／`validate` 預設檔名認 `Caddyfile`（C7）
- [x] 位址解析支援 IPv6 zone（`[fe80::1%eth0]:8080`）或明確拒絕
  （V2 延伸）

> 額外修正（P2 過程中發現）：`{host}` placeholder 改為 Caddy 語義
> （不含 port）；companion redirect 在非標準 `https_port` 時帶正確
> 端口。

**P2 收工**：真 binary 測 `tls auto` 開 443 + 80 companion；多
listener site 的 Host header 路由精確；官方位址表格每個 case 有
compile 測試。
✅ **2026-08-01 完成**：`address_semantics_tests` 11 項單元測試 +
集成測試 `test_hostname_tls_site_derives_https_and_http_companion`
（真 binary：自動 https_port TLS 監聽 + http_port companion 308，
Location 指向 https_port）；四項 gate 全綠。

---

## 🔧 P3 — 語法與 matcher

### P3.1 基礎語法

- [x] 單站無大括號簡寫（U1）：第一個 token 是 site 位址，後續行
  屬於該 site
- [x] 環境變數 parse 前展開：`{$VAR}`／`{$VAR:default}`、多 token、
  可空值（U3）
- [x] `{placeholder}` 與相鄰文字保持同一 token（P2：
  `redir https://www.{host}{uri}`）
- [x] duration 完整語法：`ns/us/ms/s/m/h/d`、小數（`1.5h`）、組合
  （`2h45m`）；裸數字拒絕（V3）
- [x] placeholder 縮寫表補齊或編譯期警告：`{labels.*}`、`{query}`、
  `{?query}`、`{port}`、`{hostport}` 已補；`{scheme}` 等標 TODO
  （V4、P6）

### P3.2 `root` 與 `file_server`

- [x] `root <path>`／`root * <path>` directive（P1）：接入
  `file_server` 根目錄
- [x] `file_server browse` inline 旗標（U2）
- [x] `file_server /path/*` inline path matcher（E-2）
- [x] `file_server` block：`root`、`index`、`browse` 正確語義；
  `precompressed`/`fs` fail closed 並標 TODO（E-1；實作列 P7）
- [x] trailing-slash 自動轉跳（目錄加斜線、檔案去斜線）（P5）

### P3.3 Matcher 全語義

- [x] multi-path matcher 全部 pattern 生效（M1：route path 多值或
  matcher 完整評估）
- [x] `header` matcher：`!` 不存在、`*suffix`、`prefix*`、兩側 `*`
  （M3）
- [x] matcher set 同型別合併：同欄位 header／path／method／host
  多值 OR、不同欄位 AND（M7/M8）
- [x] path matcher 四種 wildcard 位置（M4）
- [x] path 匹配前正規化：case-insensitive、dot-segment、多 slash、
  URI-decode（M4）
- [x] DSL 支援 `host`／`query`／`protocol`／`remote_ip`／`client_ip`
  matcher（M5）
- [x] `not` 的 inline 多值與 block 語意測試鎖定（M7）

**P3 收工**：官方 tutorial + patterns + examples 頁的原文範例
（扣除標記 v0.3+ 的）全部能編譯；matcher 每個語意有 runtime 測試。
✅ **2026-08-01 完成**：`p3_syntax_tests` 18 項單元測試 + router
matcher runtime 測試 5 項（glob 四位置、正規化、CIDR、negated header）
+ 真 binary 集成測試 `test_file_server_trailing_slash_redirects`；
官方範例探針全部編譯（含 `redir` matcher 形式）；四項 gate 全綠。
`redir /a /b` 的 inline path matcher 提前實作（P4 D-4 一部分）。

---

## 🔧 P4 — directive 順序與 middleware chain

- [x] 已支援 directive 依 Caddy 預設順序執行（header 在 respond 前、
  basic_auth 在 file_server 前…）（D1）
- [x] middleware（header/rewrite/basic_auth/rate_limit…）成為包住
  routing 的 chain，不再被 terminal route 遮蔽（D2）
- [x] 同名 `handle` 依 matcher specificity 排序（D3）
- [x] directive 第一參數 `/`-path 解析為 matcher（`reverse_proxy
  /api/*`、`redir /a /b`…）（D4）
- [x] `rewrite`：Caddy path 語意與 Pingclair regex 語意明確區分
  （D5/P4）
- [x] `route` block 保留字面順序（既有）；內層 matcher token fail
  closed 並標 TODO(v0.3)（需 per-handler 條件執行）（D6）
- [x] `to` 單行多 upstream（E-6）
- [ ] `order` global option（D8）— 固定排序已實作；order 覆寫標
  TODO(v0.3)

**P4 收工**：同一份設定只改 directive 排列順序，HTTP 行為完全一致
（真 binary 差分測試）。
✅ **2026-08-02 完成**：`directive_order_tests` 8 項單元測試 + 真
binary 差分集成測試 `test_directive_order_does_not_change_behavior`
（兩個真實伺服器，順序反轉後 status/header/body 完全一致）；四項
gate 全綠。D6 內層 matcher token 與 D8 order 覆寫標 TODO(v0.3)。

---

## 🔧 P5 — Automatic HTTPS 完整化

> 依賴 P2（位址修復）——443 開不起來，本 Part 全部無意義。

- [x] 背景 eager issuance：啟動時為所有 `tls auto` 具名網域發起
  簽發；首次 handshake 不阻塞（T2）
- [x] 失敗重試與指數退避（最長 1 天；失敗訊息可觀測）（T3）
  （T5）
- [ ] TLS-ALPN-01 challenge（T3；GUARDRAILS 級別，需 TLS acceptor
  改動）— 標 TODO(v0.3)
- [ ] DNS-01 challenge + wildcard 憑證（T4；含 `tls { dns }` 語法；
  與 `abort` directive、`host` matcher 一起）
  — 標 TODO(v0.3)（需 DNS provider 生態）
- [ ] issuer fallback（LE → ZeroSSL）（T6）— 標 TODO(v0.3)（需
  external-account-binding 支援）
- [x] localhost／本機 IP 自動本機 CA HTTPS（T7：預設走 `tls
  internal` 能力）
- [x] reload 時中止 in-flight ACME（T8：reload 清除 pending markers）
- [x] storage 可寫性預檢與文件（T9：啟動時 probe，不可寫即 fail）

**P5 收工**：本機 staging 全流程（不需手動觸發 handshake 就簽到）；
`tls auto`／`tls internal`／manual cert 三路回歸；Linux release +
quiche-client smoke 按 AGENTS.md。
✅ **2026-08-02 部分完成**：T-2/T-3/T-7/T-8/T-9 已實作；eager domain
收集有單元測試、renewal daemon 首次接線。T-4（TLS-ALPN-01）、T-5
（DNS-01/wildcard）、T-6（issuer fallback）為 GUARDRAILS 級改動或
需外部生態（DNS provider、ZeroSSL EAB），已標 TODO(v0.3) 並在程式
碼註解；公網 staging 全流程驗證需 Linux/VPS 環境（AGENTS.md）。

---

## 🔧 P6 — API／CLI／Logging／Metrics／部署

> 本 Part 是管理面補齊，依賴 P2（reload 位址語義）與 P4（reload
> 後 handler 順序一致）。

### P6.1 Admin API 與 reload

- [x] SIGHUP reload 偵測 global 差異並警告「需要重啟」（A1；
  macOS 本機實測）
- [x] `POST /load` 整包替換（完整 `PingclairConfig`、失敗 rollback、
  相同 config 不 reload）（A2/A8）
- [x] `GET /config` 回傳可重新 POST 的 config 文件（A7）
- [x] `POST /stop`（A 系列；graceful 協調標 TODO(v0.3)）
- [ ] admin `origins`／`enforce_origin`（P1.3 的 runtime 半）
- [x] `POST /adapt`（A9）

### P6.2 CLI

- [x] `pingclair adapt [--pretty] [--validate]`（C1）
- [x] `pingclair fmt [--overwrite] [--diff]`（C1）
- [x] `validate` 走 provisioning 層（cert 檔存在性等）（C2）
- [x] SIGUSR1 reload（C3；SIGHUP 相容；macOS 本機實測）
- [x] `file-server` 旗標：`--browse`、`--domain`、`--access-log`、
  `--no-compress`（C4；`--templates` 標 TODO(v0.3)、`--file-limit`
  明確報未實作）
- [x] `reverse-proxy` 旗標：多 `--to`、`--header-up/down`、
  `--insecure`、`--internal-certs`、`--disable-redirects`（C5）
- [x] `hash-password`（bcrypt）（C8）

### P6.3 Logging

- [x] per-server `level` 支援（L2；`log { level ... }` 解析並寫入
  config）
- [ ] global `log` option（多 log 管道）（L3）
- [ ] access log 補 request/response headers、TLS 資訊（L4）

### P6.4 Metrics

- [x] `{ metrics }`／`{ metrics { per_host } }` 開關（MT-1；
  per_host/otlp block 標 TODO(v0.3)）
- [x] runtime/process 指標（MT-2；跨平台 getrusage collector）
- [x] admin API 指標（MT-3；`pingclair_admin_http_requests_total`）
- [x] HTTP 指標補齊：request/response size、TTFB、errors（MT-4）
- [x] upstream health 0/1 gauge（MT-5；LB select 時更新）
- [x] `active_connections` 改 gauge 並打點（MT-6）

### P6.5 部署

- [x] systemd unit 單一來源 + `Restart=on-failure` +
  `RestartPreventExitStatus=1`（K-1/K-2）
- [x] README 補 production compose 與 `tls internal` trust 安裝
  流程（K-4/K-5/K-6；三語同步）

**P6 收工**：管理面每項有真 binary 測試（`POST /load`、reload、
metrics 打點、CLI 指令）；三語 README 與實際一致。
✅ **2026-08-02 部分完成**：reload（SIGHUP+SIGUSR1）、admin API
（/load、/adapt、/stop、GET /config 文件）、CLI（adapt/fmt/
hash-password/validate provisioning）、metrics 開關與 active
connections gauge、systemd unit 修復，均在 macOS 本機集成測試
驗證。file-server/reverse-proxy 旗標、log level、HTTP 指標補齊
標 TODO(v0.3)。

> 🔧 **平台修正**：signal/reload handler 原為 `cfg(target_os =
> "linux")`，macOS 本機根本沒編譯沒測試——已放寬為 `cfg(unix)` 並
> 補 macOS 可跑的訊號集成測試；jemalloc 同放寬到 unix；service
> 子命令保留 Linux-only（systemctl 平台專屬）但非 Linux 路徑有
> macOS 單元測試。`GlobalConfig` 補 `PartialEq` 讓 global 差異比較
> 在所有平台編譯。

---

## 🗄️ P7 — 進階（v0.3+，只列不排期）

- config path traversal（`/config/<path>`）、`@id`、Etag/If-Match
  （A3/A4/A11）
- config persistence + `--resume`（A5）
- `handle_response` 完整實作（status class、header 條件、
  replace/copy/fallback）（R3）
- `try_files`、`templates`、`handle_path`、`handle_errors`（S6/S7、
  D7）
- `pki`／`acme_server`（自建 CA + 內嵌 ACME server）（E-7）
- on-demand TLS、ECH（automatic-https 文檔 §5）
- FrankenPHP／`php_fastcgi`（patterns 文檔）
- `fs` 模組（sqlite/embedded）（E-1 延伸）
- `dynamic srv` SRV 後端（E-5 延伸）
- OTLP metrics push、OpenMetrics 協商（MT-7）
- `completion`／`manpage`／`storage export|import`（CLI 對照表）
- `default_bind`、`grace_period`／`shutdown_delay`（G7/G9）
- Unix socket `|0200` 權限模式（V 系列延伸）

---

## 收工條件（每個 Part）

1. 該 Part 涉及的所有官方原文範例能編譯（compile fixture，
   `pingclair-config/tests/` 或 documentation 測試）；
2. `cargo +1.88.0 fmt --all -- --check`、
   `cargo +1.88.0 clippy --locked --workspace --all-targets -- -D warnings`、
   `cargo +1.88.0 build --locked --workspace`、
   `cargo +1.88.0 test --locked --workspace`（AGENTS.md 四項 gate）；
3. 真 binary 整合測試覆蓋該 Part 的 runtime 行為
   （`pingclair/tests/integration.rs`）；
4. 每項「未支援」的錯誤訊息通過「能與 typo 區分」的測試；
5. `docs/STATUS.md` 更新；三語 README 的 Caddyfile 宣稱與實際一致；
6. `docs/CADDYFILE_COMPATIBILITY_MASTER.md` 對應項目打 ✅。
