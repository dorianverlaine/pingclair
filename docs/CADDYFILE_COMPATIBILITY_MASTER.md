# Caddyfile 相容性補齊總需求（Master）

> 📌 彙整 15 份專項審查（docs/CADDYFILE_*.md，2026-08-01，
> main @ 2026-07-31）的全部發現，按**功能領域**組織，作為
> `docs/TODO.md` Day 排期的直接輸入。原則是：**官方文檔每一頁
> 都是需求，缺的功能全部要補**；每項標註來源文件與依賴關係。
>
> 分級：🔴 先做（錯誤行為／安全／阻擋其他功能）；🟠 次之
> （功能缺口）；🟡 後補（增強／工具）。「失敗處理原則」：
> 還沒實作的功能一律 fail closed（明確拒絕），不允許靜默無效。

## 0. 跨領域鐵律（所有修復的共通前題）

1. **禁止靜默吞錯**：adapter 的所有 `_ => {}` catch-all、`filter_map`
   丟棄、未知參數忽略，全部改成明確錯誤（類別：`encode gzipp`、
   `reverse_proxy` 子指令、`log` 子指令、`debug fales`、method
   未知 verb、`listen` 未知旗標……）。來源：D6、G4、L1、R1、M2。
   ✅ P1 已修：reverse_proxy/file_server/log catch-all、`debug`、
   `auto_https`、`method`、`header`、`header_up`、admin block。
2. **禁止「編譯過但 runtime 壞」**：port range、`tcp/` 前綴、
   `unix//`、`/api/*` 當 upstream、無 port listen 等，不支援就要
   編譯期拒絕。來源：V1、V2、H1、P3。
   ✅ P1 已修：`unix//`、port range、`tcp/` 前綴編譯期拒絕。
3. **未支援功能要說「Caddy 相容但不支援」**，錯誤訊息要能與一般
   typo 區分。來源：G8、D6、U5。
   ✅ P1 已修：`UnsupportedFeature` 錯誤變體＋已知 Caddy 選項清單。
4. **DSL 與 JSON/Admin 兩條路同規則**（GUARDRAILS 既有原則）。
   來源：B4、M6。
5. 修完一項，官方對應頁面的原文範例要進 compile fixture。
   來源：H2、P 系列、U 系列。

## 1. 位址與 vhost 語義（來源：ADDRESS）

| 項 | 需求 | 級別 |
|---|---|---|
| A-1 | 修 `tls auto` 自動 443：site 位址推導的隱式 listen 不塞進 `listen`，只有顯式 port/scheme 才 push；main.rs `listen.is_empty()` 分支要能走（B0/B1 根因，方案 A/B 見 ADDRESS §2.4） | 🔴 |
| A-2 | 多 listener 不塌 vhost name（`_` 只留給裸 port/catch-all）；`_` 目前會變 catch-all（B3） | 🔴 |
| A-3 | `listen` 去重：site 隱式 + 顯式 `listen :80` 不得重複（B1） ✅ P2 已修 | 🔴 |
| A-4 | 純 hostname 不加隱式 80（B2：`listen :8443` 被偷加 80） ✅ P2 已修 | 🔴 |
| A-5 | 裸 `:443` 預設 TLS；`:8443` 慣例寫成 core 層規則（B4） ✅ P2 已修 | 🟠 |
| A-6 | `localhost`／IP site 依 TLS 推導 443（B5、T6） 🟠 部分：`localhost` 已可推導；自動本機 CA 待 T7 | 🟠 |
| A-7 | 多位址 block（`example.com, www.example.com`）單一 site 共用設定（B9） ✅ P2 已修（`ServerConfig.names`） | 🟠 |
| A-8 | site 位址帶 path（`example.com/app`）實作或明確拒絕（B8） 🟡 部分：明確拒絕已涵蓋；path matcher 待 P3 | 🟡 |
| A-9 | `auto_https off` 不改變預設 protocol 的語義分離（B6，需產品決策） | 🟡 |
| A-10 | 位址解析支援 `tcp/` 前綴、port range（展開或拒絕）、IPv6 zone（V1/V2） ✅ P1/P2 已修（前綴/range/zone 拒絕） | 🔴 |
| A-11 | `unix//` socket 位址實作或明確拒絕（H1，含 `\|0200` 權限） ✅ P1 已修（拒絕） | 🔴 |

## 2. 設定語法與解析（來源：TUTORIAL、PATTERNS、CONVENTIONS、HOMEPAGE）

| 項 | 需求 | 級別 |
|---|---|---|
| S-1 | 單站無大括號簡寫：第一個 token 是 site 位址，後續行屬該 site（U1，Tutorial 第一步） | 🔴 |
| S-2 | 環境變數 parse 前展開：`{$VAR}`／`{$VAR:default}`、多 token、可空（U3） | 🔴 |
| S-3 | `{placeholder}` 與相鄰文字保持同一 token（P2：`redir https://www.{host}{uri}`） | 🔴 |
| S-4 | `root` directive：site block 內 `root <path>`／`root * <path>`，接入 file_server（P1，官方首頁與 patterns 的基礎） | 🔴 |
| S-5 | `file_server browse` inline 旗標（U2）；`file_server` 其他 Caddy 子指令（`index`、`root`、`browse`、`precompressed` 等） | 🟠 |
| S-6 | `try_files`（SPA 核心，P8） | 🟠 |
| S-7 | `templates` directive（U5、C4 旗標） | 🟡（v0.3） |
| S-8 | 完整 duration：`ns/us/ms/s/m/h/d`、小數、組合；裸數字拒絕（V3） | 🟠 |
| S-9 | placeholder 生態：`{labels.*}`、`{query}`、`{scheme}` 等官方縮寫表；未支援者編譯期警告（V4、P6） | 🟠 |
| S-10 | 預設檔名認 `Caddyfile`（C7）；`run` 無 config 時錯誤訊息提示 ✅ P2 已修 | 🟡 |
| S-11 | TLS store 路徑文件/實作一致＋持久性警示（V5） | 🟡 |

## 3. Matcher（來源：MATCHERS）

| 項 | 需求 | 級別 |
|---|---|---|
| M-1 | multi-path matcher 全部 pattern 生效：route path 表示多值，或路由層完整評估 matcher（M1，目前只註冊第一條） | 🔴 |
| M-2 | Query matcher runtime 不再 fail-open：`?q=1` 命中、其他不命中；非法 query 不匹配（M6，安全） ✅ P1 已修 | 🔴 |
| M-3 | `method` 支援全部標準 verb（HEAD/PATCH/OPTIONS…），未知 verb 報錯（M2） ✅ P1 已修 | 🔴 |
| M-4 | `header` matcher：`!` 不存在、`*suffix`、`prefix*`、兩側 `*`；多值 OR（M3、M8） | 🟠 |
| M-5 | path matcher 四種 wildcard 位置＋case-insensitive＋dot-segment 清理＋多 slash 合併＋URI-decode 正規化（M4） | 🟠 |
| M-6 | DSL 支援 `host`／`query`／`protocol`／`remote_ip`／`client_ip`（M5；core 已有型別） | 🟠 |
| M-7 | matcher set 依型別合併：同欄位 header／同鍵 query／path／method／host 多值 OR，不同欄位 AND（M8） | 🟠 |
| M-8 | `not` 的 inline 多值與 block 語意加測試鎖定（M7） | 🟡 |

## 4. Directives（來源：DIRECTIVES）

| 項 | 需求 | 級別 |
|---|---|---|
| D-1 | 已支援 directive 依 Caddy 預設順序固定執行（header 在 respond 前等；D1） | 🔴 |
| D-2 | middleware（header/rewrite/basic_auth…）是包住 routing 的 chain，不是 route arm；不被 terminal route 遮蔽（D2） | 🔴 |
| D-3 | 同名 `handle` 依 matcher specificity 排序（D3） | 🟠 |
| D-4 | directive 第一參數 `/`-path 解析為 matcher（`reverse_proxy /api/*`、`redir /a /b` 等；P3、P4） | 🟠 |
| D-5 | `rewrite` 的 path 語意與 regex 語意明確區分（P4） | 🟠 |
| D-6 | `route` block 保留字面順序、支援內層 matcher token（D5） | 🟠 |
| D-7 | directive 覆蓋度補齊：`abort`、`error`、`handle_errors`、`handle_path`、`request_header`、`uri`、`vars`、`method`（D6 清單，分批） | 🟡 |
| D-8 | `order` global option（配 D-1 一起） | 🟡 |

## 5. Global Options（來源：GLOBAL_OPTIONS）

| 項 | 需求 | 級別 |
|---|---|---|
| G-1 | `servers` block：位址參數保留（per-listener 語意）、子選項不靜默丟棄；`protocols` 真正寫入 runtime 或 fail closed（G1） | 🔴 |
| G-2 | `admin` block：`origins`／`enforce_origin` 實作或 fail closed（G2，安全） ✅ P1 已修（fail closed） | 🔴 |
| G-3 | `trusted_proxies static [private_ranges] <ranges...>` 語法（G3） | 🟠 |
| G-4 | `debug` 只收無參數（G4） ✅ P1 已修 | 🟠 |
| G-5 | `auto_https` 四模式（`disable_certs`／`ignore_loaded_certs`）＋無參數報錯（G5） ✅ P1 已修（無參數報錯；兩模式標 unsupported） | 🟠 |
| G-6 | `http_port`／`https_port`（A 系列位址修復的前置，B7/G6） ✅ P2 已修 | 🔴 |
| G-7 | `default_bind`（B7） | 🟡 |
| G-8 | global block 必須檔首（G7） | 🟡 |
| G-9 | `grace_period`／`shutdown_delay`（G8，配 shutdown 協調） | 🟡 |
| G-10 | `acme_ca`／`local_certs`／`acme_ca_root`（TLS 開發流程，G8） | 🟠 |
| G-11 | `servers { timeouts }` 對應 per-listener 語法（G9，至少錯誤訊息指路） | 🟡 |

## 6. Automatic HTTPS（來源：AUTOMATIC_HTTPS）

| 項 | 需求 | 級別 |
|---|---|---|
| T-1 | 修 A-1 後，`tls auto` 簽發路徑才通；驗證「不需手動 handshake 就簽到」 | 🔴 |
| T-2 | 背景 eager issuance：啟動時為所有 `tls auto` 具名網域發起簽發；handshake 不再阻塞（T2） | 🔴 |
| T-3 | 失敗重試與退避（指數退避、最長 1 天、30 天內持續）（T5） | 🟠 |
| T-4 | TLS-ALPN-01 challenge（T3，GUARDRAILS 級別） | 🟠 |
| T-5 | DNS-01 + wildcard 憑證（T4，含 `tls { dns }` 語法） | 🟠 |
| T-6 | issuer fallback（LE→ZeroSSL）（T5） | 🟡 |
| T-7 | localhost/本機 IP 自動本機 CA HTTPS（T6、A-6） | 🟠 |
| T-8 | reload 中止 in-flight ACME（T8、A-1） | 🟡 |
| T-9 | storage 預檢／叢集協調說明（T7） | 🟡 |

## 7. Response Matcher / 攔截（來源：RESPONSE_MATCHERS）

| 項 | 需求 | 級別 |
|---|---|---|
| R-1 | `handle_response`／`replace_status`／`copy_response_headers`／`@name { status/header }` 未實作前**必須 fail closed**（R1，目前靜默無效） ✅ P1 已修 | 🔴 |
| R-2 | `error_page` 支援 `4xx` 類別碼或明確錯誤訊息（R2） | 🟠 |
| R-3 | `handle_response` 完整實作（status class、header 條件、replace/copy、fallback）列 v0.3（R3/R4） | 🟡 |

## 8. Admin API（來源：ADMIN_API、GETTING_STARTED）

| 項 | 需求 | 級別 |
|---|---|---|
| API-1 | SIGHUP reload 偵測並警告 global 差異（A1，最便宜止血） | 🔴 |
| API-2 | `POST /load` 整包替換（完整 `PingclairConfig`，失敗 rollback、相同 config 不 reload）（A2/A8） | 🔴 |
| API-3 | `GET /config` 回傳可重新 POST 的 config 文件（A7） | 🟠 |
| API-4 | `POST /stop`（A 系列） | 🟠 |
| API-5 | config path traversal（GET/POST/PUT/PATCH/DELETE `/config/<path>`、陣列 `/...` 展開）（A3） | 🟡（v0.3） |
| API-6 | `@id` 支援（A4） | 🟡（v0.3） |
| API-7 | Etag／If-Match 樂觀並行（A11） | 🟡（v0.3） |
| API-8 | config persistence＋`--resume`（A5、C6） | 🟡（v0.3） |
| API-9 | `POST /adapt`（A9） | 🟡 |
| API-10 | `GET /reverse_proxy/upstreams`（A10，BackendHealth 快照） | 🟡 |
| API-11 | `GET /pki/ca/<id>`（A 系列） | 🟡（v0.3） |
| API-12 | admin 預設值／origins 保護與 README 一致（A6、G-2） | 🟠 |

## 9. CLI（來源：COMMAND_LINE、GETTING_STARTED）

| 項 | 需求 | 級別 |
|---|---|---|
| CLI-1 | `pingclair adapt [--pretty] [--validate]`（C1） | 🔴 |
| CLI-2 | `pingclair fmt [--overwrite] [--diff]`（C1） | 🔴 |
| CLI-3 | `validate` 走 provisioning 層（cert 檔存在性、upstream TLS 素材）（C2） | 🔴 |
| CLI-4 | SIGUSR1 reload（C3；SIGHUP 相容保留） | 🟠 |
| CLI-5 | `file-server` 旗標：`--browse`、`--domain`、`--templates`、`--access-log`、`--no-compress`、`--file-limit`（C4） | 🟠 |
| CLI-6 | `reverse-proxy` 旗標：多 `--to`、`--header-up/down`、`--insecure`、`--internal-certs`、`--disable-redirects`（C5） | 🟠 |
| CLI-7 | `hash-password`（bcrypt；C8） | 🟡 |
| CLI-8 | `run --watch`／`--pidfile`／`--envfile`（C6） | 🟡 |
| CLI-9 | `reload`／`start`／`stop` 子命令（配合 API-2/API-4） | 🟡（v0.3） |
| CLI-10 | exit code 語意文件化（C8） | 🟡 |

## 10. Logging（來源：LOGGING）

| 項 | 需求 | 級別 |
|---|---|---|
| LOG-1 | `log` block 未知子指令 fail closed（L1） ✅ P1 已修 | 🔴 |
| LOG-2 | per-server/global `level` 支援（L2；`LoggingConfig.level` 死欄位接上或刪除） | 🟠 |
| LOG-3 | global `log` option（多 log 管道）（L3） | 🟡（v0.3） |
| LOG-4 | access log 補 request/response headers、TLS 資訊（L4） | 🟡 |
| LOG-5 | sampling 與 logger include/exclude（L5） | 🟡（v0.3） |
| LOG-6 | rotation／retention／bounded async writer（L6，Day 22 既有） | 🟡 |

## 10a. Metrics（來源：METRICS）

| 項 | 需求 | 級別 |
|---|---|---|
| MT-1 | `{ metrics }`／`{ metrics { per_host ... } }` global option；預設關閉或文件化恆開 | 🟠 |
| MT-2 | runtime/process 指標（`go_*`/`process_*` 對應物） | 🟠 |
| MT-3 | admin API 指標（request/error counter per endpoint） | 🟠 |
| MT-4 | HTTP 指標補齊：request/response size、TTFB、errors、in_flight；labels 對齊 Caddy（server/handler/code/method）或文件化映射 | 🟠 |
| MT-5 | `upstream_healthy` 0/1 gauge（接 `BackendHealth`，與 API-10 同源） | 🟠 |
| MT-6 | `active_connections` 改 gauge 並打點，或刪除 | 🟡 |
| MT-7 | OpenMetrics 協商；OTLP push（v0.3） | 🟡 |

## 10b. 服務管理與部署（來源：KEEP_RUNNING）

| 項 | 需求 | 級別 |
|---|---|---|
| K-1 | systemd unit：`Restart=on-failure`＋`RestartPreventExitStatus=1`（config 壞不無限重啟） | 🟠 |
| K-2 | 兩份 unit（scripts/ vs deployment/）合併為單一來源 | 🟠 |
| K-3 | API 工作流 service variant（配 `--resume`，API-8 一起） | 🟡 |
| K-4 | production Docker Compose 範例（80/443/443-udp、TLS store volume） | 🟡 |
| K-5 | 容器執行 `pingclair run` 的完整 README 範例（root Dockerfile CMD 只是 demo） | 🟡 |
| K-6 | `tls internal` root.crt 的 trust 安裝流程文件化（systemd/Docker/browser） | 🟡 |
| K-7 | reload 訊號文件化（承接 CLI C3） | 🟡 |

## 10c. 官方 Examples 頁（來源：EXAMPLES）

| 項 | 需求 | 級別 |
|---|---|---|
| EX-1 | `file_server` block 子指令（`precompressed`、`fs`）不靜默吞：實作或 fail closed（現況 `root` 連 matcher 一起錯） ✅ P1 已修（fail closed） | 🔴 |
| EX-2 | `file_server /path/*` 的 inline path matcher（與 D-4 同源） | 🔴 |
| EX-3 | `localhost` 與 `http://localhost` 共存（不同 scheme 的 site 不撞名） | 🟠 |
| EX-4 | `https://`／`http://` catch-all 位址語義（443/80、無 Host matcher） | 🟠 |
| EX-5 | `dynamic srv`／`lb_try_duration`／`fail_duration` 至少 fail closed；完整實作列 v0.3 | 🟠 |
| EX-6 | `to` 單行多 upstream（Caddy 官方寫法） | 🟠 |
| EX-7 | `pki`/`acme_server`/`frankenphp`/`on_demand_tls` 錯誤訊息標「Caddy 相容但不支援」 | 🟡 |

官方 examples 頁 7 段原文進 compile fixture（E 系列驗收基準）。

## 11. 建議執行順序（依賴排序）

### Phase 0 — 止血（fail closed + 安全）
- 0.1 所有 catch-all 靜默吞錯改明確拒絕（§0 第 1 條）：reverse_proxy、
  log、debug、method、global options
- 0.2 Query matcher fail-open 修正（M-2）
- 0.3 admin origins 靜默丟棄（G-2）
- 0.4 `unix//`／port range／`tcp/` 編譯期拒絕（A-10/A-11）

### Phase 1 — 位址基礎（解鎖自動 HTTPS 與 vhost）
- 1.1 隱式 listen 語義修正（A-1、A-3、A-4、A-5）
- 1.2 vhost name 不塌陷（A-2；連帶修 U4 多裸 port site）
- 1.3 `http_port`／`https_port`（G-6）
- 1.4 背景 eager issuance + 重試（T-2/T-3）→ `tls auto` 全流程驗證

### Phase 2 — 語法與 matcher
- 2.1 無大括號簡寫（S-1）、env var 展開（S-2）、placeholder token（S-3）
- 2.2 `root`（S-4）＋`file_server browse`（S-5）→ 官方首頁/patterns 範例
- 2.3 matcher 修正（M-1/M-3/M-4/M-5/M-6/M-7）
- 2.4 duration／placeholder 表（S-8/S-9）
- 2.5 file_server inline matcher 與子指令（EX-1/EX-2）、catch-all
  位址語義（EX-4）、`to` 多值（EX-6）

### Phase 3 — directive 排序與 middleware
- 3.1 Caddy 預設順序（D-1）＋ middleware chain（D-2）
- 3.2 specificity 排序（D-3）、inline path matcher（D-4）、rewrite 語意（D-5）
- 3.3 `order` option（D-8）

### Phase 4 — TLS 完整化
- 4.1 TLS-ALPN-01（T-4）
- 4.2 DNS-01／wildcard（T-5）＋ `abort`／`host` matcher 補齊
- 4.3 issuer fallback（T-6）
- 4.4 localhost 自動 HTTPS（T-7）

### Phase 5 — API／CLI／Logging
- 5.1 `POST /load`＋reload global 警告（API-2/API-1）
- 5.2 `adapt`／`fmt`／`validate` provisioning（CLI-1/2/3）
- 5.3 SIGUSR1、file-server/reverse-proxy 旗標（CLI-4/5/6）
- 5.4 log level／global log（LOG-2/LOG-3）
- 5.5 metrics 開關與指標補齊（MT-1~MT-5）
- 5.6 unit 修復（K-1/K-2）＋ SIGUSR1 後 ExecReload 更新（K-7）

### Phase 6 — 進階（v0.3+）

- production compose 與 trust 安裝文件（K-4/K-5/K-6）

### Phase 6 — 進階（v0.3+）
- path traversal／@id／Etag（API-5/6/7）
- persistence／resume（API-8）
- `handle_response` 完整實作（R-3）
- `try_files`／`templates`／`handle_path`／`handle_errors`（S-6/S-7、D-7）
- storage 生態、ECH、on-demand TLS（AUTOMATIC_HTTPS §5）

## 12. 驗證基準（每 Phase 收工）

1. 該 Phase 涉及的所有官方頁面原文範例能編譯（compile fixture）；
2. `cargo test --workspace` + `cargo clippy -- -D warnings`（AGENTS.md
   四項 gate）；
3. 真 binary 整合測試（integration.rs）覆蓋該 Phase 的 runtime 行為；
4. `docs/STATUS.md` 更新；三語 README 的「Caddyfile-compatible」
   宣稱與實際支援一致；
5. 每項「未支援」的錯誤訊息通過「能與 typo 區分」的測試。
