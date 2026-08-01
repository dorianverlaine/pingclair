# 🔧 Caddyfile 行為對照修復 TODO（與 Caddy 完全對齊）

> 📌 來源：`docs/CADDYFILE_VM_TEST_NOTES.md` 九組對照測試（AWS
> `t4g.micro`，Ubuntu 26.04 arm64；Pingclair 起點 commit `70d0fb0`，
> Caddy v2.11.4）。
> 目標：**行為與 Caddy v2.11.4 一致**。原列 v0.3+ 的項目
> （`templates`、`/load` 完整語義、`respond`、`--watch`、storage、
> trust 等）**全部納入本次**；決策點已定案為「以 Caddy 行為為準」，
> 不再用「文件說明／最小方案」替代實作。
> 唯一例外：`upgrade`／`add-package`／`remove-package` 依賴 Go/xcaddy
> 重編譯生態，Pingclair 靜態編譯無法等價，列「不適用」並寫進文件。
> F-01（`/load` 靜默載入空配置）已在 `70d0fb0` 修復；其餘
> F-02～F-32 未動工。

## 排序原則

1. 會「假裝成功／靜默錯誤」的先修（fail-closed 優先）；
2. 語意正確 > 功能補齊；功能補齊時以 Caddy 行為為驗證基準；
3. 每項收工條件：對應單元測試 + 真 binary 整合測試 + 香港機重跑該組
   對照（AGENTS.md 四 gate：fmt、clippy `-D warnings`、build、test）。

## Part 總覽（依賴順序）

| Part | 名稱 | 核心內容 | 依賴 |
| --- | --- | --- | --- |
| FX-A | 止血與 fail-closed | `/config/*` 語意陷阱、`:9000` upstream、stdin | — |
| FX-B | /load 與 admin API 完整語意 | 新 listener、整包替換、adapter、`/config/` 匯出、`/stop`、persistence/`--resume` | FX-A |
| FX-C | reload 與 signals 對齊 | handler 替換生效、新 listener 警告、SIGQUIT/SIGHUP/SIGUSR1 | FX-A |
| FX-D | CLI 快速命令 | `reload`/`start`/`stop`、`respond`、`--watch`、CLI HTTPS、`--change-host-header` | FX-A |
| FX-E | Caddyfile 語意 | bare hostname 預設 HTTPS、directive 優先序、`templates`、JSON auto-HTTPS | FX-A |
| FX-F | headers／網路／小語意 | Content-Type/charset/Vary、IPv6、預設 port、`--file-limit`、argon2id、fmt、exit code | 全部 |
| FX-G | CLI 表面補齊 | `completion`/`environ`/`list-modules`/`build-info`/`manpage`/storage/`trust`/`untrust`；upgrade 系列不適用 | FX-A |

```
FX-A ──> FX-B ──> FX-C
  └────> FX-D ──> FX-F
  └────> FX-E ──┘
  └────> FX-G ──┘
```

---

## 🔧 FX-A — 止血與 fail-closed

> 原則：先消滅「路徑/輸入看起來合理、行為卻不是那回事」的項目。

### FX-A1（F-24，P2）`POST /config/<path>` 不要再當 ServerConfig 上傳

- [x] 實作 Caddy 的 config path traversal 語意
      （`GET/POST/PUT/PATCH/DELETE /config/<path>`，含陣列索引、
      POST `...` 展開、失敗 rollback）；保留 legacy
      `/config/<index>` 作為 `servers[index]` 別名。
- 驗證：單元（`pingclair-api::config_tree`）+ 真 binary 整合
      （`test_admin_config_traversal_*`）+ 香港機實測全過。
- 註記：`@id` 與 persistence 仍屬 FX-B5。

### FX-A2（F-20，P1）upstream 裸 port `:9000` 解析失敗

- [x] `UpstreamSpec::parse` 空 host → `127.0.0.1`；adapter 與 CLI 的
      `:9000-9005` port range 展開為多 upstream（Caddy 語義）。
- 驗證：`upstream::tests::bare_port_upstreams_default_to_loopback_like_caddy`、
      `adapter::mod::tests`、`upstream_port_ranges_expand_like_caddy`；
      香港機 `reverse_proxy :9000` 與 `--to :9000-9001` 實測 200。

### FX-A3（F-31，P3）`adapt`／`validate` 支援 stdin（`-`）

- [x] `-c -`／positional `-` 讀 stdin（adapt、validate；fmt 原本就有）。
- 驗證：`cli_adapt_and_validate_read_stdin` 整合測試 + 香港機實測。

---

## 🔧 FX-B — /load 與 admin API 完整語意

### FX-B1（F-02 + F-10，P1）`/load` 開新 listener 且整包替換

- [x] RuntimeListeners：`/load` 與 traversal 遇到未綁定 listener 時以
      Pingora `Service::start_service` 動態建立（先同步 probe bind，
      失敗 rollback）；整包替換時 document 未提及的 dynamic listener
      停止、啟動時 listener 清空內容（socket 需重啟才關閉，已 log）。
- 驗證：`test_admin_load_creates_and_removes_listeners`、
      `test_admin_config_traversal_unbindable_listener_rolls_back`；
      香港機實測新 listener 服務、整包替換後 socket 關閉。

### FX-B2（F-11，P1）`/load` 支援 config adapter

- [x] `/load` 依 Content-Type 選擇 adapter：`text/caddyfile` 先編譯
      再載入。
- 驗證：`test_admin_load_accepts_caddyfile_content_type` + 香港機實測。

### FX-B3（F-03，P1）`GET /config/` 與完整文件匯出

- [x] `/config/` 與 `/config` 同義；document 保留啟動/載入時的
      `admin`/`global`/`logging` 實際值，匯出文件可直接回 POST。
- 驗證：香港機 `GET /config/` 顯示 admin/global；既有
      `test_admin_adapt_export_and_load` 仍綠。

### FX-B4（F-04，P2）`POST /stop` 先回應再 graceful shutdown

- [x] `/stop` 回 200 後透過 Notify 觸發主程序的 SIGTERM graceful 路徑。
- 驗證：`test_admin_stop_returns_response_then_exits` + 香港機實測
      （200 回應、process 退出）。

### FX-B5（API Tutorial：traversal + `@id`）

- [x] `@id`：任何 JSON 物件可標 `"@id"`，`/id/<name>[/<path>]`
      GET/POST/PUT/PATCH/DELETE（與 FX-A1 traversal 共用）。
- [x] config persistence：`/load`／traversal 成功後寫
      `$PINGCLAIR_TLS_STORE/autosave.json`；`run --resume` 優先載入。
- 驗證：`test_admin_id_tags_end_to_end`、`test_admin_autosave_and_resume`
      + 香港機實測（`--resume` 恢復 `id-ok`）。

---

## 🔧 FX-C — reload 與 signals 對齊

### FX-C1（F-14，P1）reload 換 handler 必須真正生效

- [x] 根因：reload 用 `listen.first()` 分組，hostname site 被歸到
      `:80`，TLS listener 沒被更新。改為 `servers_by_bind_address`
      （與啟動相同的 listener 推導＋automatic companion）。
- 驗證：`test_signal_reload_switches_handler_types` + 香港機
      `respond → file_server browse` reload 後 `/` 與 `/empty/` 都生效。

### FX-C2（F-09，P2）reload 新 listener 的警告要有細節

- [x] reload 遇到未綁定 listener 時直接透過 RuntimeListeners 動態開啟
      （Caddy 行為）；失敗時警告列出位址與原因。
- 驗證：香港機 reload 新增 `:9094` 後直接服務；`test_signal_reload_*`
      全綠。

### FX-C3（F-32，P2）signals 完全對齊 Caddy

- [x] SIGQUIT：立即退出（exit code 2）。
- [x] SIGHUP：ignored（註冊 handler 但丟棄，不再 reload）。
- [x] SIGUSR1：reload config file；API 變更過後失效並 log 警告。
- [x] SIGINT/SIGTERM：graceful（原有）。
- 驗證：`test_sigquit_exits_with_code_2`、`test_api_change_disables_signal_reload`、
      更新後的 `test_signal_reload_applies_config_and_warns_on_global_changes`
      + 香港機實測。

---

## 🔧 FX-D — CLI 快速命令

### FX-D1（F-08，P2）`reload`／`start`／`stop` 子命令

- [x] `reload`（`--config`/`--address`，Content-Type 依副檔名）、
      `start`（背景 spawn）、`stop`（`--address`，走 admin `/stop`）。
- 驗證：`test_cli_reload_uses_admin_api`、`test_cli_start_and_stop`
      + 香港機實測 v1→v2 reload、stop 後 port 關閉。

### FX-D2（F-30，P2）`respond` CLI 子命令

- [x] `respond`：`--status`/`--header`/`--body`/`--listen`
      （單 listener；port range 與 body 模板列 v0.3）。
- 驗證：`test_cli_respond_serves_body` + 香港機實測
      （202 + header + body）。

### FX-D3（F-25，P3）`run --watch`

- [x] `run --watch`：mtime polling + 自動 SIGUSR1。
- 驗證：`test_cli_run_watch_reloads`（v1→v2 自動生效）。

### FX-D4（F-21，P1）`reverse-proxy --from` HTTPS 路徑

- [x] hostname `--from` 展開成 `0.0.0.0:443`（vhost 語義，不再 panic）；
      `--internal-certs` 只取 host 部分簽發；localhost 用 internal CA。
- 驗證：香港機 `--from localhost` 預設 443 200、
      `--from example.com:8443 --internal-certs` 200。

### FX-D5（F-13，P2）`file-server --domain` 與 bare port

- [x] `--domain` 觸發簽發（localhost → internal CA）；`--listen`
      接受 bare port。
- [ ] `--templates`／`--precompressed`／`--reveal-symlinks`：`--templates`
      併入 FX-E3（templates 引擎）；其餘兩項列 v0.3。
- 驗證：香港機 `--domain localhost --listen :2118` 與 bare port 皆 200。

### FX-D6（F-18 + F-19，P2）`reverse-proxy` 預設與 Host 旗標

- [x] 預設 `--from localhost`（HTTPS 443，internal CA）；
      `-c/--change-host-header` 實作（Host = upstream hostport）。
- 驗證：`test_cli_site_addresses_derive_like_caddy` + 香港機
      `--change-host-header` backend 收到 `Host: 127.0.0.1:9000`。

---

## 🔧 FX-E — Caddyfile 語意

### FX-E1（F-22，P1）bare hostname 預設自動 HTTPS

- [x] compiler 對「bare hostname、無 listen、`auto_https != off`」的 site
      自動加 `tls auto`（localhost/IP 維持 internal）；`http://` 前綴
      維持明文。
- 驗證：`bare_hostname_without_tls_derives_no_listener`、
      `auto_https_off_keeps_bare_hostname_plaintext`。

### FX-E2（F-28，P1）directive 優先序對齊

- [x] terminal handler 的 pipeline 順序改為 Caddy 優先序的反向
      （file_server → reverse_proxy → respond，後者覆寫前者＝
      Caddy 的 first-wins）。
- 驗證：`terminal_handlers_run_in_reverse_caddy_priority`；香港機重驗
      Matchers 節。

### FX-E3（F-26，P1）`templates` directive 實作

- [x] `templates` directive（minijinja）：`now`＋`date`（Go layout）、
      `include`；pipeline 中 file_server 前執行，只攔截含 `{{` 的檔案；
      H1/H2/H3 都接；`file-server --templates` 同步。
- 驗證：`test_templates_directive_renders_caddy_templates`、
      `test_cli_file_server_templates`、`template_tests`；香港機
      `caddy.html` 渲染日期、`index.html` 原樣。

### FX-E4（F-23，P2）JSON 路徑自動 HTTPS 觸發

- [x] `eager_issuance_domains` 改用 `names`（JSON shape 的 hostname 不再
      被 `name="default"` 擋掉）。
- 驗證：`eager_issuance_domains_excludes_internal_manual_and_wildcards`
      加入 JSON shape case；香港機重驗。

---

## 🔧 FX-F — headers／網路／小語意

- [ ] FX-F1（F-05/F-15/F-27，P2/P3）：`respond` 預設
      `Content-Type: text/plain; charset=utf-8`；file_server 補
      charset；`encode` 補 `Vary: Accept-Encoding`。
- [ ] FX-F2（F-06，P2）：listen 雙棧（`:port` 同時 IPv4+IPv6，
      對齊 Caddy）。
- [ ] FX-F3（F-16，P3）：`file-server` 預設 `:80`、`reverse-proxy`
      預設 `localhost:443`（對齊 Caddy）。
- [ ] FX-F4（F-17，P3）：`--file-limit` 語意對齊（Caddy：browse 讀取
      目錄數上限，預設 10000）。
- [ ] FX-F5（F-29，P3）：`hash-password` 支援 `--algorithm argon2id`
      （time/memory/threads/keylen）。
- [ ] FX-F6（F-07，P1）：TLS store 對齊 Caddy——預設路徑改使用者可寫
      目錄（如 `~/.local/share/pingclair/`，`PINGCLAIR_TLS_STORE`
      覆寫）；純 HTTP（無 TLS/ACME 需求）不初始化 store。
- [ ] FX-F7（exit code，P3）：無子命令印 help 回 0（Caddy）；保留
      啟動失敗 1；SIGQUIT 對應 2（FX-C3）。
- [ ] FX-F8（fmt 引號，P3）：fmt 保留原始引號（與 Caddy 一致）。
- [ ] FX-F9（version，P3）：`version` 輸出格式對齊（單行版本號）。

---

## 🔧 FX-G — CLI 表面補齊

- [ ] FX-G1：`completion`（bash/zsh/fish/powershell，clap_complete）。
- [ ] FX-G2：`environ`（列印 process 環境後退出）。
- [ ] FX-G3：`list-modules`（列出已編譯模組/功能，支援 `--json`/
      `--skip-standard` 語意）。
- [ ] FX-G4：`build-info`（Rust 版本/依賴/commit 資訊）。
- [ ] FX-G5：`manpage --directory`（clap_mangen 生成）。
- [ ] FX-G6（F-12，P2）：`trust`／`untrust`（內部 CA `root.crt` 安裝/
      移除系統 trust）；首次 internal CA 簽發後自動嘗試安裝，失敗僅
      警告不阻止啟動（Caddy 行為）。
- [ ] FX-G7：`storage export`／`import`（Pingclair 的 storage =
      `PINGCLAIR_TLS_STORE` 目錄，tarball 語意與 Caddy 一致）。
- [ ] FX-G8：`upgrade`／`add-package`／`remove-package` — **不適用**
      （Go/xcaddy 重編譯生態）；README 三語與 CLI help 明寫
      「Pingclair 靜態編譯，無此命令」，不回 2 就算完成。

---

## 收工條件（每個 Part）

- `cargo fmt --all -- --check`
- `cargo clippy --workspace --all-targets -- -D warnings`
- `cargo build --workspace`
- `cargo test --workspace`（含新增單元與真 binary 整合測試）
- 香港機重跑該 Part 對應的測試組，結果更新到
  `docs/CADDYFILE_VM_TEST_NOTES.md`（標記已修復）。
- `docs/STATUS.md` 同步該項目狀態；使用者可見行為變化同步
  README 三語。
