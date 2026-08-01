# Command Line 需求文檔（對照 Caddy 官方 command-line）

> 📌 本專項以 Caddy 官方文檔（`command-line`，本機
> `~/code/caddy-website`）為基準，對照 Pingclair 的 CLI
> （`pingclair/src/main.rs`，clap 定義 :220 附近）。

## 1. 子命令對照

| Caddy 子命令 | 用途 | Pingclair | 備註 |
|---|---|---|---|
| `run` | 前台啟動（config/adapter/pidfile/environ/envfile/resume/watch） | ⚠️ 只有 `run <config>` | 見 C1–C3 |
| `reload` | 經 admin API 換 config | ❌ | 只能 SIGHUP（C3） |
| `start`／`stop` | 背景啟動／優雅停止 | ❌ | 有 `service` 子命令（systemd 包裝） |
| `validate` | 驗證 config 後退出 | ⚠️ 只有 compile 層驗證 | 見 C2 |
| `adapt` | Caddyfile→JSON | ❌ | 已有能力但沒 CLI 入口 |
| `fmt` | 格式化 Caddyfile | ❌ | |
| `hash-password` | 產生 bcrypt/argon2id hash | ❌ | DSL 已有 basic_auth bcrypt，卻沒有產生工具 |
| `file-server` | 快速靜態伺服器 | ⚠️ 只有 `--listen`/`--root` | 見 C4 |
| `reverse-proxy` | 快速反代 | ⚠️ 只有 `--from`/`--to` | 見 C5 |
| `respond` | 開發用固定回應伺服器 | ❌ | |
| `trust`／`untrust` | 安裝/移除本機 CA 信任 | ❌ | `tls internal` 有 root.crt 但無 CLI |
| `completion`／`manpage`／`environ`／`build-info`／`list-modules` | 工具 | ❌ | |
| `storage export/import` | storage 遷移 | ❌ | |
| `upgrade`／`add-package`／`remove-package` | 升級/插件 | ❌ | 不適用（Rust 無插件生態） |
| `version` | 版本 | ✅ | |
| `service` | — | ✅（Pingclair 特有） | systemd 管理，Caddy 沒有 |

## 2. 已確認缺口（依影響排序）

### 🔴 C1：沒有 `adapt`／`fmt`——設定生態的基礎工具缺一

`pingclair_config::compile()` 已有 Pingclairfile→core→JSON 的完整
能力，卻沒有 CLI 暴露。Caddy 的 `caddy adapt --config Caddyfile
--pretty` 是遷移、CI、人工 review 的第一工具；`caddy fmt` 是
「文件範例不再能編譯」這類問題的第一道防線（本專案 documentation
測試做了類似的事，但 CLI 沒有）。**最低需求**：`pingclair adapt
[--pretty] [--validate]` 與 `pingclair fmt [--overwrite]`。

### 🔴 C2：`validate` 沒有 provisioning 層驗證

Caddy 的 `validate` 不只 parse，還會 load/provision 模組——例如
`tls cert_notexist.pem key_notexist.pem` 在 `adapt` 成功、`validate`
失敗（文件原話）。Pingclair 的 `validate` 只跑 `compile_file`
（parse + semantic + validate_config），**不會檢查 cert/key 檔案
是否存在、upstream TLS 素材能否載入**。這正是 GUARDRAILS 強調的
「驗證函式 ≠ 真實路徑」：cert 檔不存在要等啟動/首次 handshake 才爆。
需求：`validate` 走完整 provisioning 路徑（TLS store 初始化、
cert 讀取、upstream TLS 編譯），或至少檢查檔案的 I/O 存在性。

### 🟠 C3：reload 訊號與 Caddy 相反（SIGHUP vs SIGUSR1）

- Caddy：**SIGHUP 忽略**；SIGUSR1 reload（僅限 `run` 無 `--resume`
  且未經 API 改過 config）；API reload 後 signal reload 停用；
- Pingclair：**SIGHUP reload**，SIGUSR1 完全沒處理。

如果使用者從 Caddy 遷移 systemd/腳本（`kill -USR1` 或 `-HUP`），
行為會完全相反。需求：至少把 SIGHUP reload 的行為寫進 README；
建議支援 SIGUSR1（Caddy 慣例）並保留 SIGHUP 相容，同時記錄
「API 改過 config 後 signal reload 停用」的語意。

### 🟠 C4：`file-server` 缺 browse/domain/templates/access-log 等旗標

Caddy：`--root`、`--listen`（預設 :80，`--domain` 時 :443）、
`--domain`（自動 HTTPS）、`--browse`、`--reveal-symlinks`、
`--templates`、`--access-log`、`--debug`、`--file-limit`、
`--no-compress`、`--precompressed`。Pingclair：只有 `--listen`
（預設 :8080）與 `--root`。`--browse` 是最常用的開發旗標。

### 🟠 C5：`reverse-proxy` 缺 header-up/down、insecure、internal-certs

Caddy：`--from`（hostname 時預設 HTTPS）、`--to`（可多個、port
range）、`--header-up`、`--header-down`、`--change-host-header`、
`--disable-redirects`、`--internal-certs`、`--insecure`（警告）。
Pingclair：只有 `--from`/`--to` 各一。快速驗證 mTLS、header 修改、
內部憑證的情境全部做不到。另外 Pingclair 的 `--from` 預設 :8080
（Caddy 是 :80/:443 依 domain 推導）。

### 🟡 C6：`run` 缺 `--resume`／`--watch`／`--pidfile`／`--envfile`

- `--resume`：Caddy 保證「API 改過的 config 重啟不丟」（admin 文檔
  A5）。Pingclair 無 persistence，自然無 resume；
- `--watch`：開發用自動 reload（tutorial 文檔已列）；
- `--pidfile`／`--envfile`：systemd/容器常見需求；Pingclair 的
  `service` 子命令部分補償了前者。

### 🟡 C7：config 檔名「Caddyfile」不被辨識

`compile_directory` 只收 `*.pingclair`／`*.json`／`Pingclairfile`；
`run` 預設找 `Pingclairfile`。使用者照 Caddy 習慣放 `Caddyfile`，
`pingclair run` 直接報找不到。需求：`run`/`validate` 的預設查找
順序納入 `Caddyfile`（且 `compile_file` 對無副檔名檔案照樣編譯——
現況本來就支援無副檔名，只是預設檔名沒列 Caddyfile）。

### 🟡 C8：`hash-password` 缺失與 exit code 語意

- DSL 支援 bcrypt basic_auth（cost 上限 14），卻沒有
  `pingclair hash-password` 產生 hash——使用者只能靠外部工具；
- exit code：現況只有 0/1（`std::process::exit(1)`）。Caddy 定義
  0 正常、1 啟動失敗、2 強制退出、3 清理失敗。至少把 1 保留給
  「啟動失敗，不要自動 restart」並寫進文件。

## 3. 驗證需求

1. `pingclair adapt --config Pingclairfile --pretty` 輸出 JSON；
   `pingclair fmt` 對官方範例格式化的結果穩定；
2. `pingclair validate` 對「cert 檔案不存在」的設定回非零 exit；
3. `kill -USR1 <pid>`（或 SIGHUP）reload 後 global 變更至少警告
   （admin 文檔 A1 的修復合併驗證）；
4. `pingclair file-server --browse`、`pingclair reverse-proxy
   --from localhost:8443 --to app:8080 --insecure` 可用；
5. README 三語的 CLI 章節與實際支援一致。

## 4. 明確不做（本文件範圍外）

- `storage export/import`、`completion`、`manpage`——列 v0.3。
- `upgrade`／`add-package`——Rust 無 Caddy 的插件下載生態，不做。
- `respond` 命令——有 `file-server`/`reverse-proxy` 就夠，
  可選（v0.3）。
