# Caddyfile 虛擬機行為對照測試紀錄

此文件記錄 Pingclair 與 Caddy 在 OrbStack 虛擬機上的行為對照測試結果。
測試期間**不改動程式碼**，只記錄差異與問題；修復另行排程。

## 測試環境（2026-08-02 建立）

| 項目 | 內容 |
| --- | --- |
| 主機 | macOS（arm64） |
| 虛擬機 | OrbStack machine `ubuntu-arm64` |
| 系統 | Ubuntu 26.04 LTS（resolute），aarch64 |
| 核心 | 7.0.11-orbstack-00360-gc9bc4d96ac70 |
| Pingclair | v0.1.7，debug build，commit `8144b73`，分支 `codex/caddyfile-audit`，位於 `~/pingclair-test/pingclair` |
| Caddy | v2.11.4 官方 binary，位於 `~/.local/bin/caddy` |
| 工具 | curl、ss（`ss` 位於 `/usr/bin/ss`） |

## 紀錄格式

每筆測試紀錄包含：

1. 測試編號與日期。
2. 使用的 Pingclairfile / Caddyfile（完整內容）。
3. 實際啟動命令與環境變數。
4. Caddy 的實際行為（版本與證據）。
5. Pingclair 的實際行為（版本與證據）。
6. 差異分類：行為不符、語法不支援、文件承諾未兌現、其他。
7. 嚴重程度：P0（資料/安全/完全無法使用）、P1（主要功能不符）、P2（次要差異）、P3（可觀察但不影響使用）。
8. 重現步驟與附註（含 port、log、curl 輸出等證據）。

## 測試環境補充

第一組測試起改用 AWS 香港測試機，VM 上的 Mach-O 測試結果作廢：

| 項目 | 內容 |
| --- | --- |
| 測試機 | AWS `t4g.micro`（`i-0ad1a431e1d8138de`，18.163.185.150，ap-east-1c） |
| 系統 | Ubuntu 26.04 LTS（resolute），aarch64 |
| Pingclair | v0.1.7，debug ELF（commit `8144b73`，分支 `codex/caddyfile-audit`），以本機 Docker `rust:1.88`（linux/arm64）編譯，位於 `~/pingclair-test/pingclair` |
| Caddy | v2.11.4 官方 binary（`~/.local/bin/caddy`） |

> ⚠️ 先前在 OrbStack VM 的測試用了 macOS Mach-O binary；該 VM 註冊了
> `mac-macho-arm64` binfmt bridge 所以「能跑」，但環境變數未完整傳遞、
> 行為不可信，所有以該 binary 取得的結果一律不算。

## 第一組測試：Getting Started（2026-08-02）

以官方 Getting Started 教學流程逐項對照，Caddy 與 Pingclair 都跑在同一台
香港測試機。共用 Caddyfile 範例：

```caddy
:2015

respond "Hello, world!"
```

### 測試結果總覽

| # | 教學步驟 | Caddy 行為 | Pingclair 行為 | 判定 |
| --- | --- | --- | --- | --- |
| GS-1 | 無子命令顯示 help | rc=0 顯示 help | rc=2 顯示 help | ⚠️ 差異 |
| GS-2 | 空目錄 `run` | 空 config + admin `localhost:2019`，`GET /config/` 回 `null` | rc=1「Failed to load config: IO error」，admin 沒開 | ❌ P1 |
| GS-3 | `GET /config/` | 回傳可重新 POST 的 config document | 無 admin 時連線拒絕；有 admin 時 `/config/` 404 | ❌ P1 |
| GS-4 | `POST /load` 上傳 JSON | 200，現場開 listener 並服務 | 原：回 200「Config loaded」但**什麼都沒載入**（靜默吞掉）；已修復：400 拒絕 Caddy JSON | ❌ P0 → ✅ 已修復 |
| GS-5 | 測試 `localhost:2015` | `Hello, world!` + `Content-Type: text/plain; charset=utf-8` | 同 body/status，但**無 Content-Type** | ❌ P2 |
| GS-6 | 寫 Caddyfile + `adapt` | 輸出 Caddy native JSON | 輸出 Pingclair native JSON（`0.0.0.0:2015`、`respond`、`path /*`） | ⚠️ 格式不同 |
| GS-7 | 自動偵測 `Caddyfile` 啟動 | ✅ | ✅（有設 `PINGCLAIR_TLS_STORE` 時） | ✅ |
| GS-8 | `--config` 指定檔名 | `caddy run --config path`、`--adapter` | `pingclair run --config` 直接 clap 錯誤（只吃 positional） | ❌ P2 |
| GS-9 | `validate` | ✅ | ✅ | ✅ |
| GS-10 | `start`／`stop` 背景執行 | ✅ `caddy start`/`caddy stop` | 兩個子命令都不存在 | ❌ P1 |
| GS-11 | 零停機 reload | `caddy reload` 成功；壞 config 失敗且保留舊 config | SIGUSR1 成功；壞 config rollback 成功；**新 listener 不會開啟** | ⚠️ 部分 |
| GS-12 | 一般使用者直接啟動 | ✅ 不需任何 store | ❌ 沒設 `PINGCLAIR_TLS_STORE` 時，連純 HTTP 都因 `/var/lib/pingclair/certs` 權限退出 | ❌ P1 |

### 重點問題：表面正常但實際行為不符

#### F-01（P0）`POST /load` 收到 Caddy JSON 回 200 但載入空配置（已修復）

實測：admin-enabled 的 Pingclair 收到教學的 Caddy JSON
（`{"apps":{"http":{"servers":{...}}}}`）後回應
`Config loaded`（HTTP 200），但 `PingclairConfig` 沒有 `apps` 欄位且
serde 未拒絕未知欄位，實際載入的是 **0 個 server**，舊配置原封不動。
照官方教學操作的使用者會以為設定成功，這是本組最危險的「表面正常」。

證據：`curl -X POST ... -d @tutorial.json` → `Config loaded` / `status=200`；
後續請求仍由舊配置回應。

**修復（2026-08-02，隨本 commit 上線）**：在 `PingclairConfig` 根結構加
`#[serde(deny_unknown_fields)]`，任何非 Pingclair 的 JSON（例如 Caddy 的
`apps` 欄位）在 `/load` 與 `.json` 設定檔路徑都直接拒絕，不再默默載入
空配置。新增測試：

- `pingclair-config/src/adapter/json.rs`：Caddy JSON 必須回報
  `unknown field`；空 document 仍合法。
- `pingclair/tests/integration.rs`（`test_admin_load_rejects_caddy_json`）：
  真 binary + 真 admin socket 上，POST Caddy JSON 回 400，既有 server
  原樣服務。

香港機實測（修復版 ELF）：Caddy JSON → `400 Invalid config: unknown field
`apps``；原生 adapt JSON → 200 `Config loaded`；`run caddy.json` →
啟動失敗並指明 unknown field。

#### F-02（P1）`POST /load` 不能現場建立新 listener

Pingclair 的 `/load` 只允許「更新已綁定 listener 的 server」；把 adapt
結果改成 `:2016` 再 POST 會回 404
`{"error":"no listener is bound to 0.0.0.0:2016; nothing was applied"}`。
Caddy 從空 config 直接 `/load` `:2015` 就 200 且立刻服務。
教學的「先跑空 daemon → `/load` 餵 config」流程因此不可行（F-01 之外的另一半）。

#### F-03（P1）`GET /config/` 與文件匯出語義不符

- 教學用的尾斜線路徑 `/config/` 回 404（只精確匹配 `/config`）。
- `GET /config` 的輸出不是可回 POST 的完整文件：就算 config 裡有
  `admin 127.0.0.1:2019`，輸出仍是 `"admin": null`；`global` 也只顯示
  default 值。此輸出對自動化是陷阱。

#### F-04（P1）`POST /stop` 不回應 HTTP

實測 `curl -X POST localhost:2019/stop` 收到 `Empty reply from server`
（無 status）。端點存在但不像 Caddy 先回覆再停機；直接呼叫的客戶端
會看到連線被切斷。

#### F-05（P2）`respond` 缺少 `Content-Type`

`respond "Hello, world!"` 的 status、body、Content-Length 都與 Caddy 一致，
但 Caddy 送 `Content-Type: text/plain; charset=utf-8`，Pingclair 完全沒有
Content-Type。對照時「body 一樣」會誤以為行為一致，實際下游可能走
content sniffing。

#### F-06（P2）`:2015` 只綁 IPv4，Caddy 是雙棧

`curl http://[::1]:2015/`：Caddy 200；Pingclair connection refused。
Pingclair adapt 輸出 `"listen": ["0.0.0.0:2015"]`，Caddy 是 `[":2015"]`。

#### F-07（P1）一般使用者第一次啟動就失敗

Ubuntu 使用者在沒有 `PINGCLAIR_TLS_STORE` 時，`pingclair run` 連純 HTTP
都無法啟動：

```
Error: 🔐 TLS store /var/lib/pingclair/certs cannot be created: Permission denied (os error 13)
```

Caddy 不需任何 writable store。即使設了 store，教學流程第一步（空 config
啟動）依然失敗（GS-2）。

#### F-08（P2）CLI 旗標/子命令與教學不同

- `pingclair run --config site.conf`：clap 錯誤「unexpected argument
  '--config'」；Pingclair 只吃 positional `pingclair run site.conf`
  （positional 可正常啟動）。
- `pingclair start`／`pingclair stop` 不存在（Caddy 教學最後兩步無法照做）。
- 無子命令時 exit code 2（Caddy 0）。

#### F-09（P2）reload 對新 listener 只算「部分成功」

啟動只有 `:2015` 的配置後，把 Caddyfile 改成 `:2015` + `:2016` 再
SIGUSR1：`:2015` 維持服務，`:2016` 保持不開；log 只印
`⚠️ Configuration partially reloaded (1 servers updated, 1 warnings)`，
沒有列出警告細節。Caddy `reload` 會套用新 listener，失敗則完整 rollback。
（Pingclair 壞配置 rollback 本身有做好：「Previous configuration remains
active」。）

### 通過項目

- `pingclair adapt`／`validate`／自動偵測 `Caddyfile`／SIGUSR1 一般 reload
  （同 listener 內容更新）都正常。
- Caddy 對照組 `start/stop`、`reload`、`/load` 開新 listener、`/config/`
  匯出均如文件所述。

### 待辦註記

- F-01 已依使用者指示先行修復並驗證；其餘差異（F-02～F-09 等）仍只記錄、
  未改碼。
- 下一組測試前可考慮的候選修復：F-05（`respond` 預設 Content-Type）、
  F-06（`:2015` 改雙棧 listen），但需另行排程。
