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

## 第二組測試：API Quick-start（2026-08-02）

官方「API quick-start」流程：`caddy start` → 空 config → `POST /load`
上傳 Caddy JSON（單站 `:2015`）→ 再上傳雙站（`:2015` + `:2016`）→
`caddy stop`。Pingclair 使用修復版 binary（commit `70d0fb0`）。

### Caddy 基準（全部符合文件）

| 步驟 | 結果 |
| --- | --- |
| `caddy start` 空配置 | admin `:2019`，`GET /config/` → `null` |
| `POST /load` 單站 | 200，`:2015` 回 `Hello, world!` |
| `POST /load` 雙站 | 200，`:2015` 與 `:2016` 同時服務 |
| `caddy stop` | 正常停止 |

### Pingclair 對照

| 步驟 | 結果 | 判定 |
| --- | --- | --- |
| `pingclair start` | 子命令不存在（rc=2） | ❌ 同 F-08 |
| 空配置啟動 | 無法空跑（同 GS-2） | ❌ |
| `POST /load` 同一份 Caddy JSON | `400 Invalid config: unknown field 'apps'` | ✅ P0 修復生效（fail loud） |
| `POST /load` 原生雙站 JSON（listener 已綁定） | 200，兩站正常 | ✅ |
| `POST /load` 原生 JSON 新增 `:2017` | 404 `no listener is bound to 0.0.0.0:2017`，`:2017` 沒開 | ❌ 同 F-02 |
| `GET /config/`、`GET /config/servers` | 都 404 | ❌ 同 F-03（無 fine-grained 路徑） |
| `POST /load` 只含 `:2015` 的文件 | 200；`:2015` 更新成功，但 `:2016` 仍在服務 | ❌ 新發現 F-10 |
| `POST /stop` | empty reply（無 HTTP response） | ❌ 同 F-04 |

### 新發現

#### F-10（P1）`/load` 是「累加更新」，不是 Caddy 的「整包替換」

Caddy 的 `POST /load` 會用新 document 整包取代 active config；Pingclair
的 `/load` 只對「document 中列出、且已綁定的 listener」執行
`add_server`，**document 沒列出的 listener 原封不動**。實測：載入只含
`:2015` 的原生 document 後，`:2016` 仍回 `initial-b`。自動化若把
`/load` 當「整包替換」使用，會留下預期外仍然在跑的舊站。

證據：`POST /load`（單站文件）→ 200；`:2015` 回 `only-2015`、`:2016`
仍回 `initial-b`。

### 本組總結

- API Quick-start 幾乎每一步都依賴 Caddy 特有的「空 daemon + `/load`
  可開新 listener + 整包替換」；Pingclair 目前只有「已綁定 listener 的
  累加更新」。
- P0 修復在這一組再次驗證：同一份 Caddy JSON 現在會明確回 400。
- 本組未改任何程式碼，只記錄。

## 第三組測試：Caddyfile Quick-start（2026-08-02）

官方流程：`localhost` + `respond` → `caddy start`（自動 local HTTPS，
443 + 80 companion）→ `https://localhost` 驗證 → 改成雙站
（`localhost` + `localhost:2016`）→ 用 `POST /load`
（`Content-Type: text/caddyfile`）或 `caddy reload` 更新 →
`https://localhost:2016` 驗證 → `caddy stop`。

測試機上兩支 binary 都以 `cap_net_bind_service` 啟動（避免 sudo 干擾
環境變數與 process 管理）。

### Caddy 基準（全部符合文件）

| 步驟 | 結果 |
| --- | --- |
| `localhost` 自動 HTTPS | `*:443` + `*:80`，`https://localhost` 回 `Hello, world!`；內部 CA 自動建立並嘗試裝入系統 trust |
| `POST /load` text/caddyfile 雙站 | 200；`https://localhost` 與 `https://localhost:2016` 都正常 |
| `caddy reload` | 200，內容更新 |
| `caddy stop` | 正常，port 全釋放 |

### Pingclair 對照（修復版 binary，commit `70d0fb0`）

| 步驟 | 結果 | 判定 |
| --- | --- | --- |
| `localhost` 自動 HTTPS | `0.0.0.0:443` + `0.0.0.0:80`；`https://localhost` 回 `Hello, world!`；internal CA 產生 `authority.json`/`root.crt` | ✅ 核心流程可用 |
| `http://localhost` companion | 308 → `https://localhost/` | ✅ 與 Caddy 一致 |
| `localhost:2016` 啟動時就綁定 | `https://localhost:2016` 回 `Goodbye, world!`（自動 TLS） | ✅ |
| SIGUSR1 reload 新增 `localhost:2016` | `:2016` 不開，log 只有「1 warnings」 | ❌ 同 F-09 |
| `POST /load`（text/caddyfile） | `400 Invalid config: expected value`；且沒設 `admin` 時連線直接被拒 | ❌ 新發現 F-11 |
| 系統 trust store | 不自動安裝；只把 `root.crt` 寫進 TLS store | ❌ 新發現 F-12 |
| `https://127.0.0.1`（SNI=IP） | 握手失敗 `NO_CERTIFICATE_SET` | ⚠️ Caddy 同樣失敗（tlsv1 alert），不算差異 |

### 新發現

#### F-11（P1）`/load` 不支援 config adapter，文件中的 API 更新步驟不可行

Caddy 的 quick-start 用 `POST /load -H "Content-Type: text/caddyfile"`
直接上傳 Caddyfile 文字。Pingclair 的 `/load` 只接受 JSON：

- 沒在 config 開 `admin` 時（quick-start 的 Caddyfile 沒有 global block），
  `localhost:2019` 根本沒 listener，連線被拒；
- 開了 `admin 127.0.0.1:2019` 後送同一請求 → `400 Invalid config:
  expected value at line 1 column 1`。

`/adapt` 可以轉 Caddyfile 文字，但 `/load` 不會先過 adapter；自動化若照
Caddy 習慣直接 `/load` Caddyfile 會失敗。

#### F-12（P2）`localhost` 內部 CA 不會自動裝進系統 trust store

Caddy 第一次啟動會嘗試把 local root CA 安裝進系統信任（log：
`installing root certificate (you might be prompted for password)`，
第二次起顯示 `root certificate is already trusted by system`）。
Pingclair 只把 `root.crt` 與 `authority.json` 寫進
`PINGCLAIR_TLS_STORE/internal/`，不做任何系統 trust 安裝；照 quick-start
用瀏覽器開 `https://localhost` 會看到憑證錯誤，除非手動信任 `root.crt`。
（這是設計差異，但對照 quick-start 的「第一次跑會被問密碼」承諾仍算缺口。）

### 本組總結

- Pingclair 的 localhost 自動 HTTPS 主流程（443、80 轉跳、雙站啟動時
  綁定）可用；主要卡點在「reload/API 更新」與「自動信任」。
- `https://127.0.0.1` 兩邊都失敗，非 Pingclair 差異，不列入。
- 本組未改任何程式碼，只記錄。

## 第四組測試：Static files quick-start（2026-08-02）

官方流程分兩條：CLI（`caddy file-server`，含 `--listen`、`--browse`、
`--root`）與 Caddyfile（`localhost` + `file_server`、`browse`、`root`）。
Pingclair 使用修復版 binary（commit `70d0fb0`），低端口已設
`cap_net_bind_service`。

### Caddy 基準（全部符合文件）

| 測試 | 結果 |
| --- | --- |
| `file-server --listen :2115` | `/` 回 index；`/sub/file.txt` 正常；`/empty/` 無 browse 回 404；headers 含 `Content-Type: text/html; charset=utf-8`、ETag、Accept-Ranges、Last-Modified |
| `file-server --browse --listen :2116` | `/empty/` 回 200 目錄列表（含 CSP header） |
| `file-server --root <dir> --listen :2117` | root 生效 |
| `file-server --domain localhost --listen :2118` | `https://localhost:2118` HTTP/2 200，內部 CA 正常 |
| `file-server`（無旗標） | 預設 `:80` 正常 |
| Caddyfile `localhost` + `file_server`／`browse`／`root` | 三種都正常（`https://localhost`） |

### Pingclair 對照

| 測試 | 結果 | 判定 |
| --- | --- | --- |
| `file-server --listen :2115` | body/status 正確；`Content-Type: text/html`（**無 charset**）、ETag `"f-1"` 格式不同 | ⚠️ F-15 |
| `file-server --browse --listen :2116` | `/empty/` 200 列表 | ✅ |
| `file-server --root <dir> --listen :2117` | root 生效 | ✅ |
| `file-server --domain localhost --listen :2118` | 啟動成功但 **TLS 無憑證**（`NO_CERTIFICATE_SET`），所有握手失敗 | ❌ F-13 |
| `file-server --listen 2118`（bare port） | 啟動 panic（`Invalid HTTP/3 listen address: 2118`）；help 卻寫「requires --listen to be a port」 | ❌ F-13 |
| `file-server`（無旗標） | 預設 `:8080`（Caddy 是 `:80`） | ⚠️ F-16 |
| `file-server`（無 `PINGCLAIR_TLS_STORE`） | 啟動即失敗（同 F-04） | ❌ |
| Caddyfile `localhost` + `file_server`／`browse`／`root` | 三種都正常（`https://localhost`，HTTP/2 + alt-svc） | ✅ |
| SIGUSR1 reload：`file_server` → `file_server browse` | log 顯示「reloaded successfully」但 `/empty/` 仍 404，**browse 沒生效** | ❌ F-14 |

### 新發現

#### F-13（P2）`file-server --domain localhost` 啟動但 HTTPS 完全不可用

`pingclair file-server --domain localhost --listen :2118` 會印
`🚀 Pingclair running...` 並開 listener，但 TLS 握手全部失敗
（`TLSHandshakeFailure ... [NO_CERTIFICATE_SET]`）——CLI 的 `--domain`
路徑沒有像 Caddyfile 的 `localhost` site 那樣觸發 internal CA 簽發。
另外 help 說 `--domain` 的 `--listen` 可以是 bare port，實測
`--listen 2118` 直接 panic：
`Invalid HTTP/3 listen address: 2118`。Caddy 對應用法正常。

#### F-14（P1）reload 改 `file_server browse` 無效，但 log 宣稱成功

啟動 `localhost + file_server` 後把 Caddyfile 改成
`localhost + file_server browse`，SIGUSR1 reload：

```
✅ Configuration reloaded successfully (1 servers updated in 401.08µs)
```

但 `/empty/` 仍回 404（reload 前後都是 404）。這是典型的「表面正常但
實際不符」：reload 路徑更新了 route，卻沒有把 browse 行為帶進
file-server 的執行狀態（或更新被靜默忽略），operator 會以為目錄列表
已開啟。

#### F-15（P3）file_server 的 Content-Type 缺 charset

`index.html` → `Content-Type: text/html`、`file.txt` →
`Content-Type: text/plain`；Caddy 為 `text/html; charset=utf-8` /
`text/plain; charset=utf-8`。UTF-8 內容在沒有 charset 時可能被舊瀏覽器
誤判。另有 minor：alt-svc `ma=86400`（Caddy 2592000）、ETag 格式不同。

#### F-16（P3）`file-server` 預設 port 不同

Caddy 預設 `:80`（文件直接 `caddy file-server` 後開 `localhost`）；
Pingclair 預設 `:8080`（help 明寫 default `:8080`）。照文件操作會發現
網站不在預期 port。

#### F-17（P3）`--file-limit` 語意不同

Caddy：`Max directories to read`（browse 時讀取目錄數上限，預設
10000）；Pingclair：`Maximum files shown in a directory listing`
（列表顯示檔案數上限）。同名旗標、不同語意。

### 本組總結

- 基本靜態檔案服務（index、browse、root）Pingclair 都可用；主要問題在
  CLI `--domain` 路徑、reload 不套用 browse、與若干 header/CLI 表面差異。
- 本組未改任何程式碼，只記錄。

## 第五組測試：Reverse proxy quick-start（2026-08-02）

官方流程：`caddy reverse-proxy --from :2080 --to :9000`（明文）、
Caddyfile `:2080` + `reverse_proxy :9000`、`--to :9000` 預設
localhost HTTPS、`--from example.com:8443` 高 port HTTPS、HTTPS upstream
（`--to https://...`）與 `--change-host-header`。測試用 Python echo
backend（`127.0.0.1:9000`，回顯收到的 headers）與 Caddy 內部 CA TLS
backend（`localhost:9443`）。

### Caddy 基準（全部符合文件）

| 測試 | 結果 |
| --- | --- |
| CLI 明文 `--from :2080 --to :9000` | 200；Host 原樣傳遞；`Via: 1.1 Caddy`、X-Forwarded-For/Host/Proto |
| Caddyfile `:2080` + `reverse_proxy :9000` | 同上 |
| `--to :9000`（預設 `--from localhost`） | `https://localhost` 200 |
| `--from example.com:8443 --internal-certs` | 以正確 SNI 連線 200 |
| `--to https://localhost:9443`（HTTPS upstream） | 200（此情境不需 `--change-host-header` 也能握手） |
| `--change-host-header` | backend 看到 `Host: localhost:9443` |

### Pingclair 對照（修復版 binary，commit `70d0fb0`）

| 測試 | 結果 | 判定 |
| --- | --- | --- |
| CLI 明文 `--from :2080 --to :9000` | **502 `no upstream available`**；改用 `127.0.0.1:9000`／`localhost:9000` 才正常 | ❌ F-20 |
| Caddyfile `reverse_proxy :9000` | 同樣 502（`:9000` upstream 解析失敗） | ❌ F-20 |
| `--to 127.0.0.1:9000`（預設 `--from`） | `:8080` 明文 200，**沒有 443** | ⚠️ F-18 |
| `--from localhost` | 啟動 panic：`Invalid HTTP/3 listen address: localhost`（先綁了 `:80` 後崩潰） | ❌ F-21 |
| `--from example.com:8443 --internal-certs` | 啟動失敗：`Invalid internal certificate domain: example.com:8443`，8443 沒開 | ❌ F-21 |
| `--to https://localhost:9443`（HTTPS upstream） | 200，不需額外旗標 | ✅ |
| `--header-up 'Host: localhost:9443'` | backend 看到 `Host: localhost:9443` | ✅（替代方案） |
| `--change-host-header` | 旗標不存在 | ❌ F-19 |

### 新發現

#### F-20（P1）upstream 裸 port（`:9000`）解析失敗，quick-start 範例直接 502

文件與 Caddyfile 都用 `reverse_proxy :9000`。Pingclair 的 adapt 會保留
`":9000"` 為 upstream address，但 runtime 找不到可用 upstream，回
`502 no upstream available`（`tries: 1`，連 connect 都沒嘗試）。
`127.0.0.1:9000` 與 `localhost:9000` 都正常。Caddy 把 `:9000` 當
`127.0.0.1:9000`。這是本組最直接的「照文件操作就壞」。

#### F-21（P1）CLI HTTPS 的 `--from` 兩條路徑都壞

- `--from localhost`：panic
  `Invalid HTTP/3 listen address: localhost`（先綁 `:80` 再崩潰）；
- `--from example.com:8443 --internal-certs`：啟動即失敗
  `Invalid internal certificate domain: example.com:8443`（把
  `host:port` 整個當成 domain 去簽 internal cert）。

Caddy 對應用法（`--to :9000` 預設 localhost HTTPS、
`--from example.com:8443 --internal-certs`）都正常。因此文件中的
「最簡單 HTTPS 代理」在 Pingclair CLI 上不可用；Caddyfile 的
`localhost` site 路線（第三組已驗證）是唯一可用的 HTTPS 路徑。

#### F-19（P2）沒有 `--change-host-header`

Pingclair `reverse-proxy --help` 沒有 `--change-host-header`（Caddy 有
`-c/--change-host-header`）。HTTPS upstream 需要改 Host 時可用
`--header-up 'Host: <upstream>'` 達到同等效果（實測有效），但文件範例
照抄會直接「unknown flag」。

#### F-18（P2）`reverse-proxy` 預設 `--from` 不同

Caddy 預設 `--from localhost`（HTTPS 443）；Pingclair 預設 `:8080`
（明文）。照文件執行 `caddy reverse-proxy --to :9000` 後開
`https://localhost` 的步驟，在 Pingclair 上會連到 `:8080` 且無 TLS。

### 本組總結

- 明文代理與 HTTPS upstream 在「明確寫出 IP/host」時可用；但 quick-start
  的兩個關鍵範例（`--to :9000` bare port、CLI 預設 HTTPS）都失敗。
- 本組未改任何程式碼，只記錄。

## 第六組測試：HTTPS quick-start（2026-08-02）

官方流程需要公開域名與對外 80/443；依使用者註記**略過真實 ACME 簽發**
（無域名），改測：假域名下的失敗模式、`tls internal` 不適用（此組未含）、
DSL 與 JSON 的自動 HTTPS 觸發行為。

### Caddy 基準

| 測試 | 結果 |
| --- | --- |
| Caddyfile `example.com` + `respond`（無 DNS） | `*:443` + `*:80`；`:80` 回 308 轉跳；`:443` 在 ACME 簽發前握手失敗（TLS alert）；背景重試（rate limiter、退避），不 crash |
| JSON host matcher（文件範例） | `*:443` + `*:80`，ACME 開始取得憑證流程 |

### Pingclair 對照（修復版 binary，commit `70d0fb0`）

| 測試 | 結果 | 判定 |
| --- | --- | --- |
| Caddyfile `example.com` + `respond`（**沒寫 `tls auto`**） | 只有 `0.0.0.0:80`，明文 200；443 不存在 | ❌ F-22 |
| Caddyfile `example.com { tls auto ... }` | `0.0.0.0:443`（TLS/H3）+ `0.0.0.0:80` companion（308）；eager ACME 啟動，`example.com` 被 LE 拒絕後 log 警告並繼續跑 | ✅ 與 Caddy 失敗模式一致 |
| 原生 JSON：`names: ["example.com"]` + `listen: ["0.0.0.0:443"]` + `tls.auto` | 443 TLS listener 有開，但 **0 次 eager issuance、沒有 :80 companion**，握手直接 EOF | ❌ F-23 |

### 新發現

#### F-22（P1）bare hostname 沒有預設自動 HTTPS

Caddy 只要 site 位址有 hostname 就預設自動 HTTPS（文件開頭明說）。Pingclair
的 `example.com` + `respond`（無 `tls auto`）會編譯成
`listen: []`、`tls: None`，最後以**明文 `:80` 直接 200** 服務。HTTPS
quick-start 的第一個 Caddyfile 範例照抄會得到「看起來正常但其實沒有
TLS」的結果，比「表面正常但不同」更危險。

#### F-23（P2）JSON 的 `names` + `tls auto` 不觸發簽發與 companion

Pingclair 原生 JSON：

```json
{"servers": [{"names": ["example.com"], "listen": ["0.0.0.0:443"],
  "tls": {"auto": true, ...}, "routes": [...]}]}
```

啟動後 log 顯示 `📍 0.0.0.0:443 -> [default]`、`Auto HTTPS: enabled`，
但 `Eager issuance` 出現 0 次、`:80` companion 出現 0 次；curl 握手
直接 EOF（無憑證）。DSL 等價寫法（`example.com { tls auto }`）則會
簽發＋80 companion。Caddy 的 host matcher JSON 會觸發自動 HTTPS。

### 本組總結

- 明確 `tls auto` 的 DSL 路徑行為正確（443+80+ACME 失敗重試）；缺口在
  「hostname 預設即 HTTPS」與 JSON 路徑的自動 HTTPS 觸發。
- 本組未改任何程式碼，只記錄。

## 第七組測試：API Tutorial（2026-08-02）

官方流程：空 daemon → `GET /config/` → `POST /load`（首次）→ 再次
`POST /load`（整包替換）→ config traversal
（`POST /config/apps/.../body`、`GET /config/.../routes`）→ `@id`
（`/config/.../@id`、`/id/msg`、`/id/msg/body`）。

### Caddy 基準（全部符合文件）

| 步驟 | 結果 |
| --- | --- |
| 空 daemon `GET /config/` | `null` |
| `POST /load` 首次 | 200，`:2015` 回 `Hello, world!` |
| `POST /load` 整包替換 | 200，`:2015` 回 `I can do hard things.` |
| traversal `POST .../routes/0/handle/0/body` | 200，`:2015` 更新；`GET .../routes` 回正確陣列 |
| `@id`：`POST .../@id` → `GET /id/msg` → `POST /id/msg/body` | 全部 200，短路徑可讀寫 |

### Pingclair 對照（修復版 binary，commit `70d0fb0`）

| 步驟 | 結果 | 判定 |
| --- | --- | --- |
| 空 daemon | 無法空跑（同 GS-2） | ❌ |
| `GET /config/` | 404 | ❌ F-03 |
| `POST /load`（同一份 Caddy tutorial JSON） | 400 `unknown field 'apps'` | ✅ P0 修復 |
| `POST /load`（原生 adapt JSON） | 200，`:2015` 可更新 | ✅ |
| `GET /config` | 200（但輸出失真：`admin: null` 等） | ❌ F-03 |
| traversal `POST /config/apps/http/.../body` | 400 `expected struct ServerConfig` | ❌ F-24 |
| traversal `GET /config/apps/http/.../routes` | 404 | ❌ F-03 |
| `POST /config/0/@id` | 400 `expected struct ServerConfig` | ❌ F-24 |
| `GET /id/msg` | 404 | ❌ F-03（無 @id） |

### 新發現

#### F-24（P2）`POST /config/<path>` 是 ServerConfig 上傳，不是 config traversal

Pingclair 把「任何以 `/config` 開頭的 POST」都當成**單一 ServerConfig
上傳**（`serde` 直接 parse `ServerConfig`）。照 Caddy 寫
`POST /config/apps/http/servers/example/routes/0/handle/0/body` 會回
`400 Invalid config: invalid type: string ..., expected struct
ServerConfig`——路徑被忽略、body 被當成整個 ServerConfig。這不是單純
「未實作」，而是**同一個 HTTP 路徑、完全不同的語意**：自動化若照
Caddy 習慣呼叫，會收到看似合理的 400，但原因與 Caddy 的語意無關。

### 本組總結

- API Tutorial 的 traversal 與 `@id` 兩大能力 Pingclair 完全沒有；
  `POST /config/*` 的語意陷阱（F-24）建議列入修復需求（至少改成
  明確「不支援 config path traversal」的 404/501，而不是把 body 當
  ServerConfig 解析）。
- 本組未改任何程式碼，只記錄。

## 第八組測試：Caddyfile Tutorial（2026-08-02）

官方流程：first site（`localhost` + `respond`，用 `--watch`）→
`file_server browse` → `templates` → `encode` → multiple sites →
matchers → env vars → comments。

### Caddy 基準（全部符合文件）

| 步驟 | 結果 |
| --- | --- |
| `run --watch` + 改檔 | 自動套用（respond → browse 不用重啟） |
| `templates` + `caddy.html` | 模板渲染日期（`Page loaded at: Sat Aug 1 ...`） |
| `encode` | gzip + `Vary: Accept-Encoding` |
| multiple sites（兩站／共享位址） | 全部正常 |
| matcher `/api/*` | proxy 只吃 `/api/*`，其餘 file_server |
| 無 matcher：`file_server` + `reverse_proxy` | `reverse_proxy` 優先（連 `/index.html` 都被 proxy） |
| env vars（`{$SITE_ADDRESS}`） | 展開並綁定 `localhost:9055`（HTTPS） |
| comments | 正常 |

### Pingclair 對照（修復版 binary，commit `70d0fb0`）

| 步驟 | 結果 | 判定 |
| --- | --- | --- |
| `run --watch` | 旗標不存在（clap rc=2） | ❌ F-25 |
| 啟動時 `file_server browse` | 正常 | ✅ |
| SIGUSR1 把 `respond` 換成 `file_server browse` | log 成功但回應仍是 `Hello, world!` | ❌ F-14 擴充 |
| `templates` | adapt/run 都 fail-closed：`directive 'templates' is not supported` | ❌ F-26 |
| `encode`（gzip） | `Content-Encoding: gzip` 有，**缺 `Vary: Accept-Encoding`** | ❌ F-27 |
| multiple sites（兩站／共享位址） | 全部正常 | ✅ |
| matcher `/api/*` | proxy 只吃 `/api/*`，其餘 file_server | ✅ |
| 無 matcher：`file_server` + `reverse_proxy` | **file_server 優先**（與 Caddy 相反） | ❌ F-28 |
| env vars（`{$SITE_ADDRESS}`） | 展開並綁定 `localhost:9055`（HTTPS；空目錄 404 內容不同） | ✅（minor 差異） |
| comments | 正常 | ✅ |

### 新發現

#### F-25（P3）`pingclair run` 沒有 `--watch`

Tutorial 用 `caddy run --watch` 讓 Caddyfile 變更自動套用；Pingclair 的
`run` 只有 positional CONFIG，`--watch` 直接 clap 錯誤。Pingclair 只能
手動 SIGUSR1，而 reload 本身還有 F-14 的套用問題。

#### F-26（P1）`templates` directive 未實作，Tutorial 步驟直接卡住

`pingclair adapt` 與 `run` 對含 `templates` 的 Caddyfile 都明確失敗：
`Caddy-compatible directive 'templates' is not supported by Pingclair
yet`（fail-closed 是好的，但功能不存在，Tutorial 的 Templates 一節無法
進行）。已知 v0.3+ backlog 項，本組實測確認。

#### F-27（P3）`encode` 壓縮回應缺 `Vary: Accept-Encoding`

5KB 檔案 + `Accept-Encoding: gzip`：Pingclair 回 `Content-Encoding:
gzip`，但沒有 Caddy 會送的 `Vary: Accept-Encoding`。下游 HTTP cache
可能把 gzip 版本快取後原樣送給不支援 gzip 的客戶端。

#### F-28（P1）無 matcher 時 `file_server` 與 `reverse_proxy` 優先序相反

```caddy
localhost {
	file_server
	reverse_proxy 127.0.0.1:9005
}
```

Caddy：`reverse_proxy` 優先（`/index.html` 也被 proxy）；Pingclair：
`file_server` 優先（`/index.html` 回檔案）。兩邊都「不是使用者想要的
行為」（Tutorial 明說這 config 不會如預期），但**優先的 handler 相反**，
任何依賴 Caddy directive order 的既有 config 遷移過來都會路由到不同
handler。加上 matcher 後（`reverse_proxy /api/* ...`）兩邊行為一致。

### 本組總結

- 通過：first site、browse（啟動時）、multi-site、matcher token、env vars、
  comments、gzip 本身。
- 卡點：`--watch`（F-25）、`templates`（F-26）、reload 換 handler 不生效
  （F-14 擴充）、缺 `Vary`（F-27）、無 matcher 優先序相反（F-28）。
- 本組未改任何程式碼，只記錄。

## 第九組測試：Command Line（2026-08-02）

以官方 Command Line 文件逐命令對照（先前組別已覆蓋 run/adapt/validate/
file-server/reverse-proxy/start/stop/reload 的主要行為；本組補子命令
盤點、fmt、hash-password、signals、exit codes）。

### 子命令對照

| 分類 | 命令 |
| --- | --- |
| ✅ 兩邊都有 | `adapt`、`file-server`、`fmt`、`hash-password`、`reverse-proxy`、`run`、`validate`、`version` |
| ❌ Pingclair 缺 | `build-info`、`completion`、`environ`、`list-modules`、`manpage`、`reload`、`respond`、`start`、`stop`、`storage`、`trust`、`untrust`、`upgrade`、`add-package`、`remove-package` |
| ➕ Pingclair 額外 | `service`（Linux only：start/stop/restart/reload/status） |

`reload`／`start`／`stop` 已在第一組記錄（F-08）；`run --watch` 在第八組
記錄（F-25）；file-server 的 `--templates`／`--precompressed`／
`--reveal-symlinks` 缺、`--file-limit` 語意不同（F-13/F-17）。

### 補測結果

| 項目 | Caddy | Pingclair | 判定 |
| --- | --- | --- | --- |
| `fmt` | 保留原始引號（`respond "x"`） | 剝掉可選引號（`respond x`）；多字串 `"a b"` 會保留引號，語意不變 | ⚠️ 純風格差異（P3） |
| `fmt -` / `--diff` / `--overwrite` | ✅ | ✅（stdin 支援） | ✅ |
| `hash-password` | 支援 argon2id 參數；預設實測 bcrypt cost 14（`$2a$14$`） | 只有 bcrypt cost 14（`$2b$14$`） | ⚠️ F-29（P3） |
| `adapt --config -`（stdin） | ✅ 輸出 JSON | ❌ 把 `-` 當檔名（IO error） | ❌ F-31（P3） |
| `respond` CLI | ✅ | ❌ 子命令不存在 | ❌ F-30（P2） |
| SIGQUIT | 立即退出，exit code 2（文件相符） | **5 秒後仍在跑**（忽略 SIGQUIT） | ❌ F-32（P2） |
| SIGHUP | ignored（照文件） | reload（照 Pingclair 既有設計） | ⚠️ minor |
| SIGINT/SIGTERM | graceful | graceful（有 handler） | ✅ |
| exit code（無子命令） | 0（印 help） | 2（clap usage error） | ⚠️ minor（第一組已記錄） |

### 新發現

#### F-32（P2）Pingclair 忽略 SIGQUIT

Caddy 文件：SIGQUIT 立即退出並清理 storage lock（exit code 2）。實測
Pingclair 收到 SIGQUIT 後 5 秒仍存活（本組第一次測試還因此卡住
`wait`）。SIGTERM/SIGINT graceful 兩邊都有；SIGHUP 兩邊不同（Caddy
ignored、Pingclair reload）。

#### F-30（P2）沒有 `respond` CLI 子命令

Caddy 的 `caddy respond` 可快速起一個硬編碼 HTTP server（開發/測試/
load balancer 驗證用，支援 `--status`/`--header`/`--body`/`--listen`
與 port range）。Pingclair 無此命令（`unrecognized subcommand`）。

#### F-31（P3）`adapt -c -` 不支援 stdin

Caddy `adapt --config -` 從 stdin 讀設定；Pingclair `adapt -c -` 把
`-` 當成檔名（`IO error: No such file or directory`）。

#### F-29（P3）`hash-password` 只有 bcrypt，無 argon2id

Caddy 支援 `--algorithm argon2id`（含 time/memory/threads/keylen
參數）；Pingclair 只有 bcrypt（help 亦明寫 bcrypt）。實測兩邊預設都是
bcrypt cost 14，輸出 `$2a$14$`（Caddy）與 `$2b$14$`（Pingclair），
格式相容；缺的是 argon2id 選項。

### 整體測試總結（九組全數完成）

- 測試範圍：Getting Started、API Quick-start、Caddyfile Quick-start、
  Static files、Reverse proxy、HTTPS、API Tutorial、Caddyfile Tutorial、
  Command Line。
- 環境：AWS `t4g.micro`（ap-east-1，Ubuntu 26.04 arm64），Pingclair
  commit `70d0fb0`（含 P0 修復），Caddy v2.11.4。
- 已修復：F-01（`/load` 靜默載入空配置 → 400，commit `70d0fb0`）；
  FX-A（本 commit）：F-20（`reverse_proxy :9000` 不再 502）、F-24
  （`/config/<path>` 實作 Caddy traversal，不再把 body 當 ServerConfig）、
  F-31（`adapt -c -`／`validate -` 支援 stdin）；
  FX-B（本 commit）：F-02/F-10（`/load` 動態開新 listener＋整包替換）、
  F-11（`/load` 支援 `text/caddyfile`）、F-03（`GET /config/` 完整匯出）、
  F-04（`/stop` 回 200 後 graceful）、`@id` 與 autosave/`--resume`；
  FX-C（本 commit）：F-14（reload 換 handler/browse 生效）、F-09
  （reload 新 listener 動態開啟＋詳細警告）、F-32（SIGQUIT exit 2、
  SIGHUP ignored、API 變更後 SIGUSR1 失效）；
  FX-D（本 commit）：F-08（`reload`/`start`/`stop` CLI）、F-30
  （`respond` CLI）、F-25（`run --watch`）、F-21（`--from` HTTPS 路徑）、
  F-13（file-server `--domain`/bare port）、F-18/F-19（預設
  `--from localhost`、`--change-host-header`）；
  FX-E（本 commit）：F-22（bare hostname 預設自動 HTTPS，真域名
  `pingclair-test.aqeo.dev` production ACME 簽發成功）、F-28（無 matcher
  時 proxy 勝過 file_server）、F-26（`templates` directive 渲染）、
  F-23（JSON `names` 觸發 eager issuance）。
- 未修 P1 清單：F-02（`/load` 不能開新 listener）、F-07（非 root 無
  TLS store 無法啟動）、F-10（`/load` 累加更新非整包替換）、F-14
  （reload 換 handler/browse 不生效）、F-20（`reverse_proxy :9000`
  502）、F-21（CLI HTTPS `--from` 兩路徑壞）、F-22（bare hostname 無
  預設 HTTPS）、F-26（`templates` 未實作）、F-28（無 matcher 的
  directive 優先序相反）。
- P2 清單：F-03（`/config/` 404 且匯出失真）、F-04（`/stop` 空回應）、
  F-09（reload 新 listener 只給 warning 數）、F-11（`/load` 不吃
  adapter）、F-13（file-server `--domain` 無憑證）、F-24（`POST
  /config/*` 語意陷阱）、F-30（無 `respond` CLI）、F-32（SIGQUIT 被
  忽略）。
- P3/minor：F-05（respond 無 Content-Type）、F-06（IPv4-only listen）、
  F-12（內部 CA 不自動 trust）、F-15（file_server charset/Vary）、
  F-16（預設 port）、F-17（`--file-limit` 語意）、F-18（reverse-proxy
  預設 `--from`）、F-19（缺 `--change-host-header`）、F-25（無
  `--watch`）、F-27（encode 缺 Vary）、F-29/F-31、fmt 引號風格、
  exit code/help 語意。
- 所有組別測試期間僅修過 F-01 與 FX-A 三項；其餘只記錄，未改碼。
