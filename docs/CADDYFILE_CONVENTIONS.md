# Caddyfile Conventions 需求文檔

> 📌 本專項以 Caddy 官方文檔（`conventions`，本機
> `~/code/caddy-website`）為基準，對照 Pingclair 的位址、duration、
> placeholder 與檔案位置慣例。**慣例是「不必查文件就會這樣寫」的
> 東西，偏離慣例的錯誤最難被發現。**

## 1. 官方慣例 vs Pingclair（2026-08-01 實測）

### 1.1 Network addresses

官方格式：`network/address`（network 可選，預設 tcp）；address 支援
`host`、`host:port`、`:port`、`[ipv6%zone]:port`、`/unix/socket`、
`/unix/socket|0200`；port 支援 range（`:8080-8085`）與 `:0`。

| 寫法 | Caddy | Pingclair 實測 |
|---|---|---|
| `:8080` | ✅ | ✅ |
| `localhost:8080` | ✅ | ✅ |
| `tcp/localhost:8080` | ✅ | ⚠️ 編譯過但 `tcp/` 被當 hostname 的一部分（listen 是 `0.0.0.0:8080`，vhost 名含 `tcp/`） |
| `localhost:8080-8085` | ✅ 展開多 listener | ❌ **listen 變成 `0.0.0.0`（無 port）**——port range parse 失敗變 None，靜默退化 |
| `[fe80::1%eth0]:8080` | ✅ zone 支援 | ❌ zone 被當成 hostname，綁 `0.0.0.0`（B 系列同源） |
| `unix//path/sock` | ✅ Unix socket | ❌ 被當 hostname（首頁文檔 H1） |
| `unix//path/sock\|0200` | ✅ 權限模式 | ❌ 同上，連 `\|0200` 一起當 hostname |
| `:0` | ✅ 任意可用 port | ✅ 編譯過（`0.0.0.0:0`） |

**最危險的是 port range**：`localhost:8080-8085` 編譯成功、listen
變成沒有 port 的 `"0.0.0.0"`——runtime 的 `normalize_listen_addr`
與 SocketAddr parse 會直接失敗或產生完全不同的 listener。

### 1.2 Durations

官方：Go `time.ParseDuration` 語法 + `d`（天），支援
`ns/us/µs/ms/s/m/h/d`、小數（`1.5h`）、組合（`2h45m`）。

Pingclair `parse_duration_ms`（adapter/caddyfile.rs :1884）實測：

| 寫法 | 結果 |
|---|---|
| `250ms` | ✅ |
| `5s` | ✅ |
| `90d` | ❌ `Invalid argument` |
| `1.5h` | ❌ `Invalid argument` |
| `2h45m` | ❌ `Invalid argument` |
| `500us` | ❌ `Invalid argument` |
| 裸數字（如 `30`） | ⚠️ 當 **milliseconds**（Caddy 不接受裸數字；`dns_refresh 30` 會變成 30ms 的 DNS 查詢風暴——code 註解自己承認這個陷阱） |

`d` 與組合單位是 production Caddyfile 最常用的寫法（`90d`、
`30m`），`1.5h` 類的小數也常見。需求：實作完整
`ns/us/ms/s/m/h/d`（含小數與組合）解析，裸數字改為拒絕或明確
單位制。

### 1.3 Placeholders

官方：全域 placeholder（`{env.*}`、`{file.*}`、`{system.*}`、
`{time.now.*}`）＋HTTP context placeholder（`{http.request.*}`、
縮寫 `{host}`、`{uri}`、`{path}` 等），不支援時應明確。

Pingclair `resolve_single_placeholder`（proxy/server.rs）只有
`{host}`、`{http.request.host}`、`{remote_ip}`、`{method}`、
`{uri}`、`{path}`、`{http.request.header.*}`。實測：

- `{env.HOME}`、`{system.hostname}` 編譯過（有引號時），runtime
  解析成**空字串**並 debug log「Unresolved Caddy placeholder」；
- patterns 文檔 P6 已記錄 `{labels.*}` 同樣變空字串。

**需求**：未支援的 placeholder 應在編譯期警告或拒絕，不能靜默變
空字串——`redir "https://{env.HOME}/x"` 會變成 `https:///x`。

### 1.4 File locations

官方：data directory 依 OS 慣例（Linux `$HOME/.local/share/caddy`、
macOS `~/Library/Application Support/Caddy`，`XDG_DATA_HOME` 可
覆寫）；config directory（`--resume` 用）依 `XDG_CONFIG_HOME`。

Pingclair：TLS store 預設 `/var/lib/pingclair/certs`
（`PINGCLAIR_TLS_STORE` 可覆寫）。`cert_store.rs` 註解寫的是
「`~/.local/share/pingclair/certs`」，實際 main.rs 預設是
`/var/lib/pingclair/certs`——**文件與實作不一致**。另外：

- `/var/lib` 是 systemd daemon 慣例，可以接受（production 合理），
  但 README 要寫清楚；
- 沒有 XDG 慣例支援、沒有 config directory（admin 文檔 A5 的
  persistence 缺失的同一根因）；
- 沒有「data directory 不可視為 cache」的守則文檔（README 應提醒
  刪掉 certs 目錄 = 失去所有憑證與 ACME 帳戶）。

## 2. 已確認問題（依影響排序）

### 🔴 V1：port range 靜默退化（`localhost:8080-8085` → 無 port listen）

`parse_server_address` 的 port parse `rest[colon+1..].parse::<u16>()`
對 `8080-8085` 回 `None`，但 `Some(ParsedAddress)` 照樣回傳——listen
變成 `"0.0.0.0"`。Caddy 會把 range 展開成 6 個 listener。最低需求：
不支援 range 就要**明確拒絕**，不能產出無 port 的 listen。

### 🔴 V2：`tcp/` network 前綴被吞

`tcp/localhost:8080` 是官方慣例的標準寫法。Pingclair 把它當成
hostname `tcp/localhost`（vhost 名與 listen 都錯）。至少應辨識
`tcp/`、`tcp4/`、`tcp6/` 前綴並剝離，或明確拒絕。

### 🟠 V3：duration 語法不足（缺 `d`、小數、組合）

見 1.2 表格。`90d`、`1.5h` 這類最常見的 production 寫法全部被拒，
裸數字還有一個「當成 ms」的靜默陷阱。

### 🟠 V4：未支援 placeholder 靜默變空字串

見 1.3。與 patterns 文檔 P6 同源，這裡補上全域 placeholder
（`{env.*}`／`{system.*}`／`{time.now.*}`）的缺失。

### 🟡 V5：TLS store 路徑文件與實作不一致

`cert_store.rs` 註解聲稱 `~/.local/share/pingclair/certs`，
`main.rs` 預設 `/var/lib/pingclair/certs`。擇一並寫進 README；
順便補上「目錄內容不可刪（憑證+ACME 帳戶）」的警示。

## 3. 驗證需求

1. `localhost:8080-8085` 編譯失敗（明確錯誤）或正確展開；
2. `tcp/localhost:8080` 等價於 `localhost:8080`；
3. duration：`90d`、`1.5h`、`2h45m`、`500us` 全部正確解析；
   裸數字被拒；
4. `redir "https://{env.HOME}/x"` 對未支援 placeholder 在編譯期
   警告/拒絕（不靜默變 `https:///x`）；
5. README 記錄 TLS store 位置與持久性要求。

## 4. 明確不做（本文件範圍外）

- 完整 placeholder 生態（`{file.*}` 讀檔等）——列 v0.3。
- XDG data/config directory 支援——列 v0.3（先寫清楚現行路徑）。
- Unix socket 的 `|0200` 權限模式——隨首頁文檔 H1（unix upstream）
  一起實作。
