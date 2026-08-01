# Caddyfile 位址與自動 HTTPS 語義需求文檔

> 📌 本文是 v0.2 收斂期間的專項需求文檔：以 Caddy 官方文檔（本機
> `~/code/caddy-website` 的 `caddyfile/concepts.md`、
> `caddyfile/options.md`、`automatic-https.md`）為準，定義 Pingclair
> 對「site 位址 → listener → TLS」這條鏈的期望行為，並列出已確認的
> bug 與同類缺口。本文只定義需求，不取代 `docs/TODO.md`（執行計畫）與
> `docs/STATUS.md`（驗證記錄）。

## 1. Caddy 官方語義（需求基準）

### 1.1 Site 位址是虛擬主機，不是 listener

（`caddyfile/concepts.md` §Addresses）

- 位址帶 hostname 時，**只有 Host header 相符的請求**才會命中該 site；
  `localhost` 不會匹配 `127.0.0.1`，反之亦然。
- site 預設綁定所有介面；要指定介面用 `bind` directive 或
  `default_bind` global option，`bind` **只接受 host，不接受 port**。
- 一個 site block 可以列多個位址，以空格或逗號分隔（逗號前後至少一個
  空白）；同一組設定套用到所有列出的位址。
- 位址不得重複。

### 1.2 預設 scheme／port 推導

（`caddyfile/concepts.md` §Addresses 表格）

| 位址 | Caddy 行為 |
|---|---|
| `example.com` | HTTPS（公開憑證） |
| `*.example.com` | HTTPS（wildcard 公開憑證） |
| `localhost` | HTTPS（本機信任憑證） |
| `127.0.0.1` | HTTPS（IP 本機憑證） |
| `http://`／`https://` | catch-all（不帶 Host matcher） |
| `http://example.com` | 明確明文 HTTP（帶 Host matcher） |
| `example.com:443` | 因 port 等於 `https_port` 而 HTTPS |
| `:443` | HTTPS catch-all |
| `:8080` | 非標準 port 明文 HTTP，無 Host matcher |
| `localhost:8080` | 非標準 port 上仍是 HTTPS（有效網域名） |
| `127.0.0.1:8080` | 同上，HTTPS |

規則摘要：

1. 位址沒有 port 時，依 scheme 推導：`http://` → `http_port`（80）、
   `https://` → `https_port`（443）；**無 scheme 時預設 `https_port`（443）**。
2. 位址帶 hostname 或 IP，且 scheme 不是明確 `http://` 時，自動 HTTPS
   啟用（公開網域走 ACME、localhost／本機 IP 走本機 CA）。
3. 只有明確 `http://` 前綴或 `:80`／`:http_port` 後綴才關掉自動 HTTPS。
4. `auto_https off` **不改變預設 protocol**：hostname site 仍然是
   HTTPS（`caddyfile/options.md` §auto_https），只停掉憑證自動管理與
   HTTP→HTTPS 轉跳。

### 1.3 Automatic HTTPS 是隱式補充，不覆蓋顯式設定

（`automatic-https.md` §Activation／Effects）

- 只要設定裡出現 hostname 或 IP，自動 HTTPS 就隱式啟用；但**永不覆蓋
   顯式設定**，只會額外補上：
  - 為合格網域簽發並續期憑證；
  - 在 HTTP port 上補 HTTP→HTTPS 轉跳（308）與 ACME HTTP-01 應答。
- 停用條件（任一）：`auto_https off`；設定裡完全沒有 hostname/IP；
  **只監聽 HTTP port**；site 位址是 `http://`；手動載入憑證。

## 2. 已知 bug：`tls auto` 沒有自動開 443

### 2.1 現況（2026-07-31 實測）

`pingclair-test.aqeo.dev { tls auto file_server ... }` 啟動後只有
`0.0.0.0:80` 明文監聽；ACME manager 初始化但從未簽發。同 binary 改成
`listen :8443` + `tls auto` 則 8443 TLS/H3 與自動 80 companion 都正常。

### 2.2 根因鏈（三處疊加）

1. **`pingclair-config/src/adapter/caddyfile.rs`**
   - `parse_server_address()`（:562）：純 hostname、無 scheme/port 時
     回傳 `ListenAddr { scheme: Http, host: "0.0.0.0", port: Some(80) }`
     ——port 80 是「無 scheme」時的錯誤預設（Caddy 是 443）。
   - `adapt_server()`（:307）把該值**無條件 push 進 `server.listens`**，
     且沒有記錄「這是 site 位址推導的隱式 listen」。
2. **`pingclair-config/src/compiler.rs`（:201）**：`server.bind` 為
   Some 且 `listen.is_empty()` 時把 bind 地址 push 進 `config.listen`
   ——第二處會把 listen 塞成非空。
3. **`pingclair/src/main.rs`（:917）**：自動 443 分支是
   `if server_config.listen.is_empty()`；因前兩處讓 listen 永遠非空，
   這個分支永遠不成立，TLS site 被當成純明文 80 服務。

### 2.3 期望行為

```caddyfile
example.com {
    tls auto
    file_server ./public
}
```

- 443：TLS（H2/H3，`server_requires_tls` 已把 443 視為 TLS）。
- 80：自動 companion（ACME HTTP-01 + 308 轉跳），沿用
  `automatic_http_companion()` 既有邏輯。
- 無 TLS 的 `example.com { file_server ... }` 仍只開 80，行為不變。

### 2.4 建議修法（供執行時選擇）

- **方案 A（最小改動）**：`adapt_server` 只在 site 位址**帶顯式 port 或
  顯式 scheme** 時 push listen；純 hostname 不 push，讓
  `listen.is_empty()` 為真，交由 main.rs 依 TLS 決定 443 或
  `AUTOMATIC_HTTP_LISTEN`。同時確認 compiler.rs:199 的 bind 預填
  不會把 listen 塞回非空。
- **方案 B**：`ServerConfig` 增加「listens 是否顯式」旗標，main.rs 依
  旗標而非 `is_empty()` 判斷。語意最清楚，改動較大。
- 兩種方案都必須保持：`localhost:8080`、`https://example.com`、
  `http://example.com`、`listen :80`、`:80`／`:443` 裸 port 行為不變。

## 3. 同類 bug（本次審查確認，依嚴重度排序）

> 以下皆以臨時探針直接打 `compile()` 實測確認（探針已刪除，未留下任何
> 工作區改動；驗證日期 2026-08-01，main @ 2026-07-31 狀態）。

### 🔴 B1：顯式 `listen :80` + hostname site 產生重複 listener

```caddyfile
example.com {
    listen :80
    tls auto
}
```

編譯結果：`listens = ["0.0.0.0:80", "0.0.0.0:80"]`。`adapt_server`
把 site 位址的隱式 `:80` 與 block 內顯式 `listen :80` 都收進來，
沒有去重。同一個位址被註冊兩次，至少造成 log 重複與 listener 語意
混淆，Pingora bind 階段可能直接失敗。

**期望**：顯式 `listen :80` 只出現一次；`tls auto` 的 443 由自動路徑
補上（Caddy 行為：8443/443 各自獨立，顯式設定不被隱式推導覆蓋）。

### 🔴 B2：顯式 `listen :8443` + hostname site 被偷偷加上 :80

```caddyfile
example.com {
    listen :8443
    tls auto
}
```

編譯結果：`listens = ["0.0.0.0:80", "0.0.0.0:8443"]`——operator 沒寫
80，卻多了一個明文 80 listener。Caddy 只會開 8443（加上自動 HTTPS
的 80 companion，行為可控）；Pingclair 的隱式 :80 會變成一個**沒有
轉跳、沒有 ACME 路由的裸明文 listener**（`automatic_http_companion`
偵測到「已在服務 80」就不補 companion），HTTP 流量直接到達 site 而
不會被轉到 HTTPS。

### 🔴 B3：多 listener site 的 name 塌成 `_`，vhost 匹配丟失

```caddyfile
example.com {
    listen :80
    listen :443
    tls auto
}
```

`adapt_server()` 在 `listens.len() > 1` 時把 `server.name` 設為 `_`
（:323）。`add_server()`（`pingclair-proxy/src/server.rs`）把 `_` 當成
**catch-all**。結果：這個 site 不再按 Host header 匹配，任何 Host
（含裸 IP）都會命中——違反 Caddy「hostname 位址只接受相符 Host」的
基本語義，也是多站台部署時最容易被忽略的安全／路由錯誤。

**期望**：多 listener 不影響 site name／vhost 匹配；name 只在位址本身
就是裸 port（`:80`、`:8080`）或 catch-all 位址（`http://`、`https://`）
時才為 catch-all。

### 🟠 B4：裸 `:443` 位址沒有預設 TLS

```caddyfile
:443 {
    file_server ./public
}
```

編譯結果：`listens = ["0.0.0.0:443"]`、`tls = None`。main.rs 的
`server_requires_tls` 會把 443/8443 視為 TLS，但 adapter 沒有把
`:443` 的 scheme 推導為 HTTPS；JSON 路徑（Admin API）沒有
`server_requires_tls` 的 port 判斷保護，語意不一致。Caddy 表格明確：
`:443` = HTTPS catch-all。`8443` 在 Pingclair 被視為 TLS 慣例 port
（`server_requires_tls`），但文件與 adapter 都沒說明，JSON 路徑也
不保證。

**期望**：`:443`（與 `https_port`）編譯後即為 TLS；`:8443` 的隱式
TLS 慣例要寫成 core 層規則（adapter 與 JSON 兩條路一致），不能只靠
main.rs 的 listener 層判斷。

### 🟠 B5：`localhost`／IP site 預設跑到明文 :80

```caddyfile
localhost {
    tls auto
}
127.0.0.1 {
    tls auto
}
```

編譯結果：兩者都是 `0.0.0.0:80`／`127.0.0.1:80` 明文。Caddy 對
`localhost` 與 `127.0.0.1` 預設 **HTTPS（本機信任憑證）**，且
`tls internal` 正是 Pingclair 對應的本機 CA 能力。需求應明確：
hostname/IP site 預設 port 一律依「是否 TLS」推導（443 或 80），
`tls auto`／`tls internal` 的 localhost site 應走 443 + 本機 CA。

### 🟡 B6：`auto_https off` 的語義與 Caddy 不同

Caddy：`auto_https off` 只停憑證自動管理與轉跳，**不把 site 從 HTTPS
變 HTTP**。Pingclair：`tls auto` 是簽發憑證的唯一入口，`auto_https off`
時 hostname site 沒有任何途徑得到 HTTPS（adapter 還把預設 port 定成
80）。需求應明確兩者解耦：protocol 推導（443 vs 80）由 site 位址／
TLS 決定，`auto_https` 只管憑證與轉跳。

### 🟡 B7：缺少 `http_port`／`https_port`／`default_bind` global options

Caddy 官方（`caddyfile/options.md`）支援 `http_port`（預設 80）與
`https_port`（預設 443），用於內部網路 port 轉發場景；`default_bind`
設定所有 site 的預設介面。Pingclair 的 global adapter 沒有這三個選項，
port 80/443 全部寫死在 main.rs（`AUTOMATIC_HTTP_LISTEN`、自動 443
字串）。需求：至少把 `http_port`／`https_port` 列入 global config，
讓隱式 443/80 路徑使用可設定的 port；`default_bind` 可列為 v0.3。

### 🟡 B8：site 位址帶 path（`example.com/app`）被當成字面 hostname

`example.com/app { ... }` 編譯為
`name = "example.com/app"`、listener `0.0.0.0:80`、route `/*`。Caddy
允許 site 位址帶 path（作為預設 path matcher）。現況會造成永遠匹配
不到該 host，且把 `/app` 塞進 server name。最低要求：**明確拒絕**
這種位址（fail closed），或實作 path 預設 matcher。

### 🟡 B9：多個 site 位址（`example.com, www.example.com`）產生重複 listener

逗號/空格分隔的多位址 block 是 Caddy 標準寫法；現況把每個 token 當成
獨立 server block，產生兩個 `0.0.0.0:80` 且 name 塌成 `_`。需求：
支援一個 block 多個位址（所有位址共用同一組設定、同一 vhost 群），
或明確拒絕並提示改用多個 block。

## 4. 驗證需求

修復完成後，以下測試必須全綠（沿 AGENTS.md 的驗證層級）：

1. **單元**：`cargo test -p pingclair-config` 補上
   - hostname + `tls auto` → `listen` 空（或旗標化後「無顯式 listen」）；
   - 顯式 `listen :80` 不重複、不帶隱式 site listen；
   - `:443` → TLS 推導；`localhost`/`127.0.0.1` → 443 推導；
   - 多位址 block、多位址 site 的 name 不塌成 `_`；
   - `example.com/app` 拒絕或正確實作；
   - `http_port`/`https_port` 影響隱式 443/80。
2. **真 binary 整合**（`cargo test -p pingclair --test integration`）：
   - `example.com { tls auto file_server ./public }` 啟動後 443（TLS:
     enabled）與 80 companion 同時存在；HTTP→HTTPS 308 正常；
   - 無 TLS 的 hostname site 仍只開 80；
   - 多 listener site 的 Host header 路由仍精確（`example.com` 不回應
     其他 Host）。
3. **文件**：三份 README 的 Automatic HTTPS 段落與本需求文檔一致；
   `docs/STATUS.md` 更新驗證證據。
4. **回歸注意**：`localhost:8080`、`https://example.com`、
   `http://example.com`、`:80`／`:443` 裸 port、`tls internal` 的既有
   測試不得行為改變。

## 5. 明確不做（本文件範圍外）

- `default_bind` global option（建議 v0.3，B7 內已註明）。
- On-Demand TLS、ECH、ACME DNS challenge 等 Caddy 進階自動 HTTPS 功能。
- `handle_path`、`host`/`query` matcher、`header { set ... }` 等
  Caddyfile 語法缺口（屬另一份適配器審查，見對話紀錄；如需併入本
  文檔請明示）。
