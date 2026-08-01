# Admin API 需求文檔（對照 Caddy API Tutorial）

> 📌 本專項以 Caddy 官方文檔（`api`、`api-tutorial`，本機
> `~/code/caddy-website`）為基準，對照 Pingclair 的
> `pingclair-api` crate 與 `main.rs` 的 reload 路徑。

## 1. Caddy 官方語義（需求基準）

API Tutorial 示範的四個能力：

1. **`POST /load`**：上傳完整 JSON config，整包替換 active config；
2. **`GET /config/`**：讀回 active config；
3. **Path traversal**：`GET/POST /config/<json path>` 只改 config
   的某個節點（例如 `/config/apps/http/servers/example/routes/0/handle/0/body`），
   不碰其他部分；
4. **`@id`**：任何 JSON 物件可標 `"@id": "msg"`，之後用
   `/id/msg` 直接存取。

外加官方 `api` 文檔的重點：

- Admin endpoint **預設 `localhost:2019`**（`CADDY_ADMIN` env 可覆寫）；
- 每次 API 變更會 **persist** config，重啟可用 `--resume` 恢復；
- `admin off` 時 config 無法熱變更；
- `origins`／`enforce_origin` 保護 endpoint（見 global options 文檔 G2）；
- 支援 `GET/POST/PUT/PATCH/DELETE` 與 config 節點的 CRUD。

## 2. Pingclair 現況

`pingclair-api/src/server.rs` 只有五個端點：

| 方法與路徑 | 行為 |
|---|---|
| `GET /health` | 健康檢查 |
| `GET /metrics` | Prometheus metrics |
| `GET /config` | 依 listener 位址 dump 目前 host 狀態（runtime 快照，不是 config 文件） |
| `POST /config` | 上傳**單一 ServerConfig**，hot-reload 進既有 listener |
| 其他 | 404 |

補充：

- **admin 預設關閉**：`config.admin` 為 None 時 main.rs 不啟動
  admin server（Caddy 預設開 `localhost:2019`）；
- 認證是自訂的 `api_key`（Bearer token）擴充，沒有 Caddy 的
  `origins`／`enforce_origin` 機制；
- 沒有 config persistence／resume：重啟後回到啟動時的設定檔，
  API 做的變更全部消失；
- SIGHUP reload 只更新既有 listener 的 server 設定。

### 官方完整 API 端點對照（`api` 文檔）

| Caddy 端點 | 語義 | Pingclair |
|---|---|---|
| `POST /load` | 整包替換 config；支援 Content-Type adapter（Caddyfile/JSON5） | ❌ 無 |
| `POST /stop` | 優雅停機並退出 | ❌ 無（只能靠 signal） |
| `GET /config/[path]` | 匯出指定路徑 config | ⚠️ 只有 `GET /config`，輸出是 runtime 快照非 config 文件 |
| `POST /config/[path]` | 物件建立/取代；**陣列 append**；`/...` 展開多元素 | ❌ 無 path 語意（現有 POST 是別的東西） |
| `PUT /config/[path]` | 物件嚴格新建；陣列 index 插入 | ❌ |
| `PATCH /config/[path]` | 取代既有值/陣列元素 | ❌ |
| `DELETE /config/[path]` | 刪除目標值 | ❌ |
| `/id/<name>` | 用 `@id` 直接存取 | ❌ |
| Etag／If-Match | 樂觀並行控制（412 Precondition Failed） | ❌ |
| `POST /adapt` | Caddyfile→JSON 只轉不載入 | ❌（Pingclair 沒有「adapt 但不執行」的 API） |
| `GET /pki/ca/<id>` | 本機 CA 資訊 | ❌ |
| `GET /pki/ca/<id>/certificates` | CA 憑證鏈 | ❌ |
| `GET /reverse_proxy/upstreams` | upstream 狀態（requests/fails） | ❌（runtime 有 `BackendHealth` 但無 API 暴露） |

**`POST /config` 的語意完全不同**：Caddy 的 `POST /config/<path>` 是
config tree 的 append/upsert；Pingclair 的 `POST /config` 是「上傳單一
ServerConfig 熱載入既有 listener」。同一個路徑、兩種語意，自動化腳本
若按 Caddy 習慣寫會得到完全不同的行為。

## 3. 已確認缺口（依影響排序）

### 🔴 A1：SIGHUP reload 靜默丟棄 global 設定

`main.rs` 的 SIGHUP 路徑（:1224 附近）把 `new_config.servers` 依
listener 分組後 `proxy.update_config(servers)`——**`global` 欄位
（email、auto_https、trusted_proxies、blocked_ips、dns_refresh、
http3、worker_threads）完全沒有被套用**。log 只報「Updated
configuration for <addr>」，global 變更無聲無息消失。例如把
`auto_https off` 加進設定檔再 SIGHUP，ACME manager 照舊跑。

**最低需求**：reload 時偵測 global 差異並明確警告「需要重啟」，
或真正套用（TLS manager 等已持引用，套用成本高，先警告也可）。

### 🔴 A2：`POST /config` 不是 Caddy 的 `/load`

現況只接受**單一 ServerConfig**，不接受完整 `PingclairConfig`
document；且只能更新「已存在 listener」的 server，不能新增 listener、
不能改 global、不能換 TLS manager 設定。官方 tutorial 的「先跑空
daemon → POST config」流程（`caddy run` 預設空 config、`/load` 上
傳）在 Pingclair 完全不可行——Pingclair 必須先有設定檔才能啟動。

### 🟠 A3：沒有 path traversal（`/config/<json path>`）

Tutorial 的核心演示是「只改 `.../routes/0/handle/0/body`，其他不動」。
Pingclair 只有整包 GET 與整包 POST。Caddy 的 traversal 同時支援
GET/POST/PUT/PATCH/DELETE 與陣列索引、物件鍵、`@id`。這是「限制
變更範圍、避免誤改其他設定」的生產安全特性，Pingclair 完全沒有。

### 🟠 A4：沒有 `@id` 支援

`"@id"` 不是 Pingclair JSON config schema 的一部分
（`PingclairConfig` 沒有這個欄位），`/id/msg` 路由不存在。

### 🟡 A5：沒有 config persistence／resume

API 變更不落盤，重啟即失。Caddy 的 `--resume` 讓「API 改完、重啟
不丟」成為可能；Pingclair 現況下 API 只適合臨時調整。

### 🟡 A6：admin 預設關閉 + 缺少 origins 保護

Caddy 預設開 `localhost:2019`（loopback，安全）；Pingclair 要
`admin <addr>` 才開。預設關閉本身保守、可接受，但要寫進 README；
更關鍵的是 G2（global options 文檔）已記錄：`admin` block 的
`origins`／`enforce_origin` 被靜默丟棄——一旦使用者把 admin 綁到
非 loopback（`admin :2020`），沒有任何 Host/Origin 驗證。

### 🟡 A7：`GET /config` 的輸出不是 config 文件

現況輸出依 listener 位址分組的 runtime 快照
（`{"0.0.0.0:80": [ ...ServerConfig ]}`），不是啟動設定的完整
document，也缺 `global`／`admin` 等。Caddy 的 `GET /config/` 回傳
可重新 POST 回去的 config 文件。差異會誤導自動化腳本。

### 🟡 A8：`POST /load`（整包替換）不存在

`pingclair-config` 的 JSON adapter 明明支援完整 `PingclairConfig`
document（`JsonAdapter::parse`、`compile_file` 也收 .json），但 admin
API 沒有對應端點——要換整個 config 只能改檔＋SIGHUP（且 A1 已記錄
SIGHUP 丟 global）。Caddy 的 `POST /load` 有「失敗自動 rollback、
相同 config 不 reload（`Cache-Control: must-revalidate` 強制）」的
語意，Pingclair 完全沒有。

### 🟡 A9：`POST /adapt` 缺失（Pingclairfile→JSON 檢查無 API）

Caddy 用 `/adapt` 做「轉換但不上線」的驗證。Pingclair 的
`pingclair_config::compile()` 已有 DSL→core 的能力，但沒有暴露成
endpoint。需求：`POST /adapt`（Content-Type 標格式）回傳
`PingclairConfig` JSON，方便 CI/腳本在載入前檢查。

### 🟡 A10：upstream 健康狀態沒有 API

`load_balancer.rs` 有 `BackendHealth`（passive fail 標記、cooldown、
DNS refresh 保留），但只有 runtime 內部使用。Caddy 的
`GET /reverse_proxy/upstreams` 回傳每個 upstream 的
`address/num_requests/fails`。需求：至少把 `BackendHealth` 的快照
（address、fails、cooldown 剩餘）暴露成唯讀端點。

### 🟡 A11：沒有 Etag／If-Match 樂觀並行控制

Caddy 對所有 `GET /config/...` 回 Etag（path + content hash），
mutative request 可帶 `If-Match`，衝突回 412。Pingclair 的
`POST /config` 用 `RwLock` 保護單一請求，但「先 GET 再 POST」的
多請求流程沒有版本檢查，兩個管理員同時改會互相覆蓋。

## 4. 驗證需求

1. **單元**：`GET /config/`（含尾斜線）不再 404；`POST /config` 接受
   完整 document 或明確 400 並說明；
2. **真 binary 整合**（`pingclair/tests/integration.rs` 或獨立 shell）：
   - SIGHUP 改 global（如 `auto_https off`）後 log 有明確警告；
   - admin 開在非 loopback 時，無 `origins` 設定的設定被拒
     （沿用 G2 的 fail-closed）；
   - `POST /config` 新 listener 位址返回明確錯誤（現況已 404，
     但要確保 message 說明「新增 listener 需要重啟」）；
   - （v0.3 若實作 `/load`）失敗 rollback 測試：送一個 runtime 無法
     套用的 config，舊 config 必須原樣保留；
3. **文件**：README 三語的 admin 章節不要宣稱與 Caddy API 相容；
   `docs/STATUS.md` 記錄 A1–A7 狀態。

## 5. 明確不做（本文件範圍外）

- `@id` 與 path traversal 的完整實作——列 v0.3（需要把 config
  節點做成可尋址的 tree，與 hot reload 一起設計）。
- `--resume` 對應的 CLI 旗標——列 v0.3（persist 格式先定）。
- `/pki/ca` 端點——列 v0.3（依賴 `tls internal` CA 的狀態暴露）。
- Caddy 完整 `/load` 的 config-adapter 生態（Pingclair 只收 JSON，
  可接受）。
