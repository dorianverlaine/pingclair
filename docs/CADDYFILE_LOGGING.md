# Logging 需求文檔（對照 Caddy How Logging Works）

> 📌 本專項以 Caddy 官方文檔（`docs/logging`，本機
> `~/code/caddy-website`）為基準，對照 Pingclair 的
> `pingclair-proxy/src/access_log.rs` 與
> `adapter/caddyfile.rs` `adapt_log_block()`。

## 1. Caddy 官方語義（需求基準）

- **Structured logs**：訊息是 strongly-typed key/value，到編碼前
  不轉字串；可以編成 JSON 或任何 encoder；zero-allocation；
- **多 log 管道**：每條訊息從 logger 發出 → 依 include/exclude
  決定進哪個 log → sampling → encoder → writer；
- 每個 log 有：encoder、writer、**level**、**sampling ratio**、
  **include/exclude logger 清單**；
- 永遠有 `default` log；global `log` option 可設定多個具名 log；
- 官方 access log 範例欄位包含：request（remote_ip/remote_port/
  client_ip/proto/method/host/uri/**headers**/**tls**）、bytes_read、
  duration、size、status、resp_headers 等。

## 2. Pingclair 現況

`pingclair-proxy/src/access_log.rs`（Day 2 交付）：

- ✅ per-server `log` block 驅動：output（stdout/stderr/file）、
  format（text/json）、`format filter { fields { x delete } }`
  exclude；
- ✅ 同路徑多 server 共用 handle＋lock、append 不截斷；
- ✅ 欄位：request_id、method、host、path、status、bytes、
  duration_ms、ttfb_ms、client_ip（trusted-proxy 解析）、route、
  upstream、protocol、user_agent、referer、error；
- ⚠️ 同步寫入（code 註解明說：磁碟卡住會擋 request path；
  rotation/retention/壓縮/bounded async writer 列 Day 22）。

## 3. 已確認問題（依影響排序）

### 🔴 L1：`log` block 的未知子指令靜默吞掉

`adapt_log_block()`（adapter/caddyfile.rs :701）結尾 `_ => {}`——
實測過的模式（global 文檔 G 系列、directives 文檔 D6 同一根因）。
後果：

```caddy
log {
    output stdout
    format jsno        # typo
}
```

編譯成功，`jsno` 被忽略、format 回退 text。`output stdoutd`、
`output file`（少路徑參數）同樣靜默。**log 設定是維運工具，靜默
吞 typo = 出事時看不到該看的 log**。需求：未知子指令、未知參數
一律報錯。

### 🟠 L2：`level` 支援缺失（`LoggingConfig.level` 是死欄位）

Caddy 的 global `log` 與 per-log 都支援 `level`（DEBUG/INFO/WARN/
ERROR）。Pingclair：

- `parser/ast.rs` 有 `LoggingConfig { level, format }` 與 `LogLevel`
  enum，但 `adapt_log_block` 不認 `level` directive；
- `GlobalBlock.logging` 從來沒有被 adapter 填入，compiler 也沒有
  讀它——**整組 global logging 型別是死代碼**；
- 沒有「per-server access log level」概念（要過濾 debug 級別
  access 行做不到）。

### 🟠 L3：global `log` option 不支援

Caddy 文件把 global log 設定列為核心（`{ log default { output ...
format ... level ... include ... exclude ... } }`）。Pingclair 的
`adapt_global` 對 `log` 回 `Unknown directive 'global: log'`
（global options 文檔 G8 已列）。runtime 只有 process-wide tracing
subscriber（RUST_LOG 控制）＋ per-server access log，兩者之間沒有
Caddy 的「多 log 管道」層。

### 🟡 L4：access log 欄位沒有 request/response headers 與 TLS 資訊

Caddy 範例含 `request.headers`、`request.tls`（version/cipher/
resumed/server_name）、`resp_headers`。Pingclair 的 `AccessEntry`
只有基本欄位（見 §2），沒有 headers、TLS 協商資訊、request body
bytes。對除錯 TLS 或調查 header 相關問題，Pingclair 的 log 不夠。

### 🟡 L5：沒有 sampling 與 logger include/exclude

Caddy：`sampling` 降低熱路徑 log 量、`include`/`exclude` 依 logger
名分流。Pingclair 只有 field-level exclude（`fields { x delete }`），
沒有 log-level include/exclude 與 sampling。

### 🟡 L6：寫入是同步且無 rotation（已知、已排期）

`access_log.rs` 註解自承：同步寫入，磁碟 stall 會擋 request path；
rotation/retention/壓縮/bounded async writer 列 Day 22（TODO）。
這與 Caddy 的 writer 模組生態（file/network socket/…）也有差距，
但至少已誠實記錄。本項只是確認排期未變。

## 4. 驗證需求

1. `log { format jsno }` 編譯失敗（錯誤訊息指出未知 format）；
   `log { output file }`（缺路徑）編譯失敗；
2. `log { level debug }` 編譯成功並真的控制 access log 級別
   （或明確拒絕並提示不支援）；
3. global `log default { ... }` 至少編譯期明確拒絕；
4. JSON access log 的 field 可被 `fields { X delete }` 排除
   （已有測試，保留）；新增 fields 時同步更新測試。

## 5. 明確不做（本文件範圍外）

- rotation/retention/壓縮/async writer——Day 22 既定範圍。
- encoder 模組生態（console/CLF/network 等）——列 v0.3。
- sampling——列 v0.3。
