# Caddyfile Global Options 需求文檔

> 📌 本專項以 Caddy 官方文檔（`caddyfile/options`，本機
> `~/code/caddy-website`）為基準，定義 Pingclair 對 **global options
> block** 的期望行為。與位址、directives、matchers 三份文檔互補。

## 1. Caddy 官方語義（需求基準）

- Global options block 是檔首 `{ ... }`，**只能有一個、必須是第一個
  block**；block 內只能放 global option，不能放 site directive。
- 以下是 Caddy 標準 global options（本專項範圍內列重點）：

| 選項 | Caddy 語義 |
|---|---|
`debug` | 設預設 logger 為 DEBUG；無參數 |
`http_port` / `https_port` | HTTP/HTTPS port（內部轉發用）；預設 80/443 |
`default_bind` | 所有 site 的預設 bind 介面（`bind` directive 可覆寫） |
`order` | 調整 directive 排序（`first`/`last`/`before`/`after`） |
`admin off\|<addr>` | 關閉或設定 admin API；`{ origins ...; enforce_origin }` 限制來源 |
`grace_period` / `shutdown_delay` | 關機寬限與延遲 |
`auto_https off\|disable_redirects\|ignore_loaded_certs\|disable_certs` | 五種模式 |
`email` / `local_certs` / `acme_ca` / `acme_ca_root` / `acme_eab` / `acme_dns` | TLS/ACME 設定 |
`default_sni` / `fallback_sni` / `key_type` / `cert_issuer` | TLS 細項 |
`servers [<addr>] { ... }` | **per-listener** server 選項（timeouts、protocols、trusted_proxies、max_header_size、0rtt、strict_sni_host 等） |
`storage` / `storage_clean_interval` / `persist_config` | 儲存 |
`log` / `metrics` / `pki` / `events` / `filesystem` | 進階 |

## 2. 現況與已確認 bug

> 全部以 `compile()` 實測（2026-08-01，臨時探針已刪除，工作區無
> 改動）。相關程式碼：`adapter/caddyfile.rs` `adapt_global()`（:141）、
> `compiler.rs` `compile_global()`（:54）、
> `core/config/types.rs` `GlobalConfig`（:37）。

### 🔴 G1：`servers` block 內設定被靜默丟棄（含 per-listener 語意丟失）

```caddyfile
{
    servers :8080 {
        protocols h1 h2
    }
}
```

現況：`expand_servers_block()` 把 `servers` 的**子 directive 直接提升
到 global 層**，同時丟掉 `:8080` 位址參數。後果：

1. `servers :8080 { ... }` 的 per-listener 語意消失——Caddy 只對
   `:8080` listener 生效的選項，Pingclair 變成（假設有實作的話）
   全域；
2. `protocols h1 h2` 被 `adapt_global` 解析進 `GlobalBlock.protocols`，
   但 `compile_global()` **從未把它寫入 `GlobalConfig`**——`protocols`
   在 runtime 沒有任何欄位承接（只有 `global.http3` 開關）。使用者寫
   `protocols h1 h2` 想關 H3，結果 H3 照常開啟，設定靜默消失；
3. semantic analyzer 卻會對 `protocols` 做組合驗證（`semantic.rs` :281），
   驗證一個不會生效的欄位——假驗證。

**期望**：`servers [<addr>]` 的位址參數要保留（或明確拒絕）；`protocols`
要真的影響 runtime（至少 h1/h2/h3 開關），否則編譯期 fail closed。

### 🔴 G2：`admin` block 子選項（origins／enforce_origin）被靜默丟棄

```caddyfile
{
    admin :2019 {
        origins http://localhost:2019
        enforce_origin
    }
}
```

現況：`adapt_global` 只讀 `sub.args.first()`，block 整個被忽略——
編譯成功、admin listener 照開，但 **origins 限制不存在**。Caddy 的
語意是：非 loopback 或啟用 `enforce_origin` 時，驗證 `Origin`／`Host`
header，防止 CSRF／跨站控制 admin API。Pingclair 靜默丟掉限制 =
admin API 比使用者以為的更開放。這是安全相關的 fail-open。

**期望**：支援 `origins`／`enforce_origin`，或對 block 形式 fail
closed（明確報「暫不支援 admin block」）。

### 🟠 G3：`trusted_proxies` 不接受 Caddy 語法（`static`／`private_ranges`）

```caddyfile
{
    trusted_proxies static 12.34.56.0/24
}
{
    trusted_proxies private_ranges
}
```

Caddy 語法：`trusted_proxies static [private_ranges] <ranges...>`，
`private_ranges` 是內建快捷（等同六段私有網段）。Pingclair 逐個
argument 當 IP/CIDR 驗證，`static` 與 `private_ranges` 都報
`invalid IP or CIDR`。野生 Caddyfile 遷移會直接失敗；但至少是
fail-closed（錯誤訊息可再加提示）。

### 🟠 G4：`debug` 接受任意參數且靜默吞掉 typo

```caddyfile
{
    debug fales   # 打錯字
}
```

現況：`debug fales` 編譯成功、`debug=false`——一個打錯的選項把 debug
「關掉」，與 `encode gzipp`／`listen ... proxy_protocol` 是同一類
靜默吞 typo。Caddy 的 `debug` 是無參數 flag。`debug false` 這種
「支援但非 Caddy」的寫法也應刪掉（要關就省略）。

### 🟠 G5：`auto_https` 缺兩個 Caddy 模式、無參數時靜默

- Caddy：`off`、`disable_redirects`、`ignore_loaded_certs`、
  `disable_certs`（＋預設 on）。Pingclair 只認 `on`／`off`／
  `disable_redirects`，`disable_certs`／`ignore_loaded_certs` 直接
  報錯（fail-closed，可接受，但語意上 `disable_certs` 是常見需求）。
- `auto_https`（無參數）編譯成功且等於沒寫（預設 On）——應報
  參數缺失。
- 加上位址文檔 B6：Caddy 的 `auto_https off` 不改變預設 protocol，
  Pingclair 的模型沒有這個分離，兩份文檔要一起修。

### 🟡 G6：缺 `http_port`／`https_port`／`default_bind`（與位址文檔 B7 同源）

`GlobalConfig` 沒有這三個欄位；`adapt_global` 對它們報
`Unknown directive 'global: ...'`。這三個是 Caddy 位址推導的核心：
沒有 `https_port`，`example.com` → 443 的推導就寫死；沒有
`http_port`，自動 80 companion 就寫死。修位址 bug 時必須一起加
（至少 `http_port`／`https_port`），否則「隱式 443/80」永遠是
魔法數字。

### 🟡 G7：global block 位置檢查缺失

```caddyfile
example.com { respond "x" }
{
    debug
}
```

Caddy：global options block 必須是**第一個** block。Pingclair：
實測編譯成功、`debug=true`。`adapt()` 只檢查「是否重複」，不檢查
位置；檔首之後的 `{ ... }` 應該報錯（或至少警告），否則 global
語意依賴解析順序。

### 🟡 G8：不支援的 Caddy global options 缺少提示

以下選項在 Caddy 是標準語法，Pingclair 全部
`Unknown directive 'global: ...'`：`http_port`、`https_port`、
`default_bind`、`order`、`grace_period`、`shutdown_delay`、
`storage`、`storage_clean_interval`、`persist_config`、`log`、
`metrics`、`local_certs`、`acme_ca`、`acme_ca_root`、`acme_eab`、
`acme_dns`、`default_sni`、`fallback_sni`、`key_type`、`cert_issuer`、
`pki`、`events`、`filesystem`。

最低要求：錯誤訊息能區分「Pingclair 不支援的 Caddy 選項」與「一般
typo」，例如
`Unknown directive 'global: http_port'（Caddy 相容選項，Pingclair 尚未支援）`。
`acme_ca`（staging 切換）與 `local_certs` 對 TLS 開發流程最常用，
建議優先支援。

### 🟡 G9：`servers` 內層的 `timeouts` 等子選項全部不支援

Caddy `servers { timeouts { ... } }` 是 per-listener 的 slowloris
防護與資源上限。Pingclair 的 per-server `limits` block 有
`header_timeout`／`body_timeout` 等對應能力，但語法完全不同。至少在
錯誤訊息指出對應的 Pingclair 語法（`limits { header_timeout ... }`），
方便遷移。

## 3. 驗證需求

修復後以下測試必須全綠：

1. **單元（`cargo test -p pingclair-config`）**：
   - `servers :8080 { ... }` 位址參數不丟失（或明確報錯）；
   - `protocols` 真正寫入 runtime config 或 fail closed；
   - `admin <addr> { origins ... }` 不靜默丟 block；
   - `debug` 只接受無參數；`auto_https` 無參數報錯；
   - `trusted_proxies static/private_ranges` 語法；
   - global block 不在檔首時報錯；
   - 不支援的 Caddy option 錯誤訊息含提示。
2. **真 binary 整合**：`{ servers :8080 { protocols h1 } }` 後 8080
   真的只有 H1（或設定被拒）；`admin` block 的 origins 生效。
3. **文件**：三份 README 的 global options 表格與實際支援一致。

## 4. 明確不做（本文件範圍外）

- `storage`／`pki`／`events`／`filesystem`／`metrics` 等模組化選項
  完整實作——列 v0.3+。
- `grace_period`／`shutdown_delay` 的 shutdown 協調——與現有
  ShutdownCoordinator 設計一起排期。
- `order` global option——與 directives 文檔 D1 的排序機制一起實作
  （先固定預設順序，`order` 覆寫再補）。
