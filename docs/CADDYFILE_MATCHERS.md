# Caddyfile Matchers 需求文檔

> 📌 本專項以 Caddy 官方文檔（`caddyfile/matchers`，本機
> `~/code/caddy-website`）為基準，定義 Pingclair 對 **matcher token
> 語法**、**standard matcher 語意**與 **matcher 評估**的期望行為。
> 與位址（`docs/CADDYFILE_ADDRESS_SEMANTICS.md`）、directive
> （`docs/CADDYFILE_DIRECTIVES.md`）兩份文檔構成完整的 Caddyfile
> 相容性需求基準。

## 1. Caddy 官方語義（需求基準）

### 1.1 Matcher token 三種形式

（`caddyfile/matchers` §Syntax）

1. `*` — 匹配所有請求（wildcard，等於省略 matcher token）；
2. `/path` — 以 `/` 開頭的內聯 path matcher；
3. `@name` — 引用 site block 內定義的 named matcher。

### 1.2 Named matcher = matcher set（AND）

- block 形式 `@name { ... }` 內的所有 matcher **AND**；
- 單一 matcher 可寫成單行 `@name <matcher> <args...>`；
- **同型別多個 matcher 依型別定義合併**：path 多值 OR、header
  同欄位多值 OR、method 多值 OR、host 多值 OR、query 同鍵多值 OR；
- 不同欄位的 header（或不同鍵的 query）AND；
- 需要複雜布林時用 `expression`（CEL）。

### 1.3 Standard matcher 語意（本專項範圍）

| Matcher | 關鍵語意 |
|---|---|
`path` | 預設**精確**匹配；`*` 可放在尾（prefix）、頭（suffix）、兩側（substring）、中間（glob）；**case-insensitive**；匹配前先清理 dot segment、合併多個 slash、URI-decode 正規化 |
`header` | 值以 `*` 前綴→suffix match、`*` 後綴→prefix match、兩側 `*`→substring、無 `*`→exact；欄位名前綴 `!`→**欄位必須不存在**；同欄位多值 OR |
`method` | 多值 OR；只接受合法 HTTP verb |
`not` | `not path /a /b` = NOT(path OR 路徑)；`not { m1 m2 }` = NOT(m1 AND m2)；多個 `not` 行 = 各自 AND |
`host` / `query` / `protocol` / `remote_ip` / `client_ip` | 多值 OR；query 需解析 query string，非法 query 不匹配 |

## 2. 現況與已確認 bug

> 以下全部以 `compile()` + runtime `Router::match_request()` 實測
> 確認（2026-08-01，臨時探針已刪除，工作區無改動）。相關程式碼：
> `adapter/caddyfile.rs` `parse_single_matcher_at()`（:2092）、
> `compiler.rs` `compile_matcher()`（:1000 附近）、
> `pingclair-core/src/server/router.rs` `evaluate_matcher_inner()`。

### 🔴 M1：named matcher 的多 path 只有第一條會路由

```caddyfile
example.com {
    @assets path /js/* /css/* /images/*
    handle @assets { respond "asset" }
    handle { respond "other" }
}
```

編譯結果：route path = `/js/*`（`find_path_pattern` 只取
`patterns.first()`）。runtime 實測：

```text
/js/a.js     → @assets 命中
/css/a.css   → fallback（!!）
/images/a.png → fallback（!!）
```

**Caddy 語意**：三個 pattern OR，三條路徑都命中。Pingclair 的 radix
router 以 route path 為第一道過濾，matcher 只在該 path 下評估，所以
第二、第三個 pattern 完全失效。這是 Caddyfile 遷移最常見的寫法之一，
影響極大。

### 🔴 M2：`method` 靜默丟棄不支援的 verb，可變成「永不匹配」

```caddyfile
@h method HEAD
```

`HttpMethod` enum 只有 GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS，但
`parse_single_matcher_at` 的 `filter_map` 只認 GET/POST/PUT/DELETE——
HEAD、OPTIONS、PATCH 被靜默丟棄，`method HEAD` 編譯出**空 methods
集合**，runtime 永不命中（實測 HEAD 與 GET 都落到 fallback）。

**Caddy 語意**：`method HEAD` 匹配 HEAD；未知 verb 是設定錯誤，
應 fail closed。Pingclair 應該：支援全部標準 verb，未知 verb 報錯。

### 🟠 M3：`header` matcher 缺 `!` 與單側 `*` 語意

```caddyfile
@not_foo header !Foo          # Caddy：欄位必須不存在
@p header Foo *.example       # Caddy：suffix match（值以 .example 結尾）
@s header Foo example*        # Caddy：prefix match（值以 example 開頭）
```

現況：

- `header !Foo` → name = `"!Foo"`（字面），condition = Exists——
  找一個叫 `!Foo` 的欄位，永不命中；Caddy 語意是「Foo 不存在」；
- `header Foo *.example` → condition = Equals(`*.example`)——字面
  比較；Caddy 語意是「以 .example 結尾」；
- 只有兩側 `*` 的 Contains 有實作，`*suffix`／`prefix*` 兩種單側
  形式缺。

### 🟠 M4：path matcher 的 wildcard 支援不足

現況 `path_matches()`（`router.rs` :293）只認：

- `pattern/*` → `path.starts_with(prefix)`；
- `pattern*` → `path.starts_with(prefix)`；
- 其他 → 字面相等。

缺：`*.suffix`（suffix match）、`*/contains/*`（substring）、
`/accounts/*/info`（中間 glob——probe 顯示它被當字面 path，
`/accounts/1/info` 永不命中）。Caddy 文檔明列四種 wildcard 位置，
而且 path 匹配是 case-insensitive、要先清理 traversal dots、合併
重複 slash、URI-decode 正規化——Pingclair 全部沒有。

### 🟠 M5：`query`／`host`／`protocol`／`remote_ip`／`client_ip` matcher 無法從 DSL 使用

`parse_single_matcher_at` 只認 `path`、`not`、`method`、`header`，
其餘回 `Unknown directive 'matcher: ...'`。但 `Matcher` 型別
（`core/config/types.rs`）與 `compile_matcher` 都支援 Query／Host／
RemoteIp／Protocol（JSON/Admin 路徑可用）。README 卻宣稱「route by
path, host, headers, and more」——DSL 支援與宣稱不符。

### 🔴 M6：runtime 的 Query matcher 永遠回 true（fail-open）

`router.rs` `evaluate_matcher_inner()`：

```rust
Matcher::Query { .. } => {
    // Query matching would need query string parsing
    true
}
```

任何含 query matcher 的設定（透過 JSON／Admin API 進入）都會匹配
**所有請求**。這是 fail-open 安全缺口：例如「只對 `?admin=1` 開放的
路由」會變成對所有人開放。Caddy 語意：query 須依 key/value（值支援
`*`）與 query string 多值語意評估；非法 query string 不匹配。

### 🟡 M7：`not` 的多值 path 合併語意

實測確認 `not path /css/* /js/*`（inline 形式）編譯為
`Not(Path ["/css/*","/js/*"])`，Path 多值在 runtime 是 OR，所以
語意 = NOT(/css/* OR /js/*)——與 Caddy 一致。**但**：Caddy 對
`not { path /api/*; method POST }` 是 NOT(AND)，Pingclair 的 block
形式也是 AND 後取反，行為一致。此項主要是**補測試**，不是 bug。
真正要小心的是 M1 的 route path 取第一條，會讓 `not path /a /b`
在路由層只註冊 `/a`，`/b` 相關請求直接走 fallback——語意在
matcher 層對，但路由層的 path 過濾把它弄壞。

### 🟡 M8：matcher set 內「同欄位多值 OR」缺

```caddyfile
@foo {
    header Foo bar
    header Foo baz
}
```

Caddy：`Foo: bar` **或** `Foo: baz` 都命中。Pingclair：
`parse_matcher_definition` 把兩行 AND 起來，變成「Foo 同時等於 bar
且 baz」——**永不命中**（runtime 實測三種值全落 fallback）。需要
依型別合併：同欄位 header／同鍵 query／path／method／host 多值 OR，
不同欄位／鍵 AND。

## 3. 驗證需求

修復後以下測試必須全綠：

1. **單元（`cargo test -p pingclair-config` / `-p pingclair-core`）**：
   - `@assets path /js/* /css/* /images/*` 三條路徑都命中
     （route path 需能表示多值，或 matcher 在路由層完整評估）；
   - `method HEAD`／`OPTIONS`／`PATCH` 命中，未知 verb fail closed；
   - `header !Foo`（不存在）、`*.example`（suffix）、`example*`
     （prefix）、`*Upgrade*`（contains）各語意正確；
   - path 四種 wildcard、case-insensitive、dot-segment 清理、
     多 slash 合併、URI-decode 正規化；
   - `not path /a /b` 在路由層與 matcher 層語意一致；
   - query matcher 不再 fail-open（`?q=1` 命中、`?q=2` 不命中、
     無 query 不命中）。
2. **真 binary 整合**：DSL 的 query/host/protocol/remote_ip matcher
   或明確拒絕訊息；Admin API 送 query matcher 後路由行為正確。
3. **文件**：README 三語的 matcher 宣稱與實際支援一致；不支援的
   matcher 明確列出。

## 4. 明確不做（本文件範圍外）

- `expression`（CEL）matcher 完整實作——需要 CEL 執行環境，列 v0.3。
- `file`／`vars`／`vars_regexp`／`header_regexp`／`path_regexp`
  （regex capture placeholder 機制）——列 v0.3。
- `client_ip` 與 `trusted_proxies` 的互動——依賴既有 trusted proxy
  政策，屬 v0.3。
