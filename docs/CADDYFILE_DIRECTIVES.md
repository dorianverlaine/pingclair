# Caddyfile Directives 需求文檔（排序與語法對照）

> 📌 本專項以 Caddy 官方文檔（`caddyfile/directives`、
> `caddyfile/concepts.md` §Directives、本機 `~/code/caddy-website`）為
> 基準，定義 Pingclair 對 **directive 排序**、**matcher 語法**與
> **directive 覆蓋度**的期望行為。與位址/自動 HTTPS 專項（
> `docs/CADDYFILE_ADDRESS_SEMANTICS.md`）互補，兩份合起來構成
> Caddyfile 相容性的需求基準。

## 1. Caddy 官方語義（需求基準）

### 1.1 Directive 有固定預設順序

（`caddyfile/directives` §Directive order）

Caddy 把 HTTP handler directive 排序進一條固定 chain，**寫入順序不影響
執行順序**（`route` block 除外）。預設順序（節錄，由先到後）：

```text
tracing / map / vars / fs / root / log_*
header
redir
method / rewrite / uri / try_files
basic_auth / forward_auth / request_header / encode / push / intercept / templates
invoke / handle / handle_path / route
abort / error / respond / metrics / reverse_proxy / php_fastcgi / file_server / acme_server
```

意涵：

- `header` 一定在 `respond`／`file_server` 之前執行，所以
  「先 respond 再 header」與「先 header 再 respond」行為相同；
- `basic_auth`／`rewrite` 這類 middleware 一定在 terminal handler
  之前執行；
- 用 `order` global option 或 `route` block 才能覆寫。

### 1.2 同名 directive 依 matcher 排序

（`caddyfile/directives` §Sorting algorithm）

- 單一 path matcher 優先，path 依 specificity 排序：
  `/foobar` > `/foo` > `/foo*`（`/foo` 比 `/foo*` 精確）、
  `/foo/*` > `/foo*`；
- 其他 matcher（named、多值 path）依寫入順序；
- 無 matcher（匹配所有）排最後；
- `vars` 的排序相反（最精確的後執行）；
- `route` block 內**保留字面順序**，不套用以上規則。

### 1.3 `handle` 互斥、`route` 不互斥

（`caddyfile/directives/handle.md`、`route.md`）

- `handle`：同一層的多個 `handle` **互斥**——只執行第一個匹配的 block；
  無 matcher 的 `handle` 是 fallback；`handle` 之間依 matcher
  specificity 排序。
- `route`：不互斥、保留字面順序，可以包 middleware 與 terminal
  handler；**directive 可以在 route block 內帶 matcher token**
  （如 `route { @p path /x/*; header @p X-A b; ... }`）。

## 2. 現況：Pingclair 沒有 directive 排序

`adapt_server()`（`pingclair-config/src/adapter/caddyfile.rs`）對 site
block 內的 directive 只做兩件事：

1. 有 matcher → `add_route()`（照寫入順序 push 進 `server.routes`）；
2. 無 matcher → `default_handlers`，最後**統一追加**成一條 `/*` fallback
   route；若已有 matcher route 且其 handler 非 terminal，再嘗試
   `compose_with_default_handlers()` 插入。

**沒有** Caddy 的「directive 種類固定順序」與「同名 matcher
specificity 排序」。以下探針結果全部以 `compile()` 實測（2026-08-01，
臨時探針已刪除，工作區無改動）。

## 3. 已確認的 bug（依影響排序）

### 🔴 D1：middleware 與 terminal handler 的順序由「寫入順序」決定

```caddyfile
example.com {
    respond "ok"
    header X-A b
}
```

編譯結果：`Pipeline { Respond, Headers }`——`header` 在 `respond`
之後執行，而 `respond` 已寫出 response，**header 永不生效**。Caddy
的預設順序把 `header` 排在 `respond` 之前，兩種寫法行為一致。

同理：

```caddyfile
example.com {
    basic_auth user pass
    respond "ok"
    header X-A b
}
```

`basic_auth` 正確在 `respond` 前（這一段湊巧對），但 `header` 又變成
死碼。需求：**至少對已支援的 Caddy 同名 directive 實作 Caddy 預設
順序**（或建立 Pingclair 自己的固定順序並以 Caddy 相容為目標），
讓同一份 Caddyfile 不因 directive 排列不同而行為不同。

### 🔴 D2：帶 matcher 的 middleware 被降級成 route arm，會被 terminal route 遮蔽

```caddyfile
example.com {
    @api path /api/*
    header @api X-A b
    handle /api/* { respond "api" }
}
```

編譯結果：兩條 route arm 都是 `path=/api/*`（Headers、Respond），
runtime 取第一條匹配——`header` 執行後 `respond` 不再執行；反過來寫
（`handle` 在前）則 `header` 永不執行。Caddy 的語義是 `header @api`
在 `handle` 之前套用、`handle` 仍然執行。middleware 不該是 route arm，
應該是包住 routing 的 chain（或至少確保 middleware 先於同 path 的
terminal route 執行）。

### 🟠 D3：同名 `handle` 沒有 matcher specificity 排序

```caddyfile
example.com {
    handle /foo* { respond "glob" }
    handle /foo { respond "exact" }
}
```

編譯結果：routes 順序 = 寫入順序（`/foo*` 在前）。Caddy 排序保證
`/foo`（精確）在 `/foo*`（glob）之前，與寫入順序無關。Pingclair
的 runtime router 對同一請求只取第一條匹配 route，所以
`/foo` 請求會命中 glob 分支。`handle /*` 寫在 `handle /api/*` 前面時
同理可能遮蔽更精確的路由（matchit 對 `/*` 的處理有部分緩解，但
同層級 specificity 排序仍是缺口）。

### 🟠 D4：`rewrite` 等 middleware 沒有 path matcher 化的語意

```caddyfile
example.com {
    rewrite /old/* /new/*
    handle /new/* { respond "new" }
}
```

編譯結果：`rewrite /old/* /new/*` 被當成「regex + replacement」的
fallback route（`path=/*`），完全沒有綁定 `/old/*`。Caddy 的
`rewrite` 是第一參數是 matcher 的 middleware（`rewrite /old/* /new/*`
表示「匹配 `/old/*` 的請求改寫成 `/new/*`」）。Pingclair 的兩參數
`rewrite` 語意與 Caddy 不同（文件已聲明是 regex），但**沿用 Caddy
寫法時行為會靜默錯誤**：不匹配也會走到 rewrite route。

### 🟡 D5：`route` block 內不能使用 matcher token

```caddyfile
example.com {
    route {
        @p path /x/*
        header @p X-A b
        reverse_proxy localhost:8080
    }
}
```

Caddy 允許 route 內 directive 帶 matcher；Pingclair 編譯失敗
（`Unknown directive '@p'`）。若短時間不支援，至少要讓錯誤訊息說明
「route 內暫不支援 matcher token」。

### 🟡 D6：directive 覆蓋度落差

Caddy 標準 directive 約 40 個。Pingclair 已支援：`basic_auth`、
`bind`、`encode`、`file_server`、`handle`、`header`、`import`、
`log`、`redir`、`respond`、`reverse_proxy`、`rewrite`、`route`、
`tls`（含自訂 `cors`、`rate_limit`、`access_control` 等）。

不支援且會直接編譯失敗：`abort`、`error`、`handle_errors`、
`handle_path`、`forward_auth`、`fs`、`invoke`、`map`、`method`、
`metrics`、`php_fastcgi`、`push`、`request_body`、`request_header`、
`root`、`templates`、`tracing`、`try_files`、`uri`、`vars`、
`intercept`、`log_append`／`log_skip`／`log_name`。

需求：

1. 已支援的 directive，其「Caddy 順序位階」要能對應到 Caddy 預設順序
   （見 D1）；
2. 不支援的 directive，錯誤訊息至少要提示「Caddy 相容但不支援」，
   避免野生 Caddyfile 遷移時被當成一般 typo；
3. `handle_path`（runtime 已有 `HandlePath`）與 `error`／`handle_errors`
   列入 v0.3 候選，與位址文檔 B3 的 vhost 修正一起排期。

## 4. 驗證需求

修復後以下測試必須全綠：

1. **單元（`cargo test -p pingclair-config`）**：
   - `respond` + `header` 與 `header` + `respond` 編譯出**相同**
     handler 順序（header 在 respond 前）；
   - `handle /foo` 與 `handle /foo*` 無論寫入順序，`/foo` 精確
     route 在前；
   - `header @api` + `handle /api/*`：header 套用後 handle 仍執行
     （middleware 不是 route arm）；
   - route block 內 matcher token 支援或明確錯誤；
   - rewrite 的 Caddy 語意（matcher + replacement）與 regex 語意
     明確區分，不接受歧義寫法。
2. **真 binary 整合**：兩個「只改 directive 排列順序」的設定檔，
   HTTP 行為（headers、status、body）完全一致。
3. **文件**：三份 README 若宣稱「Caddyfile-compatible」，需標明
   directive 順序相容範圍；`docs/STATUS.md` 記錄證據。

## 5. 明確不做（本文件範圍外）

- `order` global option 的完整實作（可先實作固定預設順序，`order`
  覆寫列 v0.3）。
- 未支援 directive 的完整實作（D6 只要求明確拒絕 + 提示）。
- `vars` 反序、`map` 等只在 Caddy 進階場景使用的語法。
