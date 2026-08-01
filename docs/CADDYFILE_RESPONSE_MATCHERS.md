# Caddyfile Response Matchers 需求文檔

> 📌 本專項以 Caddy 官方文檔（`caddyfile/response-matchers` 與
> `reverse_proxy` 的 Intercepting responses 章節）為基準，評估
> Pingclair 對 **response 端攔截**的支援狀態。

## 1. Caddy 官方語義（需求基準）

Response matcher 用於「回應寫回客戶端之前」做決策，只出現在特定
directive 的 block 內（主要是 `reverse_proxy` 的
`handle_response`，以及 `replace_status`、`copy_response`、
`copy_response_headers`）。

### 1.1 Named response matcher

```caddy-d
@name {
    status <code...>
    header <field> [<value>]
}
@name status <code...>
```

- `status`：HTTP status code 清單，支援 `2xx`／`3xx`／`4xx`／`5xx`
  類別寫法；
- `header`：與 request matcher 同語意（`!` 不存在、`*` 前/後綴、
  兩側 `*` substring、多值 OR、多欄位 AND）。

### 1.2 使用位置

```caddy-d
reverse_proxy ... {
    @name {
        status 404
        header Foo *bar*
    }
    replace_status [<matcher>] <status_code>
    handle_response [<matcher>] {
        <directives...>
        copy_response [<matcher>] [<status>] { status <status> }
        copy_response_headers [<matcher>] { include/exclude <fields...> }
    }
}
```

## 2. Pingclair 現況

**沒有 response matcher 概念，也沒有 `handle_response`。** 現有的
response 端能力只有 nginx 風格的 `error_page`：

- `error_page 404 /404.html`：status → 檔案，編譯期展開成
  `error_pages: Vec<(u16, String)>`；
- runtime 用 `intercepts_error_status()`／`read_error_page()` 在
  錯誤路徑替換回應；
- **沒有** status class（`4xx`）、沒有 header 條件、沒有
  `replace_status`／`copy_response`／`copy_response_headers`。

## 3. 已確認問題（2026-08-01 實測，探針已刪除）

### 🔴 R1：`handle_response`／`replace_status`／`copy_response_headers` 靜默無效

```caddyfile
example.com {
    reverse_proxy localhost:8080 {
        handle_response @name {
            respond "intercepted"
        }
        @name {
            status 404
        }
        replace_status 404 200
    }
}
```

編譯**成功**、`error_pages` 為空——因為 `adapt_reverse_proxy` 的
catch-all 分支 `_ => {}` 把未知子指令整個吞掉（directives 文檔 D6
已記錄同一根因）。使用者以為配了回應攔截，實際上游 404 原樣回傳。
這比「編譯失敗」危險：設定看起來有效，行為完全沒有。

**最低需求**：未實作的子指令（`handle_response`、`replace_status`、
`copy_response`、`copy_response_headers`、`@name { status/header }`
response matcher 定義）必須**編譯期明確拒絕**，並提示
「Pingclair 尚未支援 response interception」。

### 🟠 R2：`error_page` 不接受 `4xx` 類別碼

```caddyfile
error_page 4xx /error.html
```

Caddy 的 status matcher 支援 `2xx`／`3xx`／`4xx`／`5xx`；Pingclair
的 `error_page` 只收 `u16` 字面值，`4xx` 報
`Invalid argument for 'error_page': 4xx`。這至少是 fail-closed，
但遷移時常見的類別寫法會直接卡住。

**建議**：`error_page` 或新的 `handle_response` 支援 status class；
短期至少把錯誤訊息寫明「支援的寫法是逐碼列舉」。

### 🟡 R3：無任何 response header 條件能力

Caddy 的 response matcher 可依 `header` 欄位存在性／值做決策
（`header Foo *bar*`、`header !Foo`）。Pingclair 的 error_page 只能
依 status 決定，無法「對帶 `X-Rate-Limit` 的回應做 X」。

### 🟡 R4：`handle_response` 相關能力列為 v0.3，但要先 fail closed

`docs/STATUS.md` 的 v0.3 候選已列「Response interception pipeline —
依 upstream status／header 執行 replace status、copy／drop headers、
redirect、fallback handler；擴成 Caddy `handle_response`」。
方向正確；本專項的附加要求是：**在 v0.3 實作完成前，R1 的靜默
吞沒必須先修**，否則所有貼了 `handle_response` 的 Caddyfile 都會
「編譯過、沒行為」。

## 4. 驗證需求

1. **單元**：含 `handle_response`／`replace_status`／
   `copy_response_headers`／`@name { status ... }` 的設定必須
   compile error（訊息含「not supported」提示）；
   `error_page 4xx` 明確拒絕（或支援）；
2. **真 binary**：目前這類設定編譯就該失敗，不需要 runtime 測試；
   v0.3 實作後再補 status class／header 條件的攔截測試；
3. **文件**：README 三語不要宣稱支援 `handle_response`；
   `docs/STATUS.md` 的 v0.3 清單保留並標注 fail-closed 前置條件。

## 5. 明確不做（本文件範圍外）

- `handle_response` 完整實作（status class、header 條件、
  copy_response、redirect、fallback handler）——列 v0.3；
- `acme_server` 等其他 response 端功能。
