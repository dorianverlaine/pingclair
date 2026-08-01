# Caddyfile Common Patterns 需求文檔

> 📌 本專項以 Caddy 官方文檔（`caddyfile/patterns`，本機
> `~/code/caddy-website`）為基準，逐個驗證「官方最小範例」在
> Pingclair 的編譯與行為。**這些範例是使用者遷移 Caddyfile 時最常
> 貼上的第一份設定**，因此是相容性的驗收基準，不是可選功能。

## 1. 逐範例驗證結果（2026-08-01 實測）

> 全部以 `compile()` 實測；「runtime」標註的部分另以原始碼追蹤確認。
> 臨時探針已刪除，工作區無改動。

| 官方範例 | 結果 | 原因 |
|---|---|---|
| Static file server（`root` + `file_server`） | ❌ 編譯失敗 | `Unknown directive 'root'`——`root` 完全沒實作 |
| Reverse proxy + `file_server`（`reverse_proxy /api/*`） | ❌ 編譯失敗 | 同上（`root`）；且內聯 path matcher 未處理 |
| PHP（`php_fastcgi`） | ❌ 編譯失敗 | `root`＋`php_fastcgi` 都不支援 |
| Redirect www（`redir https://www.{host}{uri}`） | ❌ 編譯失敗 | **`{host}{uri}` 相鄰 placeholder 被拆成三個 token** |
| Trailing slash（rewrite 版） | ⚠️ 編譯過但語意不同 | 兩參數 rewrite 是 regex 語意，不是 Caddy 的 path 語意 |
| Trailing slash（redir 版） | ❌ 編譯失敗 | `redir /add /add/`：`/add/` 被當 status code |
| Wildcard certificates（`tls { dns ... }`） | ❌ 編譯失敗 | `tls: dns`、`host` matcher、`abort` 都不支援 |
| SPA（`try_files`） | ❌ 編譯失敗 | `root`、`try_files` 不支援 |
| Caddy→Caddy（front） | ✅ 可以 | 位址解析有 B 系列問題但不擋這個範例 |
| Caddy→Caddy（back，`trusted_proxies static private_ranges`） | ❌ 編譯失敗 | `trusted_proxies` 不認 `static`／`private_ranges` |

## 2. 已確認 bug（依影響排序）

### 🔴 P1：`root` directive 完全沒有實作

Patterns 文檔的 static file server、reverse proxy、PHP、SPA 範例
全部以 `root /var/www` 為基礎，Pingclair 卻回
`Unknown directive 'root'`。`file_server` 只能靠
`file_server ./path`（inline）或 `file_server { root ... }`（block）
設定根目錄。Caddy 的 `root` 同時影響 `try_files`、`file` matcher、
`php_fastcgi` 的 index 解析，是遷移時第一道牆。

**最低需求**：site block 內支援 `root <path>`（含 `root * <path>`
的 matcher token 形式），並接入 `file_server` 的根目錄。

### 🔴 P2：`redir https://www.{host}{uri}` 被拆 token（www 轉跳全滅）

官方「add www」與「remove www」範例：

```caddy
example.com {
    redir https://www.{host}{uri}
}
```

lexer 把 `{host}`、`{uri}` 當獨立 token，parser 組出三個參數
`["https://www.", "{host}", "{uri}"]`，`adapt_redirect` 直接報錯。
STATUS.md 已記錄「目標含 `{` 必須加引號」的 workaround，但 Caddy
官方範例就是不加引號——**這代表官方 patterns 頁整段不能原樣貼**。
修法：lexer 應把 `{placeholder}` 與相鄰文字保持在同一 token
（Caddy 的 token 化就是如此），或至少讓 `redir` 支援把相鄰
placeholder 重新組合成單一目標。

### 🟠 P3：`reverse_proxy /api/* localhost:5000` 的內聯 path matcher 未處理

```caddy
example.com {
    reverse_proxy /api/* localhost:5000
    file_server
}
```

`adapt_reverse_proxy` 只過濾 `@` 開頭的參數；`/api/*` 會被當成
upstream 位址（`ProxyConfig.upstreams = ["/api/*", "localhost:5000"]`）。
除非 route 層先有 matcher，否則第二個 upstream 不存在時編譯仍過、
runtime 才壞。Caddy 語意：`/api/*` 是該 directive 的 matcher。
需求：`reverse_proxy`（及其他支援 matcher 的 directive）解析第一個
參數是否為 `/`-開頭的 path matcher。

### 🟠 P4：`rewrite` 兩參數形式與 Caddy 語意不同（trailing slash 依賴）

```caddy
example.com {
    rewrite /add /add/
    rewrite /remove/ /remove
}
```

現況兩參數 = regex + replacement。`/add` 當 regex 恰好能匹配
`/add`（也誤匹配 `/added`），`/remove/` 當 regex 也「剛好能跑」，
所以範例能動，但語意是錯的：Caddy 的兩參數 rewrite 是
`rewrite <matcher> <replacement>`（第一參數是 path matcher）。
Pingclair 的 regex 語意對 `/foo/bar` 這類含 regex 特殊字元的 path
會壞，且誤匹配沒有防護。需求：明確區分「Caddy path rewrite」與
「Pingclair regex rewrite」（例如 regex 版改名或要求前綴），
不接受同一寫法兩種解讀。

### 🟠 P5：`file_server` 沒有 trailing-slash 自動轉跳

Patterns 文檔明說：file_server 會對「目錄無斜線」的請求 308 加斜線、
對「檔案帶斜線」的請求去斜線。Pingclair 的
`pingclair-static/src/file_server.rs` `serve_auto()` 對目錄直接
找 index 回應，**沒有 Location redirect**。結果：SEO canonical 與
客戶端 URL 正規化行為與 Caddy 不同（雙 URL 都能開，但不會收斂到
單一斜線形式）。

### 🟡 P6：placeholder 支援只有 5 種，`{labels.*}` 等解析成空字串

`resolve_single_placeholder`（`pingclair-proxy/src/server.rs`）只支援
`{host}`、`{http.request.host}`、`{remote_ip}`、`{method}`、`{uri}`、
`{path}`（＋`{http.request.header.*}`）。官方 placeholder 縮寫表
（concepts 文檔）約 40 種，patterns 頁用到的 `{labels.1}.{labels.0}`
（多網域 www 移除）會解析成空字串——編譯過、行為錯。
需求：至少把 patterns 頁用到的 `{labels.*}` 補上，其餘縮寫明確
記錄為「不支援 → 編譯期警告」。

### 🟡 P7：wildcard site 三缺一（`tls { dns }`／`host` matcher／`abort`）

Wildcard certificates 範例需要三個能力，Pingclair 全部沒有：

- `tls { dns <provider> ... }`（ACME DNS challenge）；
- `host` matcher（wildcard site 內分流子網域）；
- `abort` directive（無匹配時終止請求，不做 fallback）。

`host` matcher 已有 core 型別與 compiler 支援（見 matchers 文檔
M5），補 adapter 即可；`abort` 與 `tls { dns }` 需要 runtime 能力，
列 v0.3。wildcard 憑證本身（ACME DNS）也列 v0.3。

### 🟡 P8：SPA 需要的 `try_files` 沒有實作

```caddy
example.com {
    root /srv
    encode
    try_files {path} /index.html
    file_server
}
```

`try_files` 是 SPA 範例的核心（先找檔案、找不到 rewrite 到 index）。
Pingclair 回 `Unknown directive 'try_files'`。需求：支援
`try_files <files...>`（配 `file` matcher 語意），或至少在 v0.3
排期並讓錯誤訊息提示替代寫法（`rewrite` + `file_server`）。

## 3. 驗證需求

1. **單元**：官方 patterns 頁每個範例做成 compile 測試（與
   `documentation.rs` 同機制，但用官方原文而非自訂範例）——
   目前 9 個範例中 6 個編譯失敗，測試會直接暴露。
2. **真 binary**：
   - `root /var/www` + `file_server` 正確服務根目錄；
   - `redir https://www.{host}{uri}` 不帶引號編譯並正確轉跳；
   - `reverse_proxy /api/* localhost:5000` + `file_server` 分流正確；
   - file_server 對目錄/檔案做 trailing-slash 308；
   - `{labels.1}.{labels.0}` 解析出正確 hostname。
3. **文件**：README 三語若宣稱「Caddyfile-compatible」，附上官方
   patterns 頁的支援狀態表。

## 4. 明確不做（本文件範圍外）

- `php_fastcgi`／`php_server`（FastCGI client 是獨立功能，列 v0.3+）。
- FrankenPHP 相關 global option。
- ACME DNS challenge／wildcard 憑證的完整實作（P7 已列）。
- `try_files` 的 file-exists 語意若短期不做，用錯誤訊息引導替代
  寫法即可（P8 已列）。
