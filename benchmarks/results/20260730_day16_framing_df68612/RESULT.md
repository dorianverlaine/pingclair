# Day 16 後半 — 訊息框架（request smuggling）

**Commit（基準）**: `df68612` ｜ **日期**: 2026-07-30
方法：原始 socket 打 15 個向量，並讓上游把**實際收到的位元組**原樣回傳，
所以「有沒有被走私」是看上游的視角，不是看 proxy 回什麼狀態碼。

## 一句話結論

15 個向量裡 **12 個修前就已經擋掉**（httparse／Pingora），
**1 個是真 bug 且已修**（`Content-Length: +5`），
**1 個由 Pingora 正確處理、不是我們的功勞**（CL+TE），
**1 個放行且判定為可接受**（bare LF）。

## 逐項

| 向量 | 修前 | 修後 | 誰擋的 |
|---|---|---|---|
| baseline GET | 200 | 200 | — |
| CL + TE（CL.TE） | 200 | 200 | **Pingora**：解析時移除 CL 並關 keepalive |
| TE + CL（TE.CL） | 200 | 200 | 同上 |
| 重複 CL（值不同） | 400 | 400 | httparse |
| 重複 CL（值相同） | 400 | 400 | httparse |
| `TE: chunked, identity` | 400 | 400 | Pingora |
| `TE: xchunked` | 400 | 400 | Pingora |
| `TE : chunked`（冒號前空白） | 400 | 400 | httparse |
| bare LF 行尾 | 200 | 200 | 放行，見下 |
| `CL: -1` | 400 | 400 | httparse |
| **`CL: +5`** | **200** | **400** | **本次新增** |
| `CL: 0x5` | 400 | 400 | httparse |
| chunk size `zz` | 400 | 400 | Pingora |
| header name 含空白 | 400 | 400 | httparse |
| 只有 CR 的行尾 | 400 | 400 | httparse |

## 唯一的真 bug：`Content-Length: +5`

RFC 9110 §8.6 規定 `Content-Length = 1*DIGIT`。httparse 擋掉了負數與十六進位，
但**接受前置正號**。修前的證據（`before-upstream-view.txt`）顯示上游收到：

    POST /echo HTTP/1.1
    Host: a
    Content-Length: +5
    ...

    HELLO

也就是 Pingclair 把 `+5` 當 5 讀了 body，並且**原封不動轉發那個非法值**。
寬鬆的後端讀 5 bytes、嚴格的後端拒絕或當 0——兩端對「剛才消耗了多少」產生分歧，
緩衝區裡就留下殘骸。這是典型的解析器分歧型走私。

修後回 400，`after-upstream-view.txt` 顯示上游完全沒收到這個請求。
紅字先行：把 `check_request_framing` 的 CL 驗證拿掉，該測試立刻失敗。

## CL+TE：Pingora 處理的，我沒修

`pingora-core-0.8.1` 的 `protocols/http/v1/server.rs:272` 在解析時就移除
`Content-Length` 並關閉 keepalive，符合 RFC 9112 §6.1。修前實測那串
`GARBAGE` 也沒有被轉給上游。

所以 `FramingRejection::AmbiguousLength` 在 H1 上**永遠不會觸發**。保留它是
對依賴行為改變的縱深防禦，真正的保護是
`test_conflicting_length_headers_cannot_smuggle_a_second_request`——Pingora
哪天放寬了，那個測試會紅。

## bare LF：放行，且判定為可接受

RFC 9112 §2.2 允許接收端把單獨的 LF 視為行終止符。Pingora 解析後會用 CRLF
重新序列化再送上游，所以前後端不會因為行尾差異而分歧。

## 第二輪：URI 正規化 —— 又一個真漏洞

見 `after-uri-matrix.txt`（探針 `uri.py`）。靜態檔的路徑逃逸全數擋掉（404），
但**反代路由沒有**：

    GET /api/../admin/x   → 200，上游收到 /api/../admin/x（原封不動）
    GET /api/%2e%2e/admin/x → 200，上游收到 /api/%2e%2e/admin/x

Pingclair 用 `/api/*` 匹配它，所以綁在 `/admin/*` 上的 403 政策**從未執行**；
而 origin 幾乎都會自己正規化，解析成 `/admin/x` 並提供服務。代理與源站對
「請求的是哪個資源」產生分歧——這就是攻擊者要的。

**修法：拒絕，不是改寫。** 改寫會變動每一個 origin 收到的東西；而合法客戶端
本來就不該送出未正規化的路徑（RFC 9110 §4.2.3）。符合專案的 fail-closed 規則。

修後 `/api/../admin/x`、`/api/%2e%2e/admin/x`、`/admin/./x`、`/static/..%2f...`
全部回 400，兩條傳輸共用同一個判斷。

`%252e%252e`（雙重編碼）維持 404 而非 400，是**正確的**：解一次碼之後是字面的
`%2e%2e`，不是 `..`；origin 若也只解一次同樣不會當成 traversal。

## 尚未涵蓋

- H2／H3 的 framing 檢查已實作（H2/H3 一律拒絕 `Transfer-Encoding`，
  RFC 9113 §8.2.2、RFC 9114 §4.1），但**只有單元測試**，沒有像 H1 這樣的
  原始 frame 級負向測試。H2 需要能發畸形 frame 的客戶端。
- URI 正規化（`..`、編碼過的斜線、雙重編碼）尚未系統性覆蓋。
