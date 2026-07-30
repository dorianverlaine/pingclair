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

## 第三輪：header 正規化 —— Host 的三個 MUST

見 `after-header-matrix.txt`（探針 `hdr.py`）。obs-fold、bare CR、NUL、
`:` 開頭的 header 名稱、空 header 名稱修前就已經全部 400。

但 **Host 的三條 RFC 9112 §3.2 的 MUST 全部沒有遵守**：

| 向量 | 修前 | 修後 |
|---|---|---|
| 重複 `Host` | 200，只取第一個轉發 | 400 |
| 缺 `Host`（HTTP/1.1） | 200 | 400 |
| `Host: a b`（含空白） | 200，原樣轉發 | 400 |

RFC 9112 §3.2 對這三種情況都寫 MUST respond 400。形狀跟路徑逃逸完全一樣：
這個代理從第一個欄位挑虛擬主機，origin 若挑最後一個，**服務的就是另一個站，
而剛剛套用的是前一個站的政策**。

HTTP/1.0 不檢查（`Host` 比它晚出現，缺席是合法的）；H2／H3 走 `:authority`，
由它們自己的 parser 負責。

## Day 16 完成度

| 類別 | 狀態 |
|---|---|
| hop-by-hop headers | ✔ `b6fbd26` |
| 重複 `Content-Length`／`Transfer-Encoding` | ✔ `06f19e7`（含 `+5` 真 bug） |
| request smuggling | ✔ 30 向量，上游視角驗證 |
| URI 正規化 | ✔ `7e89167`（路徑逃逸繞過路由政策） |
| header 正規化 | ✔ 本輪（Host 三條 MUST） |
| oversized headers | ✔ Day 8 已完成（431），M2 矩陣遠端驗證過 |
| malformed frame（H2／H3） | ⬜ framing 檢查已實作但只有單元測試 |
| proptest／fuzzing、與 nginx／Caddy 差異測試 | ⬜ |
