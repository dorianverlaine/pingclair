# Day 27 之前的剩餘工作與實施計劃

## Context

`docs/TODO.md` 的 M3.5 段落已經跟程式碼脫節。今天逐項查證後，**四項宣稱是錯的**
（`host` matcher、`{scheme}` placeholder、path URI-decode 正規化其實都做完了；
`handle_response` 也早就 fail closed，不是文件說的「靜默吞沒」），而**兩個真實缺陷
沒有被記錄**，其中一個每個請求都回錯的內容。照現況的 TODO 排程，等於對著一份
部分虛構的清單規劃。

同時，量測工具本身也是錯的：語料 harness 用 `pingclair validate`，而它比
`caddy adapt` 多做一個 TLS 憑證檔案存在性檢查，害兩份 fixture 假失敗。
**目前的 67／228 是用錯的尺量出來的。**

擁有者已決定：**v0.2 範圍擴大到完整相容 Caddy**，發布日期後推；Day 15 跳過，
改成功能做完後一次統一驗證；工作層級到「全部，含 🔴 深工程」。

目標成果：把 TODO 校正回事實、把量尺修對，然後照「先停止做錯 → 再擴大相容」的
順序推進，並以上游語料（228 份）的**逐份 verdict** 作為可量測的進度。

---

## 一、Day 27 之前的實際剩餘工作（校正後）

### 已經做完，但 TODO 說沒做 —— 只需改文件

| 項目 | 證據 |
| --- | --- |
| `host` matcher | core `types.rs:469`、router `router.rs:266`、compiler `compiler.rs:1305`、**adapter 也在** `matchers.rs:316` |
| `{scheme}` placeholder | `server.rs:3689`；`{method}`／`{remote_host}`／`{labels.N}`／`{query}`／`{hostport}`／`{port}` 全在。`server.rs:3695` 有一條**過期的 TODO 註釋**還列著它們，這很可能就是誤判來源 |
| path URI-decode 正規化 | `http_policy.rs:759` 先 `decode_encoded_dots` 再正規化，且在 routing 之前；測試 `http_policy.rs:1075` 釘住 `%2e%2e` |
| `handle_response`／`replace_status` 靜默吞沒 | **相反**：`reverse_proxy.rs:436-446` 兩條 arm 都報錯。註釋自己寫著「used to vanish here」——文件讀的是過去式 |
| `dynamic srv`／`fail_duration` 靜默吞沒 | 已拒絕（`reverse_proxy.rs:98`、`:838`）；`lb_try_duration` **已完整實作**（`retry.rs:11`） |

### 兩個沒被記錄的真實缺陷

1. **🚨 靜默做錯事（最嚴重）**：`route`／`handle` 區塊內 directive 上的 matcher token
   被丟掉，而且 token 被當成資料讀。
   ```
   :PORT { @admin path /admin/*
           route { respond @admin "SECRET" 200
                   respond "public" 200 } }
   ```
   兩邊都說 valid，**執行期 3／3 全差**：Caddy 正確分流，我們對**每一個請求**
   回字面字串 `@admin`。根因：`sites.rs:415` 把未剝除的 args 丟給 `adapt_handler`，
   各 directive 各自把 `@` 開頭參數濾掉（`reverse_proxy.rs:24`、`directives.rs:678`）
   或誤讀（`adapt_respond`）。

2. **H3 parity gap**：`respond` 內文在 HTTP/3 完全不展開 placeholder。
   實測（curl 8.21 帶 HTTP3）：H1/H2 得到 `path=/probe scheme=https`，
   H3 得到字面 `path={path} scheme={scheme}`。`server.rs:2606` 有解析，
   `quic.rs:2062` 直接送原字。諷刺的是 `quic.rs:1713` 的註釋正好在講
   「不要製造只在一個 transport 成立的 parity gap」。

### 量尺本身的缺陷

語料 harness 跑 `pingclair validate`，它比 `caddy adapt` 多一個 TLS 檔案存在性檢查
（`cli/dispatch.rs:641`）。`tls_automation_policies_10` 與
`tls_automation_wildcard_shadowing` **只因為這個**假失敗——已逐項驗證：
`adapt` 兩份都 OK、`caddy adapt` 兩份都 OK、`validate` 兩份都 NO。

### 其餘既有欠帳

- **M4.5**：🚨 `https://host` 反而拿到比 `host` 少的 TLS；重構尾巴 26k／26k-1／26h-1
- **TRIAGE**：P1 `hash-password argon2id` 產生伺服器驗不了的 hash（等於造出假帳號）；
  P2 file_server canonical redirect 用改寫後路徑而非原始路徑、明文密碼被接受、
  `parse_range` debug panic 與靜默修復、`should_stream` 繞過 docroot 檢查
- **Day 26 殘項**：關閉排水根因未查、`03-metrics.sh`／`04-readiness.sh` 測試腳本無效
- **發布**：release binary 需要 glibc 2.38+（Day 33 必須明講或換基底）

### 語料失敗權重（161 份失敗，作為排序依據）

`tls client_auth` 15｜`global pki` 8｜`global dns` 7｜log 類 ~16｜`error` 6（見下）｜
`import` 帶區塊 6｜`php_fastcgi` 6｜`tls issuer` 4｜`forward_auth` 3｜`metrics` 5｜
`header_regexp` capture 3｜`lb_retry_match` 3｜`file_server` 子指令 6｜其餘散項

> **兩個反直覺的發現，已逐份查證：**
> - **`error` 單獨做會 +0**。七份 `error_*` fixture **全部**同時用到
>   `handle_errors`（實測：`error_subhandlers` 甚至只有 `handle_errors`）。
>   而 `handle_errors` 是空殼——三條路徑都不做事。兩者是**一個 7 份的叢集**。
> - **`forward_auth` 不是功能，是語法糖**：上游用 `reverse_proxy` +
>   `handle_response` + `copy_headers` 實作。它與 `intercept`、
>   `reverse_proxy handle_response`、`php_fastcgi handle_response`
>   是**同一個機制**。

---

## 二、實施計劃（逐個 session，每個一句話主題）

排序原則沿用倉庫自己的規則：**現在就在做錯的排最前**，再來是**修量尺**，
然後照「每單位工作的語料移動量」排，內部重構墊底。

### Session 0 — 只改文件，不動程式碼

校正 `docs/TODO.md`：刪掉上表五項假宣稱、把兩個新缺陷寫進去、Day 15 標為跳過、
重寫 **v0.2 明確不做** 段落（Caddy 功能移入範圍；保留永久排除項：
`upgrade`／`add-package`／`remove-package`——理由是**架構上沒有等價語意**，
不是排程選擇——以及 `--reveal-symlinks`、AI Gateway、xDS、L4 passthrough），
修好 `建議順序` 壞掉的編號（現在是 5,4,5），把 M4.5 的 ⚫ 項標 `[x]`。

### Phase A — 停止做錯（3 個 session，語料預期 +0）

**A1｜`route`／`handle` 內的 matcher token 改成明確拒絕，而不是當成資料。**
完整修法需要動三個核心抽象（見 C2），一個 session 放不下；先擋住。
擋板註釋要寫明在等什麼，並在 C2 同一個 commit 刪掉。
檔案：`sites.rs`（route／handle／handle_path arm）、`directives.rs:93`。
重用 `matchers::matcher_token`，不要寫第三份規則。
驗證：單元 + 語料**逐份 verdict** 比對 + 16 份 golden 逐位元 + 真 binary 整合測試。

**A2｜HTTP/3 的 `respond` 內文比照 H1/H2 展開 placeholder。**
只動 `quic.rs`；順手把 `Redirect` arm 的 `None` 換成 `verified_client_ip_text`
（⚡ 走過就修規則）。**不需要 Linux**——不碰 TLS 依賴、不碰連結、不碰 QUIC transport，
commit body 要寫明這一點免得下一個人誤判。

**A3｜寫 `https://host` 至少要拿到跟 `host` 一樣多的 TLS。**
`compiler.rs:55` 的 `block.listens.is_empty()` 條件錯了；`ListenAddr` 已帶 `scheme`。
**先讀上游 `httpcaddyfile/httptype.go` 的自動 HTTPS 推導**，不要用「測試會過」反推。
golden fixture 會變，逐份讀 diff。

### Phase B — 先修量尺（1 個 session，+2 → 69）

**B1｜語料改用 `adapt` 量，因為那才是這份語料在問的問題。**
只改 `verification/day26/corpus.py`。舊的 `baseline-frozen-bc87e85.json` **保留不覆蓋**。
修完可能露出被 `validate` 的額外檢查遮住的缺陷——**預設當成發現，不是回歸**。

### Phase C — matcher 抽象（2 個 session）

**C1｜把 matcher 評估變成任何地方都能呼叫的預編譯原語，行為零改變。**
`router.rs`：公開 `MatcherRequest` 與 `evaluate`，並在 `CompiledRoute` 上加一個
**今天是空的**、C2 才會填的預編譯容器。容器放這裡是刻意的——否則 C2 會同時動兩個抽象。
驗證標準：語料**相同**、golden **逐位元相同**。動了就代表改的不是你以為的東西。

**C2｜讓 `route`／`handle` 內的 directive 帶自己的 matcher。**
`HandlerConfig::Pipeline`／`Handle` 改成帶 `Option<Matcher>` 的元素。
**先讀上游 `httpcaddyfile/directives.go:356-425`**（三條猜不到的規則：區塊內的
matcher 定義從父層複製、本地增補、不向上洩漏；`route` **不排序**內容而 `handle` **排序**）。
🚨 serde 風險：`Matcher` 有手寫 `Deserialize` 擋著一個真實的 stack-overflow DoS
（`types.rs:427`），新的巢狀型別**必須 externally tagged，絕不可 untagged**；
且既有 JSON `pipeline` 設定必須照樣載入。
同 commit 刪掉 A1 的擋板。語料 +2。

### Phase D — 設定層的高投報（4 個 session，~+20）

**D1｜採用上游的 logger 文法**（最大單一收穫，~8–11 份）。
🤡 這是 `basic_auth` 那個缺陷的同一個形狀：我們把 `log <name>` 讀成「導向全域宣告的
channel」，上游讀成「一個叫 `<name>` 的 logger，由這個區塊設定」——**兩種拼法相撞，
不是擴充**。處置同 `basic_auth`：採用上游文法，舊拼法指名拒絕並說出替代寫法。
是 breaking change，CHANGELOG + 三份 README 當天改。

**D2｜補完 logger 子選項**：`hostnames`／`include`／`exclude`／`sampling`／
format `filter`／`log_skip`／`log_append`／`log_name`／其餘 `roll_*`。~7 份。
⚠️ 扁平與區塊兩種拼法**必須走同一個 parse helper**（`health_interval` 秒 vs 毫秒那條）。

**D3｜把區塊替換進要求它的 snippet**（`{block}`，~6 份）。
❓ **開工前先決定**：上游在 **token** 層替換（`caddyfile/parse.go:534`），
我們在 adapter 的 **Directive** 層展開。讀 `parse.go:520-570` 決定哪一層——
答案會讓這個 session 的大小差三倍。

**D4｜讓 `validate` 回答 `adapt` 在問的問題**：`tls <email>` 簡寫、
`persist_config off` 接受／`on` 拒絕、`local_certs` 接到既有 internal CA。
📌 `local_certs` **本身得分 0**（兩份 fixture 都還要 `on_demand`）——先講明白，
不要做完才發現（「便宜實作 ≠ 便宜的分數」）。

### Phase E — 安全欠帳（1 個 session）

**E1｜密碼比對器由設定宣告的演算法決定，而不是用前綴猜。**
🔬 修正 TRIAGE 那一列的隱含選項：**上游有 argon2id**
（`caddyauth/argon2id.go`），所以在「完整相容 Caddy」範圍下「停止產生它」是錯的分支——
要實作。根因兩列共用：`compiler.rs:1610` 用 `$2` 前綴推斷 `hashed`，
`handlers.rs:373` 掉到字面比對。改成存下宣告的演算法、實作 argon2id 驗證、
**拒絕明文**——同一行同時關掉那個 P2。

### Phase F — 錯誤變成可路由（2 個 session，+7）

**F1｜`error` 成為產生狀態碼的 handler。** 預期**語料 +0**，commit body 要寫明原因，
免得下一個人把持平讀成失敗。
**F2｜錯誤照請求的方式被路由**（`handle_errors`）。卡在 C2 之後
（`error_subhandlers` 在 `handle_errors` 裡放 `handle` 區塊）。
🚨 兩個必測形狀：重複回應、錯誤處理器自己出錯的無限遞迴。

### Phase G — 請求範圍狀態（2 個 session）

**G1｜給請求一個放值的地方**（`vars`、`vars` matcher、`{http.vars.*}`）。
放 `http_policy.rs`，因為兩個 transport 都要（CLAUDE.md 明文）。
**G2｜具名 regex capture 變成 placeholder**（`{re.name.N}`）。
⚠️ 三份 `replaceable_upstream*` **不要排在這裡**——它們把捕捉值當**上游位址**用，
那與 `ProxyState` 的預編譯 per-route 負載平衡器和 `HttpPeer::group_key` 池隔離相撞。歸 H2。

### Phase H — 上游可達性（3 個 session）

**H1｜撥接 Unix socket**（`unix//`、`unix+h2c//`、portless）。+2，且是 `php_fastcgi` 的前置。
**H2｜解析只在請求當下才知道的上游**（`dynamic` + `replaceable_upstream*`，+5）。
🚨 全計劃最容易違反 hot-path 規則的一項：設計時先回答「per-request peer 從哪來
而不把設定期工作搬到熱路徑」。
**H3｜補完 `reverse_proxy` 的其餘選項**（`lb_retry_match` 等，~7）。
❓ 先花十分鐘查 `reverse_proxy_health_headers` 為何撞到我們自己的
「health_check headers 無效或過長」——可能是我們的驗證錯了，那就是 TRIAGE 而非功能。

### Phase I — 回應攔截（2 個 session，~+6）

**I1｜讓 handler 在客戶端看到之前檢查上游回應**（`handle_response`／`copy_response`／
`copy_response_headers`）。一個機制同時解鎖 `intercept`、`php_fastcgi handle_response`
與整個 `forward_auth`。
🌊 **全計劃串流風險最高**：天真實作會把上游 body 整份緩衝來做判斷，
而這個倉庫**已經出貨過兩次整份緩衝**。不可省的測試：20 MB body、SSE、
客戶端中途斷線、RSS 有界。
**I2｜`forward_auth` 就是 `reverse_proxy` 加 `handle_response`**。純展開，+3。
🔐 上游有一個 header 剝除的安全修補（`GHSA-f59h-q822-g45g`）——要一起做，
否則 `copy_headers` 可被繞過。

### Phase J — FastCGI（2 個 session，+6）

**J1｜講 FastCGI 協定**（新子系統，語料不直接給分）。卡在 H1。
**J2｜照上游的方式展開 `php_fastcgi`**。卡在 J1 與 C2。
🚫 沒有 J1 就接受這個 directive，正好是本計劃開篇要關掉的那一類靜默錯誤。

### Phase K — TLS（4 個 session，**全部需要 Linux**）

macOS 單元測試證明不了這裡任何一項。`rust:1.97-bookworm` 需要 `cmake` 與
`clang`／`libclang-dev`，否則 `boring-sys` 在 build script 就失敗。

**K1｜給 TLS 一份 automation policy**（`default_sni`、`on_demand`、`get_certificate`，~8）。
📌 `default_sni` 順帶修一個**現行缺陷**：`certs.rs:145` 在 SNI 為空時提早返回，
所以不送 SNI 的客戶端**現在完全拿不到憑證**。
**K2｜解析 client trust pool**（只有設定層，macOS 可證，本身 0 分）。
**K3｜在 H1/H2 acceptor 上驗證客戶端憑證**（+15，最大單一叢集）。**Linux only。**
**K4｜HTTP/3 給出同一個 client-auth 答案**。不同的 stack（`tokio-quiche` 的
`ConnectionHook`，不是 Pingora acceptor）。**Linux only。**
🚨 不可以讓 K3 宣稱 `client_auth` 可用而 H3 靜默放行所有人。
**K5｜用 DNS-01 簽發憑證**（~18，一個機制）。
❗ 需要 **provider registry**：上游靠外掛填，語料只用 `dns mock`。
**明確決定出貨哪幾個 provider，其餘指名拒絕**——接受任意 provider 字串等於
每一張萬用字元憑證都靜默簽不出來。做完三份 README 當天改（它現在寫著沒有 DNS-01）。

### Phase L / M / N — 其餘（7 個 session）

- **L**：`metrics` 站台 handler；全域 `servers` 區塊（我們**完全沒有**這個全域選項）
- **M1**：補完 `file_server` 六個子指令（+6）。❓ **先讀 `precompressed` 的函式體**——
  TODO 說 CLI flag 已拉回 v0.2，但「數 arm」這個推論今天已經錯過一次。
  順手一起修 canonical-URI redirect 那個 P2（同一段程式碼）。
- **M2**：`method`／`request_header`／`request_body`／`abort`。
  ⚠️ `request_body` 是設計衝突：上游 per-route，我們 `client_max_body_size` 是 per-server——
  要明確解決，不是含糊帶過。
- **M3**：其餘全域選項與 matcher。`path_regexp` matcher 要新的 core `Matcher` 變體，
  而那個型別帶著擋 DoS 的手寫 serde——若不只是加一支 arm，就自己一個 session。
- **N1**：26k-1（連 README 第 8 個 config 區塊與 ~24 個內嵌測試一起收緊）、
  26h-1（**先查出上游是哪一層擋的**，TODO 明講還沒查清）、26k 位址語意尾巴
- **N2**：TRIAGE 的 P2 批次（`parse_range` 兩項、`should_stream`、404 body、
  `encode.rs` 自相矛盾的註釋、`mime.rs` 的整檔 `allow(dead_code)`）

### 📌 一個我建議你重新考慮的項目

`pki` + `acme_server`（8 份）的內容是「**成為一個 CA，用 RFC 8555 對其他客戶端簽發憑證**」。
它比上面好幾個 phase 加起來還大，是全語料**投報率最差**的一項，而且三份 README
昨天才剛把它寫成不支援。你的答覆是「全部」，所以我把它排在功能的最後、驗證之前，
但它實際上是 3–4 個 session 而不是 1 個。**若要縮短路徑，這是最該砍的一項。**

### Phase O — 一次統一驗證（2 個 session）

取代 Day 15、Day 22 式的逐里程碑驗證日與 Day 26 的 RC 關卡。

**O1（本機）**：`+1.97.1` 四閘門；完整語料**逐份 verdict 比對**（不是看總分）；
16 份 golden；`compare.py` 對照 Caddy v2.11.4；`integration.rs`（含 AGENTS.md 的
幽靈程序檢查）；`test-h3-day28-local.sh` 與 `test-h3-cancellation-local.sh`。

**O2（Linux／公網）**：`validate-linux-commit.sh` release build；
`cargo tree -i openssl-sys` 無匹配且 `boring-sys` 恰好一份；H3 冒煙矩陣；
兩個 transport 的 client-auth；DNS-01 對 ACME staging；以及**從未重跑過的 Day 29
公網矩陣**。證據寫進 `benchmarks/results/<date>_<commit>/`，記完整 SHA。

---

## 三、驗證方式（每個 session 通用）

```bash
cargo +1.97.1 fmt --all -- --check
cargo +1.97.1 clippy --locked --workspace --all-targets -- -D warnings
cargo +1.97.1 build --locked --workspace
cargo +1.97.1 test --locked --workspace
```

加上這三項，因為本 session 已證明它們各自抓到過單元測試抓不到的東西：

1. **語料逐份 verdict 比對**（不是總分——總分持平可能是一升一降）
   ```bash
   PC_BIN=$PWD/target/debug/pingclair python3 verification/day26/corpus.py
   ```
2. **對照官方 Caddy binary**（`verification/day26/caddy`，v2.11.4）：同一份設定文字
   兩邊只換 port，比 adapt 結果**與執行期回應**。`try_files` 的結尾斜線語意
   就是這樣抓到的，單元測試全綠而行為錯。
3. **判準取自上游原始碼**（`/Users/sinclairverlaine/code/caddy`，`ff6da121`），
   不是黑箱推論。**測試是 oracle，不是規格。**

新缺陷寫 `TRIAGE.md`，不折進當前 diff。
