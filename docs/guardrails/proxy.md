# ⚠️ Pingclair 實作守則 — Proxy、HTTP/3 與串流

## 🚀 HTTP/3 實作護欄

### 為什麼 H3 釘在 quiche／BoringSSL（不要再重問這題）

**Pingora 不提供 H3，而且短期內不會提供。** 核查於 2026-07-27：

| 上游 | 狀態 |
|---|---|
| [pingora#95](https://github.com/cloudflare/pingora/issues/95) HTTP3/QUIC Support | 2024-03-02 開，**仍 open**，官方標籤 **`Long Term Goal`**（"plan to support but not likely in the near future"） |
| [pingora#514](https://github.com/cloudflare/pingora/pull/514) server／listener 側 quiche::h3 | +3,449 行／30 檔，2025-01-16 開，**未合併**，2025-08-27 後停滯 |
| [pingora#524](https://github.com/cloudflare/pingora/pull/524) client／connector 側 | +6,548 行／52 檔，2025-02-03 開，**未合併**，2025-02-07 後停滯 |

社群已經把 server 端寫完了，掛了一年半沒合。所以「等上游」不是一個有期限的選項。

**結構性阻礙是 TLS 後端,不是工作量。** quiche 只跑在 BoringSSL／QuicTLS 上，
pingora-core 預設 OpenSSL，兩者符號直接衝突。要 H3 就得把**整棵依賴樹**
釘死在 BoringSSL——這是全域且不可逆的架構決定，不是加個 feature flag。
上面「依賴與鏈結」那三條禁令全部源自這個決定。

> 🚨 **「評估過並否決」的註解,如果沒有留下可驗證的依據,比沒有註解更糟。**
> `Cargo.toml` 曾經寫著「tokio-quiche was evaluated and rejected: its
> server-side accept API is pub(crate)」。**這句是錯的**,而且錯在最有害的地方:
> 它讓後來的人不再去看。實際上只有內部的 `quic::start_listener()` 是
> `pub(crate)`,公開 facade 一直都在——2026-07-30 對 `tokio-quiche 0.19.1`
> 實測:`tokio_quiche::listen()`（`lib.rs:191`）、`ServerH3Driver`、
> `ServerH3Controller`、`InitialQuicConnection`、`ApplicationOverQuic` 全部公開。
> 依賴版本也完全對齊（`quiche 0.29.3`＋`boring 4.22.0`,無 `openssl-sys`）。
>
> **代價已經付掉了**:那句話的存在讓這個專案手寫並維護了一整套 QUIC 傳輸層
> ——socket 迴圈、connection map、計時器、版本協商、stateless retry 與 token
> 驗證,約 500 行。2026-07-30 全部刪除,換成 `tokio-quiche`（`ba37ffc`）。
>
> **寫否決註解的規則**:必須寫下「哪一版、看了哪個符號、什麼日期」。
> 只寫結論的否決註解會變成一道沒人敢推的門。

> ⚠️ **要換回 Pingora 原生 H3 的前提**：#514 已合併進 released crate、
> `pingora-proxy` 有 H3 整合測試、且 BoringSSL 鏈結方式與現況相容。
> 三項缺一就不要動——代價是整份 `quic.rs` 重寫。

### 架構

> 📌 **2026-07-30（`ba37ffc`）換掉了傳輸層。** 以下描述的是換完之後的樣子；
> 手寫的 UDP 迴圈與無鎖 connection map 已經不存在。

- **分界線是傳輸／應用。** `tokio-quiche` 擁有 UDP socket、封包解析、版本協商、
  stateless retry 與位址驗證、connection-ID 路由、GSO、pacing、每連線計時器。
  `pingclair-proxy/src/quic.rs` 只保留應用層。
- 每條連線由 `H3App` 驅動，它是本專案的 `ApplicationOverQuic` 實作。
  **它不是 Pingora `ProxyHttp Session` 的延伸**。
- **`tokio-quiche` 不管的兩件事必須留在 accept 迴圈**：L4 blocklist 與
  listener 的 `max_connections`。連線數由 `ConnectionSlot` 在 drop 時釋放，
  所以是 worker task 結束時才減,不是 accept 迴圈往前走時就減。
- 憑證**永遠不落盤**。`ConnectionParams` 要求一個 `TlsCertificatePaths`，但那組
  路徑只會被交給 `ConnectionHook`；真正讀檔的 `quiche_config_with_tls` 是 hook
  回傳 `None` 時才走的分支。所以我們傳 `IN_MEMORY_CERT_SENTINEL` 這個假路徑，
  憑證留在記憶體的 `CertTable` 裡。
  **不得為了滿足型別而把私鑰寫進暫存檔**——那是安全倒退，不是變通。
- middleware parity 應抽出 **transport-neutral 邏輯**（見 `http_policy.rs`），
  不可硬把 H1/H2 Session 塞進 H3。

> ⚠️ **`tokio-quiche` 版本釘死在 `=0.19.1`。** 上面「憑證不落盤」那條依賴的是
> 0.19.1 原始碼裡 `settings/config.rs:122` 的 `.zip(params.tls_cert)` 與
> `settings/config.rs:224` 的讀檔分支。minor 版本一升就可能開始真的去讀那組
> 路徑。要升版**必須先重讀這兩處**，並確認
> `pingclair-proxy/tests/h3_in_memory_certs.rs` 仍然紅字先行會掛。

### 正確性

- **request body drain 必須在 pump 之前重試,而且不能只由收包驅動**。
  `h3::Connection::recv_body` 會在最後一段 body 被消化時才在內部排入 `Finished`,
  所以一個因為 handler channel 滿而中止的 drain,若不重試就永遠等不到結束訊號
  ——大型 POST 會**永久卡住**。現在這條由 `H3App::process_reads` 保證：
  它先重試 `body_read_pending` 的串流,再 `pump_h3_events`。
  （舊結構是「收包 ＋ maintenance pass 都要 pump」,maintenance pass 已隨手寫
  迴圈一起刪除,但要求本身沒變。）
- H3 憑證表以 `ArcSwap` 發佈，透過 `TlsManager::peek_pem` 讀取既有憑證並每 60 秒刷新。
  **`peek_pem` 不可觸發 ACME 簽發**。
- 🚫 listener port、憑證 domain 清單等 topology 在啟動時擷取。
  Admin／signal reload 若新增或刪除它們，必須整份回
  `restart_required`，不得啟動只有 TCP 而缺 H3／mTLS／resumption 政策的
  side listener，也不得 autosave 或回報成功。

### 資源

- H3 request／response body 必須維持 **bounded channel、QUIC flow control 與串流**。
  不可為了 middleware parity 改成全量緩衝。
- **0-RTT early data 已預設停用**：reverse proxy 支援非冪等方法且尚無 replay protection。
  在 route/method policy、replay 語意與負向測試完成前**不得重新開啟**。

### 驗證

- 修改 H3 或 TLS dependency 後，至少以 **Linux release binary＋quiche client** 重跑：
  Alt-Svc、SNI、多大小靜態／代理 body、含／不含 Content-Length 的 POST、413、
  upstream keepalive。
- **macOS 單元測試不足以驗證鏈結與 QUIC 行為。**

- 跑這一關用 `scripts/test-h3-day28-local.sh`（功能矩陣，需要支援 HTTP/3 的
  curl）與 `scripts/test-h3-cancellation-local.sh`（SSE／取消／trailer）。
  Linux 那一半用 docker `rust:1.97-bookworm`。

> ✅ **`ba37ffc` 的遷移已通過這一關**（2026-07-30，證據在
> `benchmarks/results/20260730_day28_f26d0a1/`）：Linux release build、
> 無 `openssl-sys`、無動態 `libssl`／`libcrypto`、Linux 454 測試全綠、
> 與 quiche 0.18 的 curl 跨版本互通、功能矩陣 14/14。

> ⚠️ **在 Linux 上建置需要 `cmake`（BoringSSL）與 `clang`／`libclang-dev`
> （bindgen）**。乾淨的 `rust:1.97-bookworm` 兩者都沒有，缺了會在
> `boring-sys` 的 build script 失敗。發布產物與 CI 環境都要帶上。
>
> 🐛 **還缺第三樣：`git`（2026-07-31 第一次真的建 production image 時撞到）。**
> `boring-sys` 在沒設 `BORING_BSSL_ASSUME_PATCHED` 時，會對 vendored 的
> BoringSSL 原始碼跑 `git init` 再套 patch（`ensure_patches_applied` →
> `Command::new("git")`）。沒有 `git` 執行檔就 panic 成
> `Os { code: 2, kind: NotFound }`——**訊息完全看不出跟 git 有關**，而且跟缺
> `clang` 的失敗長得幾乎一樣，所以第一次修錯了方向。
>
> 完整清單（當時 Fedora 套件名）：`cmake gcc-c++ perl-interpreter
> pkgconf-pkg-config clang clang-devel git`。Debian 對應：`cmake g++ perl
> pkg-config clang libclang-dev git`。
>
> 📌 **這個坑之所以拖到現在才現形**：`deployment/Dockerfile` 自從 H3 換成
> tokio-quiche（`ba37ffc`）之後**從來沒有人真的建過**。線上跑的
> `rc-a554477` image 是在依賴樹改變之前建的。一份不會被 CI 執行的建置腳本
> 就是一份沒有測試的程式碼。（當時 Dockerfile 基底是 slim bookworm 變體,
> 連 `git` 都沒有；現已改為 ubuntu:latest ＋ rustup,套件清單見上方。）
>
> 📌 **端對端測試（`pingclair-proxy/tests/h3_end_to_end.rs`）用的是手寫 quiche
> client**，它證明的是我們的事件迴圈對 quiche 協定實作正確，**不證明互通性**。
> 互通性要靠上面那兩支腳本裡的真 curl，而且刻意用不同的 QUIC 實作
> （ngtcp2／nghttp3，以及 quiche 0.18）。

---

## 🧵 串流與記憶體

專案歷史上出現過兩次同類 bug（反代 gzip、靜態檔 gzip），都是「全量緩衝」造成的。

- 任何壓縮、retry、middleware 或觀測功能**都不得重新引入全量 body buffering**。
- 大 body、SSE、range 與 client disconnect cancellation 必須維持 bounded memory。
- 新增會碰 response body 的功能時，預設要問：**這在 20MB body 下會發生什麼？**

### 🧱 唯一一個刻意緩衝的地方，以及它為什麼不會變成同一個 bug

`request_buffers`／`response_buffers`（`pingclair-proxy/src/body_buffer.rs`，
2026-08-13）是這份文件唯一允許的例外，條件是**上限由我們決定，不是由設定決定**：

- **`unlimited` 不是無上限。** 上游對 `-1` 的語意是整份讀進記憶體，它自己在載入
  時就印 `UNLIMITED BUFFERING … can result in OOM crashes`。我們把 `-1` 讀成
  「緩衝到 `MAX_BUFFERED_BODY_BYTES`（8 MiB）為止」，超過就**回到串流**。設定
  能調的是這個數字以下的值，不能調到以上。
- **超過上限要退回串流，不是拒絕。** 緩衝是相容性與延遲的旋鈕，不是限制；會
  拒絕過大 body 的是 `request_body max_size`，它自己 fail closed。把緩衝旋鈕
  變成 413 產生器，是往貴的那個方向給操作者驚喜。
- **限制、deadline、pacer 都跑在「收到的位元組」上，不是跑在「決定送出的位元組」
  上。** 順序寫反的話，打開緩衝就等於把整條路由的 `client_max_body_size` 悄悄
  調高了。

> 🪤 **request 側扣住 chunk 要交回空的 `Bytes`，不能交 `None`。**
> `pingora-proxy 0.8.1` 的 `proxy_h1.rs:774` 在 filter 跑完之後才用
> `end_of_body || data.is_none()` 重算結束旗標，所以 `None` 會被讀成「客戶端送完了」
> ——upstream 的 body 提早結束，沒有任何錯誤，後端拿到一份被截斷的 body。
> response 側的結束旗標是隨 task 傳的（`lib.rs:382`），`None` 在那邊安全，
> 但兩側一律寫空 `Bytes`：有例外的規則就是會被記錯的規則。

> 🚫 **不要再設計「溢出到暫存檔」。** 2026-08-13 查過：filter 一次只能交回一塊，
> 而 downstream body 結束後（`proxy_h1.rs:411` 的
> `DownstreamStateMachine::maybe_finished`）filter 就不會再被呼叫。所以溢出到檔案
> 的 body 仍然得整份讀回記憶體才交得出去，**尖峰記憶體和不寫檔完全一樣**，只多
> 一個檔案描述符與權限面。從 filter 裡直接寫 session 也否決了：downstream body
> writer 的 framing 狀態屬於 `proxy_h1.rs:1209` 的 task pipeline，插進第二個 writer
> 會壞掉 chunked framing，而且壞得不會有測試穩定抓到。

---

## 🩺 上游健康：只有遠端失敗可以把 backend 標成不健康

反向代理是靠「連不上」來認識後端的，所以連線失敗會讓那個後端被踢出輪替十秒
——這件事本身完全正確。**但不是每一次連線失敗都是關於後端的證據。**

本機沒有檔案描述符的時候，`socket()` 在任何一個封包離開這台機器之前就失敗了。
後端是健康的、閒著的、而且完全不知道發生過什麼事。把這個當成「後端掛了」，
等於**因為我們自己耗盡了資源而懲罰一個正常的後端**——而單一後端的路由沒有東西
可以 failover，於是整條路由在冷卻期內停止服務。

2026-08-11 在 `4ed66ec` 上實測（證據 `benchmarks/results/20260811_fd_exhaustion_4ed66ec/`，本地）：
**5 次**本機 `socket()` 失敗造成 **139 次**請求被拒，而且負載停止、描述符全數歸還、
後端完全閒置之後，單一探測請求**連續九秒**回 502。放大 27 倍。

> 🎯 **規則**：任何新的「連線失敗 → 標記後端」站點，都必須先問
> `crate::upstream_failure::classify_*` 拿到的 `FailureOrigin`，
> 而且只在 `implicates_backend()` 為真時才標記。

政策放在 `pingclair-proxy/src/upstream_failure.rs`，**一份**，兩個 transport
共用，reverse proxy 與 FastCGI 也共用。目前五個站點：
`server.rs` 的 `fail_to_connect` 與 FastCGI 撥接、`quic.rs` 的 H3 上游連線、
h2 ALPN 不符、與 H3 FastCGI 撥接。

### 🪤 照直覺寫的修法是死程式碼

```rust
// ❌ 永遠不會 match。
match error.etype() {
    ErrorType::SocketError | ErrorType::BindError => { /* 本機問題，跳過 */ }
    _ => mark_down(),
}
```

`pingora-core` 0.8.1 的 `connectors/l4.rs:151` **在回傳之前**就把
`SocketError` 與 `BindError` 改寫成 `InternalError`，真正的名字只留在 cause chain 裡：

```text
Upstream InternalError context: Fail to connect to addr: 127.0.0.1:19000
  cause: SocketError context: failed to create socket
  cause: Too many open files (os error 24)
```

所以要 match 的是 **`InternalError`**。上面那個寫法會通過 review、會編譯、
會出貨，然後什麼都不改變——而下一個人會因此結論說「分類理論本來就是錯的」。

📌 **`InternalError` 涵蓋的不只有 EMFILE**：ephemeral port 耗盡走 `BindError`，
在忙碌的代理上比 EMFILE 更常見；`EACCES`／`EADDRINUSE` 與 TLS **設定**類錯誤
（讀不到憑證庫、client key 無效）也在同一格。

⚠️ **未知的 errno 維持判成 remote**（`ConnectError` 是 connector 的 catch-all）。
這是刻意的保守選擇：判錯的代價是後端多留在輪替裡一下子，而不是健康的後端
因為不是它的錯而被踢掉。

### 🧪 為什麼單元測試不夠

`upstream_failure.rs` 的單元測試斷言的是**它自己造出來的**錯誤值。那證明了分類器，
沒有證明分類器依賴的那個前提：真正的 `EMFILE` 真的會以塌掉的 `InternalError`
形狀從 Pingora 的 connector 送過來。只有真的把描述符耗盡、真的穿過 connector
才驗得到——`pingclair/tests/integration.rs` 的
`test_local_descriptor_exhaustion_does_not_mark_the_backend_down` 用
`pre_exec` 對**子行程**設 `RLIMIT_NOFILE` 做這件事，所以測試框架自己的描述符不受影響。

⚠️ **H3 目前沒有對應的執行期負向測試**，因為 `h3_end_to_end.rs` 是 in-process 的，
降 `RLIMIT_NOFILE` 會毒害同一個二進位裡的每一個測試。H3 那半目前靠共用分類器 ＋
H1/H2 那支證出來的錯誤形狀 ＋ `h3_refused_backend_still_fails_closed`（遠端那半）。
這個缺口記在 TRIAGE，不要當成已驗證。

## 🔀 兩個 transport 的 parity，兩種走光的方式

兩條路徑各自缺一塊的情形，2026-08-11 一次量到兩個，兩個都在 H3 這邊，
而且兩個都是**「H1/H2 那一側的多做了一步，H3 這側沒做」**：

- **rewrite 的目標是模板，H3 沒有展開它。** H1/H2 的 `HandlerConfig::Rewrite`
  會先跑 `resolve_caddy_placeholders`；`quic.rs` 直接把 `replace` 原樣送進
  `rewrite_request_uri`。於是 HTTP/3 把 URI 改寫成字面上的
  `{http.matchers.file.relative}`，後面的 file server 對每個請求都 404
  ——整個單頁應用寫法，無聲，而且只在 HTTP/3 上。
- **matcher 的第三種答案，H3 只認兩種。** `file` matcher 的 `=404` 候選回傳的是
  `MatcherVerdict::Error`，H3 的 element matcher helper 回傳 `bool`，
  於是 `Error` 塌成 no-match：同一份設定 HTTP/2 回 404、HTTP/3 往下一個 handler 走。

  > 🎯 **可操作的規則**：讓一個 helper 回傳 `bool`，就是在宣稱這個問題只有兩種
  > 答案。哪天多出第三種（這裡是「拋出狀態」），編譯器**不會**去問所有呼叫端
  > ——`bool` 版本會安靜地繼續編譯。共用型別要共用到**回傳型別**那一層。

兩個都不是「H3 忘了實作某個 handler」——那種缺口很顯眼，會回 501。
這兩個是**同一個 handler 在兩邊做的事情不一樣**，兩邊都回 200 或 404，
差別只在內容。所以：

> 🎯 **可操作的規則**：碰 `server.rs` 裡任何一個 `HandlerConfig::` arm 時，
> 把 `quic.rs` 的同名 arm 並排讀一次。兩邊都存在**不代表**兩邊做一樣的事，
> 而測試只有在真的送出請求、真的比對 body 的時候才看得出來
> （`h3_end_to_end.rs` 要走 `pingclair_config::compile`，不要手寫 `HandlerConfig`
> ——手寫的那份會跳過 adapter，而 adapter 正是差異的來源）。
