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
- listener port、憑證 domain 清單等 topology 主要在啟動時擷取；
  新增項目**不得假設 hot reload 已完整生效**。

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

---

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
