# ⚠️ Pingclair 實作守則

> 動手改程式碼或跑驗證**之前**先讀這份。這裡記錄的都是踩過的坑，
> 不是理論建議——每一條後面都有一次實際失敗。
>
> - 接下來要做什麼 → `docs/TODO.md`（🔒 維護者本機文件，未進倉庫）
> - 已完成與驗證證據 → `docs/STATUS.md`
>
> 最後整理：2026-07-30

---

## 🧪 測試與除錯

- **自簽憑證測不出憑證鏈的缺陷。** 自簽憑證自己就是自己的簽發者，它**沒有**
  中繼憑證——「只送 leaf」和「送完整鏈」產生的位元組完全相同。所以任何用
  自簽 fixture 的 TLS 測試，對「伺服器把中繼憑證丟掉了」這類 bug 是**物理上
  不可觀測**的。2026-07-30 的雙區域公網驗證就是這樣抓到 H1／H2 只送 leaf：
  在那之前 474 個測試沒有一個可能發現它。要驗憑證鏈，fixture 必須是
  root → intermediate → leaf 的真實兩層信任路徑（`rcgen` 可以直接建，見
  `pingclair/tests/integration.rs` 的 `build_two_level_chain`），
  斷言用 client 端的 `peer_cert_chain().len()`。
- **瀏覽器不能當 TLS 憑證鏈的驗收工具。** Chrome 與 Firefox 會快取中繼憑證，
  也會用 AIA 自己去補抓缺少的那張，所以**伺服器少送中繼，瀏覽器照樣顯示綠鎖**。
  curl、Go、Java、Python requests 則會直接以
  `unable to get local issuer certificate (20)` 硬失敗。驗收要用嚴格 client，
  不要用瀏覽器「看起來正常」當證據。
- **本機 macOS 有系統代理 `127.0.0.1:1082`**；reqwest 整合測試必須 `.no_proxy()`，
  否則請求會被代理攔截，症狀看起來像路由錯誤。
- **本機 `dig` 會回假 IP。** 系統代理用 fake-IP DNS，直接 `dig example.com`
  得到的是 `198.18.x.x`，看起來像 DNS 還沒生效。查真實解析必須指定公開
  resolver：`dig @8.8.8.8 example.com`。
- **遇到固定 404／502 或 readiness 異常**，先用 `lsof`／`ss` 查 port owner，
  再查 child 是否已因 bind failure 退出。**不要先假設是路由邏輯錯誤**——
  這個誤判浪費過整輪除錯。
- **timeout 時必須先 kill＋wait，再讀 stdout/stderr 到 EOF**。
  順序反了會永久阻塞並留下幽靈程序。
- 真 binary 測試一律用**動態 port**與**唯一 readiness token**。固定 port 會讓
  舊程序被誤判為 ready，測試看似通過實則測到別的東西。
- **真 binary drill 必須設 `PINGCLAIR_TLS_STORE` 指向可寫目錄**，即使配置裡
  完全沒有 TLS。TLS manager 在讀配置前就無條件初始化，預設路徑不可寫時
  直接 panic（`PermissionDenied`），而 log 只有一行看不出跟 TLS store 有關。
- **`zsh` 不會對未加引號的變數做 word splitting**。`for x in "a 1" ...; set -- $x`
  在 bash 能拆成兩個參數，在 zsh 只會得到一個——症狀是 `$2` 空白，很容易誤讀成
  被測程式的問題。測試腳本改用明確參數的 function。
- **壓縮測試的 payload 必須逐 chunk 唯一且不可壓縮**。重複同一塊資料會被
  zstd 的 window 去重（64MiB → 15KB），讓「輸出有在流動」這類斷言**假性失敗**。
- **本機 gate 必須用 `cargo +1.88.0`,不是預設工具鏈**。CI 釘 `1.88.0`
  （`.github/workflows/rust.yml`），workspace 也宣告 `rust-version = "1.88"`,
  但本機預設可能新上好幾個版本。新編譯器的型別推論更寬鬆——`&[&String, &String,
  &str]` 這種混型陣列在 1.97 過、在 1.88 是 `E0308`。本機四項全綠然後 CI 全紅,
  就是這樣來的（2026-07-29）。`rustfmt` 的換行決策也隨版本變,所以 fmt 也要用
  同一個工具鏈跑。
- 🎩 **2026-07-31 起 `rust.yml` 的 `test` job 跑在 `fedora:latest` 容器裡**,
  跟 `deployment/Dockerfile` 同一個 base、同一份 rustup 釘版 1.88.0、同一份
  `dnf` 套件清單。理由是同一天先撞到的事：那份 Dockerfile 自從 H3 換
  tokio-quiche 之後**從沒被建過**,線上跑的 image 是依賴樹改變前建的,
  Rust 版本也早就跟 `Cargo.toml` 的宣告不一致。CI 跑在 Debian／ubuntu 上
  完全遮住這件事。**兩份套件清單必須手動保持同步**——CI 的 `dnf install`
  跟 Dockerfile builder stage 那份改一邊就要改另一邊,目前沒有機制強制同步,
  這條本身就是下一個可能重犯的坑。
- 🐳 **`rust.yml` 新增 `docker-image` job,真的建 `deployment/Dockerfile`
  並開機驗證**（`docker run ... version`、`docker run ... validate` 一份真
  Pingclairfile）。這是「一份沒人跑的建置腳本等於沒測試過的程式碼」這句話
  的直接對策——上面那次 Dockerfile 漂移,如果這個 job 當時存在,第一次
  push 就會紅。
- 🔒 **新增 `security-audit` job（`cargo audit`）,每次 push 都跑**,不只在
  發布前跑一次。RustSec 公告的時間不受這個專案控制,一個已合併但後來被公告
  漏洞的依賴,只有持續跑才抓得到。真的出現 finding 時的例外處理是**書面風險
  接受**（`docs/STATUS.md` Day 30 的既有規則),不是把這個 job 改成
  `continue-on-error`。
- **要在容器 log 裡看到 ERROR 以下的內容必須設 `RUST_LOG`**。subscriber 是
  `EnvFilter::from_default_env()` 建的，沒設等於只留 ERROR——症狀是功能明明
  正常卻「什麼都沒 log」。
- **grep 容器 log 前要先剝掉 ANSI**。tracing 的 fmt layer 即使 stdout 不是 tty
  也會給欄位名上色，`from=1.2.3.4` 實際上是 `from<ESC>[0m<ESC>[2m=<ESC>[0m1.2.3.4`，
  直接 grep 字面字串會**假性失敗**。
- **改 bind-mount 的單一檔案禁止用 `sed -i`**。bind mount 綁的是 **inode 不是路徑**：
  `sed -i` 寫新檔再改名蓋過去，宿主看到改動、**容器繼續讀舊 inode**。這個失敗
  完全無聲——reload 會回報「成功」（它確實重載了，只是內容一模一樣），於是
  「壞配置被拒」「last-known-good 還在」這類斷言**全部假性通過**。
  一律用 `cat new > target` 這種**原地截斷改寫**，並在演練開頭斷言
  `stat -c %i` 宿主與容器一致。2026-07-28 Day 7 實際踩到，兩條 ✅ 是假的。
- **`grep -q` 不要放在 `set -o pipefail` 的 pipeline 尾端**。命中即提前退出會把
  上游 SIGPIPE 掉，141 變成整條 pipeline 的狀態，**命中反而被讀成失敗**；
  而且只有輸出夠長才輸掉這個 race，所以會間歇性假性失敗。先存檔再 grep 檔案。
- **腳本收 results 目錄參數時要處理絕對路徑**。`-v "$(pwd)/$conf"` 遇到絕對路徑
  會變成 `/tmp//tmp/...`，Docker 靜默建一個空目錄當掛載點，程式起不來。
- **測 DNS 重解析時容器位址要用 `--ip` 明確指定**。讓 Docker 自己配，
  「backend 有沒有跟著搬」就變成看 daemon 的位址回收策略；只有在剛好拿到新
  IP 時才會過的測試不算測試。要製造「名稱解析不到但舊位址還健康」，用
  `docker network disconnect` 後再 `connect --ip <同一個位址>`（不帶 alias）——
  同一個容器、同一個位址，只是名稱查不到了。

---

## 🔗 依賴與鏈結

- **CI 與 Dockerfile 使用 stable Rust**。nightly 曾在 release profile
  （`panic="abort"` + fat LTO + `codegen-units=1`）編譯 tokio 時 ICE。
- **reqwest dev dependency 必須維持 rustls**。native-tls／OpenSSL 會與 quiche 的
  BoringSSL 產生連結衝突。
- **禁止引入 `pingora-openssl`、`openssl-sys` 或 reqwest `native-tls`**。
  `quiche 0.29`、`boring 4.22` 與 Pingora `boringssl` feature 是同一套 BoringSSL
  鏈結設計；過去曾因 OpenSSL／BoringSSL 符號衝突造成**啟動 SIGBUS 與 Linux link error**。
  這三條不是偏好而是 H3 的前提，理由見下方「為什麼 H3 釘在 quiche／BoringSSL」。

---

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
> 驗證,約 500 行。2026-07-30 全部刪除,換成 `tokio-quiche`（`561d802`）。
>
> **寫否決註解的規則**:必須寫下「哪一版、看了哪個符號、什麼日期」。
> 只寫結論的否決註解會變成一道沒人敢推的門。

> ⚠️ **要換回 Pingora 原生 H3 的前提**：#514 已合併進 released crate、
> `pingora-proxy` 有 H3 整合測試、且 BoringSSL 鏈結方式與現況相容。
> 三項缺一就不要動——代價是整份 `quic.rs` 重寫。

### 架構

> 📌 **2026-07-30（`561d802`）換掉了傳輸層。** 以下描述的是換完之後的樣子；
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
  Linux 那一半用 docker `rust:1.88-bookworm`。

> ✅ **`561d802` 的遷移已通過這一關**（2026-07-30，證據在
> `benchmarks/results/20260730_day28_f26d0a1/`）：Linux release build、
> 無 `openssl-sys`、無動態 `libssl`／`libcrypto`、Linux 454 測試全綠、
> 與 quiche 0.18 的 curl 跨版本互通、功能矩陣 14/14。

> ⚠️ **在 Linux 上建置需要 `cmake`（BoringSSL）與 `clang`／`libclang-dev`
> （bindgen）**。乾淨的 `rust:1.88-bookworm` 兩者都沒有，缺了會在
> `boring-sys` 的 build script 失敗。發布產物與 CI 環境都要帶上。
>
> 🐛 **還缺第三樣：`git`（2026-07-31 第一次真的建 production image 時撞到）。**
> `boring-sys` 在沒設 `BORING_BSSL_ASSUME_PATCHED` 時，會對 vendored 的
> BoringSSL 原始碼跑 `git init` 再套 patch（`ensure_patches_applied` →
> `Command::new("git")`）。沒有 `git` 執行檔就 panic 成
> `Os { code: 2, kind: NotFound }`——**訊息完全看不出跟 git 有關**，而且跟缺
> `clang` 的失敗長得幾乎一樣，所以第一次修錯了方向。
>
> 完整清單（Fedora 套件名）：`cmake gcc-c++ perl-interpreter
> pkgconf-pkg-config clang clang-devel git`。Debian 對應：`cmake g++ perl
> pkg-config clang libclang-dev git`。
>
> 📌 **這個坑之所以拖到現在才現形**：`deployment/Dockerfile` 自從 H3 換成
> tokio-quiche（`561d802`）之後**從來沒有人真的建過**。線上跑的
> `rc-a554477` image 是在依賴樹改變之前建的。一份不會被 CI 執行的建置腳本
> 就是一份沒有測試的程式碼。
>
> 🐛 **`-slim` 變體還缺第三樣：`git`（2026-07-31 首次建置 production image 時
> 撞到）。** `boring-sys` 的 build script 在沒有 `BORING_BSSL_ASSUME_PATCHED`
> 時，會對 vendored BoringSSL 原始碼跑 `git init` 再套用 patch
> （`ensure_patches_applied` → `Command::new("git")`）；沒有 `git` 執行檔會
> 直接 panic 成 `Os { code: 2, kind: NotFound }`，訊息完全看不出跟 git 有關。
> `deployment/Dockerfile` 用 `rust:1.88-slim-bookworm`（不是上面驗證過的
> 完整版 `rust:1.88-bookworm`），slim 版連 `git` 都沒有——這也是為什麼這個
> 問題直到現在才第一次出現：`561d802` 之後從沒有人真的建過這份 production
> Dockerfile。三個都要裝：`cmake g++ pkg-config clang libclang-dev git`。

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

## 🔐 安全預設

- 未受信來源**不得**偽造 `X-Forwarded-*`／`X-Real-IP`／`CF-Connecting-IP`。
- 錯誤配置一律 **fail closed**，不是靜默忽略。
- 敏感欄位（`Authorization`、`Cookie`、API key）在 log／metrics／Admin dump／panic
  訊息中**預設遮罩**。
- `insecure_skip_verify` 這類降級開關必須**顯眼且預設關閉**。
- **遞迴型別禁止用 `#[serde(untagged)]`**。newtype variant（`Not(Box<Self>)`）
  在 untagged 下會「把整個 payload 再當成一次自己解」而**不消耗任何輸入**，
  任何對不上其他 variant 的值都會無限遞迴；serde 的 untagged replay 不會再經過
  serde_json 的 parser，所以 serde_json 的 recursion limit 攔不到，`panic = "abort"`
  的 release binary 直接中止。這在 `Matcher` 上是可由 Admin API 遠端觸發的
  DoS（2026-07-28 修）。遞迴 enum 一律用 tag 表示。
- **設定規則必須擋在 core config 層，不能只擋 Pingclairfile adapter**。
  Admin API 直接把 config document 反序列化進 core 型別，**完全不經過 adapter**。
  只寫在 `adapter/caddyfile.rs` 的檢查等於留了一條繞道。矛盾或半套的設定
  （`insecure_skip_verify` ＋ pinned CA、只有 cert 沒有 key）兩條路都要拒。
  2026-07-29 Day 11 上游 TLS 依此同時補了 `compiler::validate_config`。
- 🎯 **把規則寫進 `validate_config` 不等於那條路徑會執行它。** 上面那條規則
  被遵守了，結論卻仍然是假的：Day 11 與 per-listener `proxy_protocol` 都
  正確地把規則加進 `compiler::validate_config`，並在 commit message 與這份
  文件寫下「Admin 這條路也擋住了」——**而 Admin API 從來沒呼叫過那個函式**
  （2026-07-30 Day 17 修）。測試呼叫的是**函式**，真正的**路徑**沒經過它。
  加了規則之後，要沿著每一個入口追到底確認它真的被叫到；否定測試要打真正的
  介面（真的 POST 進 Admin socket），不是呼叫驗證函式。
- 🎯 **`panic = "abort"` 只設在 release profile，所以測試抓不到 abort。**
  debug 是 unwind，一個 `unwrap()` 只會炸掉該連線的 task，伺服器照樣活著。
  於是「伺服器還在嗎」這種斷言，對著它要抓的 panic 也會通過——2026-07-30
  我就寫出過這種測試。要驗 panic，檢查子程序 stderr 有沒有 `panicked at`，
  這個訊號在兩種 profile 下都成立。
- **listener 層級的開關不要做成全域**。PROXY protocol 一度是 `global.proxy_protocol`，
  開了之後每個 listener 都要求 header，直連的那個就全掛。nginx 是
  `listen 443 proxy_protocol;`、Caddy 是 per-server listener wrapper，兩者都不是
  全域，因為真實部署常常一個 port 在 L4 LB 後面、另一個直連。
  順帶一提，`listen` 以前會**靜默丟棄多餘參數**，所以 `listen :443 proxy_protocol`
  會產生一個「名字寫了但其實不要求」的 listener——跟 `encode gzipp` 同一類。
  2026-07-30 在凍結 RC 前改掉:**已知是錯的設定介面不要拿去做遠端驗證**，
  發布之後就改不動了。
- **在 Pingora listener 前面再加一層自己的 ingress，會讓 Pingora 那層的
  admission control 失去意義**。Day 14 的 PROXY protocol 把 Pingora app 搬到
  私有 loopback listener，前面自建 ingress；`limits { max_connections }` 由
  `ResourceGuardedProxy` 持有,於是它只再管**內部那一跳**，外部連線變成無上限。
  Pingora 回的 503 也救不了——外部 socket 屬於 ingress 不屬於 Pingora。
  **任何自建的 accept loop 都必須自己帶上同一個上限**，而且信任檢查要放在
  取 permit **之前**，否則未受信的洪水會吃掉留給真流量的額度。
  2026-07-30 Day 14 review 修，證據見
  `benchmarks/results/20260730_day14_review_failed_ingress_limit/`。
- **`HttpHealthCheck` 只替換位址，其他全部沿用 `peer_template`**。SNI、`Host`、
  TLS 素材都來自那個 template，而 template 通常是用 **first backend** 建的。
  所以 backend 名字不同的 pool（`to https://a.internal` ＋ `to https://b.internal`）
  會用 a 的 SNI 去探 b，hostname 驗證必定失敗、b 被永久摘除，但它服務正常——
  正常流量走 `build_http_peer`，用的是各自的 `HostName` ext。
  探測時一定要讀 `target.ext.get::<HostName>()`。這個 bug 在單一 backend、
  同名 backend 或純 HTTP pool 上**完全看不出來**，也就是幾乎所有既有測試。
  2026-07-30 Day 12 review 修。
- **Pingora 的 `HttpPeer` reuse hash 沒有算 `options.ca`**。它算了 client cert、
  `verify_cert`／`verify_hostname`／`alternative_cn`、SNI 與 `group_key`，
  但 **CA bundle 不在裡面**。同位址同 SNI、trust roots 不同的兩條 route 會共用
  pooled connection，嚴格那條會沿用寬鬆那條驗過的 session（reuse 直接跳過
  handshake）。任何新的「誰可以被信任」維度都必須自己打包進 `group_key`。
  Pingclair 的做法：protocol group 佔低 8 bits，TLS identity hash 左移進高位，
  用 `peer_protocol_group()` 取回協定，不要再直接比較 `group_key == 4`。
- **BoringSSL 在設定期接受不匹配的 cert/key**，只有 handshake 才失敗，
  而上游回的 `bad certificate` alert 跟十幾種無關的網路錯誤長得一樣。
  載入 client identity 時一定要自己驗 `cert.public_key()?.public_eq(&key)`，
  並在錯誤訊息裡**同時點名兩個檔案**——半套輪替（只換憑證沒換 key）就是靠這個抓的。
- **`trusted_ca_certs` 是取代不是疊加**。Pingora 走
  `SSL_set1_verify_cert_store`，會覆蓋整個 store 而非附加。這是我們要的語意
  （pin 內部 CA 的 route 不該同時接受公開 CA 簽的同名憑證），但必須寫在文件裡，
  否則會被誤讀成「額外信任」。
- **untagged 也代表「不可還原」**。variant 只靠 payload 形狀辨識，形狀相同的
  variant round-trip 後會變成別人——`Not` 甚至會整個消失，直接反轉路由決策。
  凡是會被序列化回去的設定型別（Admin dump→post、config 檔）都必須有 tag。

---

## 📁 驗證證據

- 結果寫進 `benchmarks/results/<date>_<commit-prefix>/`。
- **失敗的證據不可覆寫**。修好之後另開目錄，保留舊的失敗紀錄作為對照。
- 驗證必須記錄**完整 commit SHA**，不能只寫「最新版」。
