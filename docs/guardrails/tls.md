# ⚠️ Pingclair 實作守則 — TLS、依賴與安全預設

## 🔗 依賴與鏈結

- **CI 與 Dockerfile 使用 stable Rust**。nightly 曾在 release profile
  （`panic="abort"` + fat LTO + `codegen-units=1`）編譯 tokio 時 ICE。
- **reqwest dev dependency 必須維持 rustls**。native-tls／OpenSSL 會與 quiche 的
  BoringSSL 產生連結衝突。
- **禁止引入 `pingora-openssl`、`openssl-sys` 或 reqwest `native-tls`**。
  `quiche 0.29`、`boring 4.22` 與 Pingora `boringssl` feature 是同一套 BoringSSL
  鏈結設計；過去曾因 OpenSSL／BoringSSL 符號衝突造成**啟動 SIGBUS 與 Linux link error**。
  這三條不是偏好而是 H3 的前提，理由見下方「為什麼 H3 釘在 quiche／BoringSSL」。

- 🔓 **`boring-sys` 是直接依賴，而且版本必須跟著 `boring` 一起動。**
  `boring` 4.22 沒有包裝 `X509_STORE_CTX_set_purpose`，而下游 mTLS 需要它
  （理由見「下游 mTLS」那節），所以 workspace 直接宣告
  `boring-sys = "4.22"` 與 `foreign-types = "0.5"`——後者是為了拿到
  `ForeignTypeRef::as_ptr`，`boring` 只 `extern crate` 沒有 re-export。
  ⚠️ **兩份 `boring-sys` 就是兩份 BoringSSL**，也就是上一條講的那種符號衝突。
  兩邊都用 caret range 是刻意的：它們會一起解析到同一版。`boring` 需要換大
  版本的那天，這一行必須同時換。
  📌 檢查方式跟原本一樣，沒有新增：`cargo tree -i boring-sys` 必須只有一份，
  `cargo tree -i openssl-sys` 必須什麼都不符合。

- **fork 上游 crate 前，先量到數字，而且要量在它是瓶頸的環境。**
  2026-08-04 一次砍掉兩個 fork（`pingora-core`、`pingora-http`，共 38,532 行）。
  兩者機制論證都成立，但都沒有一次「被 patch 的東西是飽和資源」的量測撐著：
  `pingora-core` 把累計配置砍掉 86 %，吞吐 +0.9 %（雜訊內）、RSS 區間完全重疊。
  第一版壓測甚至是無效的——nginx 打滿 200 % 配額而 Pingclair 還有餘裕，量到的
  是後端。**現在的規則：A/B 每輪都要記錄三方 CPU，proxy 不是飽和的那層就丟掉該輪。**

- **`[patch.crates-io]` 會讓 crate 對 `cargo audit` 隱形。**
  patch 之後 lockfile 條目失去 `source` 與 `checksum`，而 cargo-audit 只回報
  能追回 crates.io 的套件。2026-08-04 直接驗證過：`atty 0.2.14` 專案會報
  RUSTSEC-2021-0145 與 RUSTSEC-2024-0375，同一個專案把 `atty` path-patch 之後
  **什麼都不報、乾淨退出**。`security-audit.yml` 因此多跑一次「剝掉 patch
  區塊、重產 lockfile、再 audit」——任何新的 `[patch]` 都必須同時確認這條路徑
  仍然涵蓋它。

- **`target/` 會無聲長到吃光磁碟；cargo 從不回收舊產物。**
  2026-08-04 量到 77 GB（`incremental` 41 GB、`deps` 44 GB／252,603 個檔案），
  當時整顆磁碟只剩 12 GiB 可用。`cargo clean` 一次回收 113 GB。
  **例行處置：`cargo sweep --time 7`**（已安裝 `cargo-sweep`），砍掉七天以上
  沒被碰過的產物又不影響日常迭代；磁碟吃緊時才用 `cargo clean`。
  注意 `target/integration-linux` 是 pingora#946 的重現 binary，clean 前要留。

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

## 🪪 下游 mTLS（`tls client_auth`，2026-08-10 K3）

- **設定解析得過不等於握手擋得住。** `client_auth` 一度完整解析、完整編譯，
  而握手路徑上**沒有任何程式碼讀它**——站台在設定與日誌裡都宣稱雙向 TLS，
  實際上放行整個網際網路。所以那段期間 `run.rs` 選擇**拒絕啟動**：
  這類「宣稱有、實際沒有」的失敗，比乾脆不支援更糟。
  📌 判準：新增任何安全開關時，找出**真正執行它的那一行**；找不到就別接受它。

- **四個 mode 必須用 custom verify callback，不能用 BoringSSL 內建驗證。**
  BoringSSL 內建只有一種答案（「建得出信任路徑，否則失敗」），
  而 `request` 與 `require` 刻意不要驗。把它們交給內建驗證器，
  會拒絕掉操作者明確要放行的客戶端。
  對照表（`SSL_set_custom_verify` 的 mode 位元）：
  `request` = `PEER`；`require` = `PEER|FAIL_IF_NO_PEER_CERT`；
  `verify_if_given` = `PEER` ＋ callback 驗；
  `require_and_verify` = `PEER|FAIL_IF_NO_PEER_CERT` ＋ callback 驗。
  空憑證由 mode 位元自己處理（`tls13_server.cc:1102` 的 `allow_anonymous`），
  callback 只在客戶端**真的送了憑證**時才會被呼叫。

- 🎯 **自訂 verify callback 的代價：purpose 檢查不會自己跑，要自己開。**
  上一條選了 custom callback，這條是它的帳單。`X509_verify_cert` 只有在
  **有人指定 purpose** 的時候才會查憑證自己宣告的用途
  （`x509_vfy.c:570`：`if (ctx->param->purpose > 0 && X509_check_purpose(...))`），
  而新建的 `X509_STORE_CTX` 的 purpose 是 0。於是「這條鏈建得起來嗎」的答案
  被當成「這張憑證可以當 client 嗎」的答案。
  **後果**：私有 CA 最常見的用法就是一個 CA 簽全公司——那麼每一台
  `serverAuth` 的伺服器憑證，都是一張可用的 client 身分。
  做法是在 `verify_cert()` 之前呼叫
  `X509_STORE_CTX_set_purpose(ctx, X509_PURPOSE_SSL_CLIENT)`。
  ⚠️ `boring` 4.22 沒有包裝它，`X509VerifyParamRef` 有 `set_flags`／`set_host`／
  `set_depth` 就是沒有 `set_purpose`，而它的 `boring_sys` 是私有
  `extern crate`——所以這裡直接依賴 `boring-sys` 與 `foreign-types`。
  版本必須跟著 `boring` 走，否則樹裡會有兩份 BoringSSL。
  📌 順手查過但**沒有**改變的一件事：`set_purpose` 同時會把 context 的 trust
  設成該 purpose 的預設值 `X509_TRUST_SSL_CLIENT`。對一般 PEM 載進來的 CA
  來說結果一樣——舊值與新值都落到 `x509_trs.c` 的 `trust_compat`，
  自簽就信、其餘不信。只有帶 `X509_CERT_AUX`（罕見的
  `TRUSTED CERTIFICATE` 區塊）的 PEM 才分得出兩者。
  🤡 有一個會讓人愣住的邊界：只寫 `anyExtendedKeyUsage` 的 leaf **會被拒**。
  BoringSSL 給 `any` 自己的 bit（`XKU_ANYEKU` 0x100），而 SSL-client 檢查看的是
  `XKU_SSL_CLIENT`（0x2）。這是照抄函式庫的行為，不是我們的選擇——要在這裡
  特判，就等於在人家的 purpose 邏輯旁邊再寫一份自己的。
  🎯 四個回歸測試（`client_auth.rs`）先驗過 red：拿掉那一行 `set_purpose`，
  四個全紅、其餘八個全綠。另有一個真握手的 H3 測試
  `h3_client_auth_refuses_a_certificate_issued_only_for_servers`。

- **信任 store 要在啟動時建好，握手只借用。**
  `SslRef::set_verify_cert_store` 走 `SSL_set0_verify_cert_store`，
  **接管所有權**，而 boring 的 `X509Store` 沒有 `Clone`——照著寫就是每次握手
  重建整個 store。改用 `X509StoreContext::init(&store, leaf, chain, …)`，
  它只要 `&X509StoreRef`，於是每條連線只付一個 `Arc` clone。

- **server 端的 `peer_cert_chain()` 不含 leaf，client 端含。**
  BoringSSL 自己在 `ssl.h:1609` 用 `WARNING:` 標了這件事。
  剛好就是 `X509_STORE_CTX_init(ctx, store, leaf, intermediates)` 要的那組參數，
  搭配 `peer_certificate()` 取 leaf。寫成 client 端的直覺會少驗一層。

- 🛡️ **有 mTLS 的 listener 必須強制 SNI 與 `Host` 同名。**
  admission 由 ClientHello 決定，routing 由 `Host` 決定——兩者可以不同。
  同一個 socket 上放一個要憑證的站台和一個不要的，攻擊者就用不要憑證的名字
  握手、用要憑證的名字下 `Host`。上游偵測到 client auth 時會自動開啟
  `strict_sni_host` 正是為此，回 `421` 並關連線。
  ⚠️ **沒送 SNI 的客戶端在這種 listener 上一律拒絕**：它什麼都沒指名，
  就不可能指名了現在要求的那個站台。

- 🚫 **有 mTLS 的 listener 要關掉 session resumption。**
  resumed handshake 不送 `CertificateRequest`（`tls13_server.cc:818`
  只在 `!session_reused` 時設 `hs->cert_request`），BoringSSL 從 ticket
  還原 peer chain 之後**不會重驗**。於是憑證過期、被撤銷，或 trust pool 換掉
  之後，舊 ticket 仍然放行。代價是這個 listener 每條連線都走完整握手，
  這是刻意付的。Go 的 `crypto/tls` 有同樣性質，上游是靠
  `VerifyConnection`（每條連線都跑，含 resumed）補的；
  BoringSSL 沒有等價 hook，所以我們關 resumption。

- 🛡️ **兩個 transport 必須給同一個答案，而它們是兩套 TLS 設定。**
  H1/H2 走 Pingora acceptor 的 `cert_cb`，H3 走 `tokio-quiche` 的
  `set_select_certificate_callback`——**QUIC 根本不跑 `cert_cb`**。
  兩邊都在「ClientHello 已知、`CertificateRequest` 未送」的那個窗口裡，
  所以同一份 `CompiledClientAuth` 可以直接掛上去。

- 🔄 **mTLS trust pool reload 必須帶 generation，不是只換 callback。**
  TCP keep-alive 與 QUIC 連線可以在 reload 前已完成握手；只讓新握手讀新
  CA，就會讓舊憑證繼續在既有連線上授權。握手必須記住
  listener-security generation，request 時與現行 generation 比對；不一致就回
  `421` 並要求重新連線。啟動時沒有 mTLS 的 TLS context 已可能發出可
  resume 的 ticket，所以後來啟用 mTLS 必須回 `restart_required`，不可假裝
  hot-apply。
  📌 政策編譯層因此住在 `pingclair-proxy/src/client_auth.rs` 而不是 binary 裡：
  只在一個 transport 上成立的安全開關，等於給攻擊者一個「換傳輸」的選項，
  而 `Alt-Svc` 還會主動邀請他們換。
  🚫 K3 落地時 H3 尚未驗，當時的 fail-closed 做法是**有 `client_auth` 的位址
  不啟 QUIC、不發 `Alt-Svc`**；K4（`4e4b05e` 之後）補上之後這條已解除。

- 🤡 **quiche 會覆寫你設的 session cache mode，所以在 QUIC 上關 resumption
  只能靠 `SSL_OP_NO_TICKET`。**
  `Context::from_boring`（quiche 0.29.3 `src/tls/mod.rs:155`）接手你的
  `SslContextBuilder` 之後，**無條件**呼叫
  `set_session_callback()` → `SSL_CTX_set_session_cache_mode(ctx,
  SSL_SESS_CACHE_CLIENT)`（`:264`）來裝它自己的 client session callback。
  你在 builder 上設的 `SslSessionCacheMode::OFF` 當場被蓋掉。
  **options 則是累加的**，quiche 從不清除，所以 `NO_TICKET` 活得下來。
  📌 我第一版兩個都設了，還寫了一段「雙保險」的註釋——**一個被默默還原的保護
  比一個誠實的保護更糟**，因為它讓下一個讀的人以為有兩層。
  🎯 這條是**測出來的不是讀出來的**：`h3_client_auth_turns_session_resumption_off`
  先證明同一支 harness 對普通 listener **resume 得起來**（沒有這個對照組，
  「沒 resume」也可能只是 harness 不會 resume），再證明 mTLS listener 不會。
  H1/H2 那邊沒有這層覆寫——`TlsSettings::build()` 只是
  `accept_builder.build()`，中間沒有人碰 options——所以那邊是靠推理成立的，
  這個不對稱刻意寫下來。

---

## 🌐 公開簽發（ACME，2026-08-17）

- 🚫 **ClientHello 裡的名字是連線方選的，不是設定檔選的。**
  這條是這一節存在的理由。resolver 同時負責「查憑證」與「查不到就去簽一張」，
  而查不到的判斷來自 SNI——於是**陌生人挑一個主機名，這台機器就去跟公開 CA
  做一次外連工作**：帳號、訂單、挑戰、速率額度，全部由對方觸發。
  做法是 `TlsManager` 多一份 `public_issuance_domains` allowlist，
  和既有的 `internal_domains` 完全對稱，在碰到 CA 之前擋掉。
  📌 **空的 allowlist 代表「誰都不簽」**，不是「都可以」。還沒讀設定檔的行程、
  或未來忘了發布清單的路徑，都必須落在拒絕那一邊。
  ⚠️ 這也表示 **catch-all 站台（`_`、`*`、`:port`）不再授權任何公開簽發**。
  「這個站台什麼都接」講的是路由，不是憑證政策；把它讀成後者正是缺陷本身。
  上游用 `on_demand_tls` 搭一個明確的 `ask` endpoint 來做這件事，我們沒有實作
  （registry 裡是 `recognised`），所以無限制的 on-demand 簽發是意外不是功能。

- 🔤 **名字要在進 store／in-flight 集合／CA 之前正規化。**
  `CertStore` 與 in-flight 集合都用字串當 key，而 SNI 大小寫不敏感、還可以帶
  結尾的點。allowlist 正規化了但下游沒有，等於**同一個站台可以被拼成上千種寫法**，
  每一種都是一次 cache miss、一次 claim、一次真的 ACME 訂單——而拼法是客戶端選的。
  同樣的道理讓 `certs.rs` 的 `ssl_cache` 也必須用正規化後的名字當 key，
  否則那個 `HashMap` 會被大小寫排列組合灌大。

- 🎟️ **in-flight 標記必須是 RAII guard，不能是「呼叫完再移除」。**
  ACME 呼叫是在 TLS 握手裡 await 的。客戶端斷線 → future 被 drop →
  **後面那行移除永遠不會執行**，於是那個名字被永久標成「簽發中」，
  之後每一次嘗試都被拒絕——一次斷線換一個永久壞掉的站台。
  順帶修掉的是原本 check 與 insert 分兩把鎖的 race：`HashSet::insert`
  的回傳值一次回答「本來有沒有」和「現在是我的了」。

- 🚦 **per-name 的去重說不了「有幾個不同名字同時在跑」。**
  所以另外有一個 process 級的 `Semaphore`（`MAX_CONCURRENT_ISSUANCES = 4`）。
  用 `try_acquire` 直接拒絕而不是排隊：**佇列是由發問者撐開的記憶體與延遲**，
  拒絕只賠掉一次握手，而 renewal daemon 和下一次握手都會重試。
  📌 正常流量碰不到這個上限——eager issuance 與 renewal 都是循序的，
  唯一的併發來源是同時握手。它是 allowlist 後面的第二道，不是第一道。

- 🤡 **`enabled` 被寫進設定、被 `auto_https off` 設成 false、然後沒有任何執行期
  程式碼讀它。** 全 repo 搜尋確認過。
  📌 判準和 K3 那條 mTLS 的一模一樣：**新增任何安全開關時，找出真正執行它的
  那一行**。這已經是同一個錯誤在這個檔案裡的第二次。
  🎯 現在的位置在 store fast path **之後**：關掉自動 HTTPS 要擋的是「去拿一張」，
  不是「用已經有的那張」——後者不外連、不花額度，擋了只會讓站台白白掛掉。

- 🎯 **這一節的每一條都先驗過 red。** 拿掉 allowlist → 3 紅；拿掉 `enabled` 閘門
  → 1 紅；把 semaphore 放大 → 1 紅（8 ≠ 4）；把 drop guard 清空 → 2 紅。
  ⚠️ 寫這種測試有個陷阱我踩了兩次：mock issuer 進去之後會等 release 訊號，
  所以閘門一拿掉，「本來不該走到 issuer」的測試會**卡住而不是失敗**。
  每一個等待都要有上限（`expect_entered`／`expect_refused`），
  否則紅的表現形式是整個測試跑不完，那是最沒用的說不。

---

## 📡 DNS-01（`tls { dns … }`，2026-08-10 K5）

- 🤡 **rustls 的 crypto provider 必須指名，否則第一次連線直接 panic。**
  這個 binary 同時鏈進了兩套：`instant-acme` 帶 aws-lc-rs，workspace 的
  `rustls` 又釘 `ring`。rustls 拒絕猜，`ClientConfig` 一建就
  `panic!("Could not automatically determine the process-level CryptoProvider")`。
  **那是簽發當下對著真 API 的 panic，不是測試產物**——
  用 `HttpsConnectorBuilder::with_provider_and_webpki_roots(provider)` 明確指定。
  📌 這條是被那支打 mock server 的測試抓到的。如果當初偷懶只寫「打真 API 的
  測試」，這個 panic 會第一次出現在正式環境。**provider 的測試要能離線跑。**

- 🏢 **zone 要由長到短試後綴，而且要快取。**
  `_acme-challenge.a.example.com` 屬於哪個 zone，名字本身沒說，只有帳號知道。
  長的先試，delegated 子 zone 才會贏過母 zone——那正是委派的意義。

- 🧹 **TXT 記錄要「取代」不是「附加」。** 重試的訂單否則會留下上一次的挑戰值，
  而一個名字帶兩筆 TXT，有些 CA 會直接判為無法判讀。

- 🏷️ **萬用字元的挑戰記錄寫在母網域上。**
  `*.example.com` 與 `example.com` 共用 `_acme-challenge.example.com`；
  照字面組出 `_acme-challenge.*.example.com` 是任何 zone 都放不下的名字。

- 🔎 **傳播檢查的 resolver 必須關快取。** 檢查要觀察的就是「記錄出現了」這個
  變化，而快取住的 NXDOMAIN 會在整個 propagation 窗口內一直說沒有。

- 🔐 **API token 是憑證。** 包在一個 `Debug` 什麼都不印的型別裡——
  不是為了防人手寫 log，是為了防日後有人在外層結構加 `#[derive(Debug)]`。
  連長度都不印：長度會洩漏 token 的種類。

- 🚫 **沒實作的 provider 在啟動時指名拒絕，不在設定期。**
  設定期拒絕會讓 12 份上游語料失敗——它們用 `dns mock`，而上游那是測試模組。
  `adapt` 說「我翻譯得了」是誠實的，拒絕**服務**才是該畫的線；
  跟 K3 的 `client_auth` 同一條理由。
