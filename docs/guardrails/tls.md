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
