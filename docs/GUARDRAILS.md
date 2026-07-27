# ⚠️ Pingclair 實作守則

> 動手改程式碼或跑驗證**之前**先讀這份。這裡記錄的都是踩過的坑，
> 不是理論建議——每一條後面都有一次實際失敗。
>
> - 接下來要做什麼 → `docs/TODO.md`
> - 已完成與驗證證據 → `docs/STATUS.md`
>
> 最後整理：2026-07-27

---

## 🧪 測試與除錯

- **本機 macOS 有系統代理 `127.0.0.1:1082`**；reqwest 整合測試必須 `.no_proxy()`，
  否則請求會被代理攔截，症狀看起來像路由錯誤。
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

---

## 🔗 依賴與鏈結

- **CI 與 Dockerfile 使用 stable Rust**。nightly 曾在 release profile
  （`panic="abort"` + fat LTO + `codegen-units=1`）編譯 tokio 時 ICE。
- **reqwest dev dependency 必須維持 rustls**。native-tls／OpenSSL 會與 quiche 的
  BoringSSL 產生連結衝突。
- **禁止引入 `pingora-openssl`、`openssl-sys` 或 reqwest `native-tls`**。
  `quiche 0.29`、`boring 4.22` 與 Pingora `boringssl` feature 是同一套 BoringSSL
  鏈結設計；過去曾因 OpenSSL／BoringSSL 符號衝突造成**啟動 SIGBUS 與 Linux link error**。

---

## 🚀 HTTP/3 實作護欄

### 架構

- H3 是 `pingclair-proxy/src/quic.rs` 的 **raw Tokio UDP／quiche 路徑**，每個 HTTPS
  port 一個 task 與一個無鎖 connection map。**它不是 Pingora `ProxyHttp Session`
  的延伸**。
- middleware parity 應抽出 **transport-neutral 邏輯**（見 `http_policy.rs`），
  不可硬把 H1/H2 Session 塞進 H3。

### 正確性

- **`pump_h3_events` 必須同時由收包與 maintenance pass 驅動**。request body drain
  可能在沒有新 UDP packet 時產生 `Finished`；只在收包時 pump 會讓大型 POST **永久卡住**。
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

---

## 📁 驗證證據

- 結果寫進 `benchmarks/results/<date>_<commit-prefix>/`。
- **失敗的證據不可覆寫**。修好之後另開目錄，保留舊的失敗紀錄作為對照。
- 驗證必須記錄**完整 commit SHA**，不能只寫「最新版」。
