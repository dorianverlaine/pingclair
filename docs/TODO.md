# 📋 Pingclair 已知問題與待辦清單

> **這是專案的「持久記憶」**:所有已知限制、待辦事項、測試缺口都記在這裡。
> 修掉一項就劃掉一項(連同日期);發現新問題就加上去。
> nginx parity 的整體審計見 `docs/AUDIT_NGINX_PARITY.md`;壓測發現並已修復的
> bug 歷史見 `benchmarks/README.md`。
>
> 最後更新: 2026-07-25(v0.1.7 之後)

---

## 🔴 安全 / 正確性(優先處理)

目前無未修的 blocker。2026-07-25 已修:Admin API 認證、auth_basic 校驗、
ACME 帳戶持久化(詳見審計文檔)。

---

## 🟡 功能缺口(按優先級)

### P1 — 常用功能

- [ ] **`error_page`** — 自訂錯誤頁(404/500/502/504)。全庫無實現,錯誤只能出預設頁。
- [ ] **LB weight / backup** — 加權負載平衡 + 備用後端。`pingclair-proxy/src/load_balancer.rs:194`
  目前所有後端一視同仁(被動健康檢查 `max_fails`/`fail_timeout` 已有)。
- [ ] **反代 Brotli** — 反代路徑只有 gzip(`pingclair-proxy/src/server.rs` `GzEncoder`);
  靜態路徑已有 br/zstd。
- [ ] **正則 rewrite** — 正則**匹配**已有(`pingclair-core/src/server/router.rs`,預編譯快取),
  正則**改寫**沒有(`handlers.rs` Rewrite 僅字面替換)。
- [ ] **bcrypt 憑據** — `BasicAuthCredential { hashed: true }` 目前**永不匹配**(直接跳過)。
  需要引入 bcrypt 依賴(刻意暫緩,是依賴決策)。明文憑據正常工作。

### P2 — 進階 / 可觀測性

- [ ] **`proxy_cache`** — HTTP 回應快取層(ETag/Cache-Control)。大功能,按週計。
- [ ] **存取日誌格式** — `LogConfig{level, format}` 是擺設,執行時固定輸出 tracing JSON
  (`pingclair-proxy/src/server.rs` 有自述註釋)。
- [ ] **Prometheus 指標太薄** — 僅 3 個 series(`pingclair-proxy/src/metrics.rs`):
  requests_total / duration / active_connections。
- [ ] **外掛系統** — `pingclair-plugin/src/loader.rs` 是 `// TODO` stub,未接線,
  已從 README 賣點移除。要做就整套設計,別留著半吊子。
- [ ] **QUIC 單 task 事件迴圈** — `pingclair-proxy/src/quic.rs` 每埠單 task 的簡單模型,
  高並發 H3 下可能是瓶頸。**從未壓測過 H3**,需要一輪 H3 benchmark。
- [ ] **健康檢查 Host 標頭** — `pingclair-proxy/src/health_check.rs:106` TODO:
  虛擬主機場景需自訂 Host。
- [ ] **`gzip_types` 可設定** — 目前硬編碼常見 MIME 類型。
- [ ] **RequestContext 輕量化** — 每請求 3 個 `HashMap::new()`(`server.rs:31-93`);
  空 HashMap 不配置堆記憶體,影響小,低優先。

---

## 🟦 DSL 缺口(Pingclairfile 還不能配,JSON 配置可用)

- [ ] **`admin.api_key`** — 編譯器硬編碼 `None`(`pingclair-config/src/compiler.rs:75`),
  Admin API 金鑰只能 JSON 設定。
- [ ] **`basic_auth`** — DSL 從不產生 `HandlerConfig::BasicAuth`,只有 JSON 配置能用到
  三條路徑(H1/H2/H3)的 Basic Auth。
- [ ] 其他候補:`error_page`、`gzip_types`、LB weight 等實現後需一併補 DSL 語法。

---

## 🧪 測試缺口

- [ ] **SSE 端到端測試** — 目前只有決策邏輯的單元測試。可在
  `pingclair/tests/integration.rs`(會起真二進位)加一個慢速 SSE 上游,
  斷言 chunk 增量到達。
- [ ] **H3 壓測** — QUIC 路徑只有九項冒煙測試(VPS),無效能數據。
- [ ] **ACME `from_credentials` 還原路徑** — 單元測試不聯網,只覆蓋序列化/持久化;
  真實還原需對 LE staging 做一次手動驗證。
- [ ] **Basic Auth 端到端** — 單元測試齊全,但沒有經真二進位 + JSON 配置的
  整合測試(401/200 全流程)。

---

## 🔧 程式碼債(小)

- [ ] `pingclair-api/src/handlers.rs` 還有一個 `#![allow(dead_code)]`(歷史遺留,
  與 auth 無關)。
- [ ] `pingclair-core/src/config/loader.rs:41` 的 TODO 註釋已過時(parser 早就有了),刪掉。
- [ ] `pingclair-proxy/src/server.rs:758` 註釋 "Rate limiting ... TODO: verify integration",
  需確認限流在 `request_filter` 的整合是否完整。

---

## ⚠️ 環境 / 測試注意事項

- 本地 macOS 有系統代理(127.0.0.1:1082),reqwest 測試必須 no_proxy
  (整合測試已處理,別改回去)。
- CI 與 Dockerfile 都釘 **stable** Rust;nightly 在本 workspace 的 release profile
  下編譯 tokio 會 ICE(見 `AGENTS.md`),不要重新引入 nightly。
- dev 依賴 reqwest 必須保持 `rustls-tls`(native-tls 會把 openssl-sys 拉進來,
  與 quiche 的 BoringSSL 連結衝突,見 `pingclair/Cargo.toml` 註釋)。
