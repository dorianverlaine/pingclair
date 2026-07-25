# 📋 Pingclair 已知問題與待辦清單

> **這是專案的「持久記憶」**:所有已知限制、待辦事項、測試缺口都記在這裡。
> 修掉一項就劃掉一項(連同日期);發現新問題就加上去。
> nginx parity 的整體審計見 `docs/AUDIT_NGINX_PARITY.md`;壓測發現並已修復的
> bug 歷史見 `benchmarks/README.md`。
>
> 最後更新: 2026-07-25(第二版,補充同類專案調研後的功能規劃)

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
- [ ] **反代壓縮補齊** — 反代路徑只有 gzip(`pingclair-proxy/src/server.rs` `GzEncoder`);
  靜態路徑已有 br/zstd。反代至少補 br,有餘力再 zstd。
- [ ] **正則 rewrite** — 正則**匹配**已有(`pingclair-core/src/server/router.rs`,預編譯快取),
  正則**改寫**沒有(`handlers.rs` Rewrite 僅字面替換)。
- [ ] **bcrypt 憑據** — `BasicAuthCredential { hashed: true }` 目前**永不匹配**(直接跳過)。
  需要引入 bcrypt 依賴(刻意暫緩,是依賴決策)。明文憑據正常工作。
- [ ] **CORS** — preflight 處理 + 回應標頭注入。目前完全沒有,反代 API 場景剛需。
- [ ] **Request ID** — 產生或透傳 `X-Request-Id`,貫穿 access log 與上游轉發。
  排障與分散式追蹤的基礎設施,成本很低。
- [ ] **IP / Referer / UA 存取控制** — 依 IP/CIDR、Referer host、User-Agent 正則
  做 allow/deny。現有 rate limiter 的 keyed 機制可複用。

### P2 — 進階 / 可觀測性

- [ ] **`proxy_cache`** — HTTP 回應快取層(ETag/Cache-Control),需含 `PURGE`
  清除端點與快取鍵設計(host+path+vary)。大功能,按週計。
- [ ] **存取日誌格式** — `LogConfig{level, format}` 是擺設,執行時固定輸出 tracing JSON
  (`pingclair-proxy/src/server.rs` 有自述註釋)。目標:nginx 風格的自訂格式字串,
  變數至少覆蓋 request_id、上游位址、上游連線/回應耗時、下游耗時、
  位元組數、快取命中狀態(參考 nginx `$upstream_*` 系列)。
- [ ] **Prometheus 指標太薄** — 僅 3 個 series(`pingclair-proxy/src/metrics.rs`):
  requests_total / duration / active_connections。應補:上游連線時間、上游回應時間、
  依 route/status 分維度、TLS 握手耗時、H3 連線數;另考慮 push 模式(Pushgateway)。
- [ ] **OpenTelemetry tracing** — 分散式追蹤接入(依賴 Request ID)。
- [ ] **外掛系統** — `pingclair-plugin/src/loader.rs` 是 `// TODO` stub,未接線,
  已從 README 賣點移除。要做就整套設計,別留著半吊子。設計要點(做之前先寫
  RFC 放 `docs/`):① 映射 Pingora 回呼為固定數量的生命週期階段(early_request /
  request / proxy_upstream / upstream_response / response),每個外掛實例只跑一個
  階段;② 外掛宣告與掛載分離——定義一次、多條路由引用,同名外掛可不同參數
  多實例化;③ 每個實例提供 `config_key()`(配置雜湊),熱更新時比對雜湊決定
  是否重建實例,避免無變化的外掛被無謂替換;④ `validate` 階段就要能抓住
  外掛配置錯誤(TryFrom 校驗)。
- [ ] **更多內建認證方式** — 現僅 basic_auth。候補:JWT(HMAC/公鑰/遠端 JWKS)、
  key_auth(header/query API key)、forward_auth(委派給外部 HTTP 服務判定)、
  CSRF(double-submit cookie)。等外掛系統落地後以外掛形式做。
- [ ] **流量拆分(traffic splitting)** — 按比例把流量導到不同 upstream
  (金絲雀/灰度)。可在 LB 層做,與 weight 項目協同。
- [ ] **回應體替換(sub_filter)** — 字面/正則替換回應內容(需流式,禁全量緩衝)。
- [ ] **mock 回應** — 路由直接回固定狀態碼/內容,可選延遲。除錯與降級好用。
- [ ] **DNS 服務發現** — upstream 填域名時定期重解析 A/SRV 記錄並更新後端池
  (現只啟動時解析一次)。之後可再考慮 Docker label 發現。
- [ ] **ACME DNS-01** — 現僅 HTTP-01,無法簽泛域名(*.example.com)。
  DNS-01 需要 DNS 供應商 API 抽象,先做主流幾家或接外部工具。
- [ ] **配置歷史 + 一鍵回滾** — Admin API 熱更新時留存歷史版本,
  提供 restore 端點。熱更新已經有了,這個是讓它敢在生產用的保險絲。
- [ ] **Graceful restart** — 改監聽埠等需要重建 listener 的變更,目前只能整個
  重啟掉請求。需要零停機重啟(舊行程 SO_REUSEPORT 或 fd 交接)。
- [ ] **gRPC-web 轉發** — Pingora 支援 HTTP/2 上游,補協議偵測與轉發即可。
- [ ] **目錄 autoindex** — 靜態服務無 index 檔時產生目錄列表(可關)。
- [ ] **Web 管理介面** — Admin API 已有,缺個內嵌的靜態 UI(單頁嵌入二進位,
  別引入前端建置鏈)。低優先。
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
- [ ] 其他候補:`error_page`、`gzip_types`、CORS、IP/Referer/UA 限制、LB weight、
  traffic splitting、新認證方式等實現後需一併補 DSL 語法。

---

## 🟣 P3 — 發佈 / 生態工程

- [ ] **靜態二進位(musl)** — 目前 release 只有 glibc 動態連結 tarball,容器與
  舊發行版部署不便。BoringSSL 是自行編譯的,musl 交叉編譯理論上可行,需驗證。
- [ ] **macOS 二進位** — release workflow 只跑 Linux x86_64/aarch64,
  開發者本地體驗要自編。補 Darwin x86_64/arm64 target。
- [ ] **官方 Docker 鏡像** — 根目錄有 Dockerfile 但沒有發佈到 registry,
  CI 應在 tag 時推 ghcr.io / Docker Hub。
- [ ] **免 root 一鍵安裝** — `scripts/install.sh` 是 root + systemd 路線;
  應加一條裝到 `/usr/local/bin`(或 `~/.local/bin`)的純二進位路線,類似
  多數 CLI 工具的 install script。
- [ ] **配置後端抽象** — 配置來源目前只有本地檔案。長遠看可抽象出
  backend 介面(檔案 / etcd / HTTP),配合熱更新做集中式配置管理。低優先。

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
