# 📋 Pingclair 狀態與待辦

> 這是專案的持久狀態表。功能「有程式碼」、「本機測試通過」與「Linux/VPS
> 實機驗證通過」是三件不同的事，不得混寫。
>
> - ✅ **完成**：已在阿里雲深圳 VPS 以真實 binary 驗證，且有結果或腳本可追溯。
> - 🧪 **待遠端驗證**：已實作並通過本機單元／整合測試，但尚未以目前版本在乾淨
>   Linux/VPS 環境驗證。
> - ⬜ **未實作**：功能或測試仍缺少。
>
> nginx parity 審計見 `docs/AUDIT_NGINX_PARITY.md`；效能數據與壓測發現的 bug
> 見 `benchmarks/README.md`。
>
> 最後整理：2026-07-26

---

## ✅ 完成：已通過遠端伺服器驗證

### 2026-07-25 VPS 生產情境測試

環境：阿里雲深圳，Ubuntu 24.04，2 vCPU／1.6GB。原始結果保存在
`benchmarks/results/20260725_vps_onbox/`，方法與數據見
`benchmarks/README.md`。

- [x] **具名虛擬主機與 listener 綁定** — `bench.local:8080` 綁 wildcard，
  依 Host 路由；靜態、gzip、range、反向代理、Admin API、TLS 均以真 binary 驗證。
- [x] **靜態路徑安全** — `..` 逃逸已拒絕，使用無 syscall 的詞法正規化。
- [x] **TLS 啟動與手動憑證** — rustls provider 啟動 panic 已修復；手動憑證可由
  SNI 正確載入。
- [x] **404 路由語意** — 不存在的檔案、未知 vhost、未匹配路由不再落成
  `ConnectNoRoute` 500。
- [x] **被動健康檢查與同請求 failover** — 兩個 upstream 中一個故障時，
  20/20 請求成功；冷卻後故障節點可重新加入。
- [x] **大檔案串流** — 20MB 靜態檔不再全量緩衝；VPS 負載測試沒有 OOM，
  RSS 與吞吐數據已留存。
- [x] **程序生命週期** — SIGTERM／SIGINT 可停止服務，不再等到 SIGKILL。
- [x] **Metrics 與轉發標頭** — Admin `/metrics` 有內容；代理請求帶
  `X-Forwarded-For`／`X-Real-IP`。
- [x] **`tls`／`admin` DSL 基線** — VPS 配置可啟動並完成實際請求。
- [x] **worker threads 與靜態熱路徑** — `available_parallelism()` 與同步
  `std::fs` 已在同機重測；靜態約 50k req/s，20MB 串流約 17.7MiB RSS。
- [x] **壓縮快取與冷快取 single-flight** — gzip 大 body 負載重測無先前的
  壓縮驚群／記憶體暴增。

### 2026-07-25 HTTP/3 VPS 冒煙測試

遠端腳本：`/root/h3_test.sh`；測試產物包含 `/root/h3test/h3_big.out`。

- [x] **quiche HTTP/3 基線** — UDP listener、H1 TLS baseline、Alt-Svc、H3
  `respond` 均通過。
- [x] **H3 靜態與反向代理大 body** — 10MB 靜態／代理回應逐位元組一致。
- [x] **H3 request body 串流** — 有／無 Content-Length 的 300KB POST 均可轉發；
  5MB 超限請求回 413。
- [x] **bare `:port` 正規化** — JSON 的 `:8443` 可在 Linux 啟動，未再出現
  `Name or service not known`。

> 遠端 `/root/pingclair` 是歷史測試工作樹，目前 HEAD 為 `79c820a` 且有大量
> 未提交變更。上列證據是已保存的測試情境與產物，不代表目前 `main` 已在該
> 工作樹重新驗證。新的驗證必須使用乾淨 clone/worktree 並記錄 commit。

---

## 🧪 已實作：本機通過，尚待乾淨遠端驗證

### 安全與正確性

- [x] **Admin API 認證**（2026-07-25）— Bearer key 已接入；未配置 key 時僅允許
  loopback。本機 auth 單元測試通過，尚未以目前 commit 做遠端拒絕／放行測試。
- [x] **Basic Auth 執行時校驗**（2026-07-25）— 正確憑據放行，缺少／錯誤憑據
  回 401；`test_basic_auth_end_to_end` 已通過。
- [x] **ACME 帳戶持久化**（2026-07-25）— staging／production 分開，0600 落盤；
  本機序列化與還原測試通過，尚待 Let's Encrypt staging 真實還原。

### 2026-07-26 Caddy parity 第一波

目前 commit：`dd1ed57`。`cargo build --workspace`、`cargo test --workspace`
與 7 項真 binary 整合測試均在本機通過，但下列項目尚未在乾淨 Linux/VPS
上跑過：

- [x] **`error_page`** — 多狀態碼共用頁；靜態 404 與上游 500/502 使用自訂頁，
  檔案讀取失敗時回退內建文字頁。
- [x] **CORS 執行路徑與 DSL** — origin、method、header、expose header、
  credentials、max-age；包含 preflight 驗證與一般回應標頭。
- [x] **IP／Referer／UA 存取控制** — IP/CIDR、Referer host wildcard、UA regex；
  deny 優先，規則於配置載入時預編譯，錯誤配置 fail closed。
- [x] **正則 rewrite 執行與 DSL** — 支援 `$1` capture 與 query string 保留；
  regex 於配置載入時預編譯。
- [x] **LB weight／backup** — 加權主池；僅在所有主節點不可選時使用 backup。

移入「完成」前需在乾淨遠端 commit 上跑一套 parity smoke：

- [ ] 靜態 404 與死亡 upstream 502 的自訂錯誤頁。
- [ ] CORS simple request、合法／非法 preflight。
- [ ] IP、Referer、UA 的 allow／deny 與 deny precedence。
- [ ] rewrite capture、query 保留、代理 upstream 實際收到的 URI。
- [ ] weight 分布，以及 primary 全掛時 backup 接手／primary 恢復。

### 其他已實作項目

- [x] **SSE／流式反代 gzip gate**（2026-07-25）— `flush_interval: -1` 與
  `text/event-stream` 會跳過 gzip；目前只有決策邏輯單元測試。
- [x] **Request ID（H1/H2）**（2026-07-26）— 消毒後接受客戶端 ID，否則生成；
  上游、下游與 access log 貫穿。H3 尚未支援。
- [x] **`admin.api_key` DSL**（2026-07-26）— `admin <listen> <token>`。
- [x] **`basic_auth` DSL**（2026-07-26）— 行內與 block＋realm 形式均可編譯。

---

## ⬜ 未實作

### P0：測試可靠性

- [ ] **整合測試動態 port／程序隔離** — 現有測試使用 9091–9098 固定埠；
  測試被中止時仍可能留下幽靈 Pingclair。新測試應使用動態埠或唯一 readiness
  token，並加入 PID／port owner 檢查。
- [ ] **測試程序群組清理** — `Drop` 只處理直接 child；需評估 process group 或
  kill-on-drop guard，確保子程序與被中止測試不殘留。
- [ ] **乾淨遠端驗證工作流** — 不可再直接使用髒的 `/root/pingclair`。
  補一個以指定 commit 建立暫存 clone/worktree、測試、收集結果、清理程序的腳本。

### P1：常用功能與協議缺口

- [ ] **反代 Brotli／Zstd** — 反代回應目前只有 gzip；靜態路徑已有 br/zstd。
- [ ] **bcrypt 憑據** — `BasicAuthCredential { hashed: true }` 目前永不匹配。
- [ ] **H3 middleware parity** — quiche 路徑目前只直接處理 terminal
  `FileServer`／`ReverseProxy` 等；CORS、存取控制、rewrite、`error_page`、
  Request ID 與 H1/H2 pipeline 尚未完整套用。
- [ ] **SSE 真 binary 端到端測試** — 慢速 upstream 逐 chunk 發送，斷言客戶端
  增量收到資料而非等待完整 body。
- [ ] **`redirect` DSL** — core 與 AST 有型別，Caddyfile adapter 尚未產生它。
- [ ] **健康檢查 Host 標頭** — 虛擬主機 upstream 需要可配置 Host。
- [ ] **`gzip_types` 可設定** — 目前 MIME 清單硬編碼。

### P2：進階功能與可觀測性

- [ ] **`proxy_cache`** — 需定義 host＋path＋vary cache key、ETag／Cache-Control
  語意及 PURGE。
- [ ] **自訂 access log 格式** — `LogConfig` 尚未真正驅動輸出；需補
  request ID、upstream 位址／連線／回應耗時、status、bytes、cache 狀態。
- [ ] **Prometheus 指標擴充** — 上游連線／回應時間、route/status、TLS handshake、
  H3 connections；評估 Pushgateway。
- [ ] **OpenTelemetry tracing**。
- [ ] **外掛系統** — loader 仍是 stub；先寫生命週期、掛載、配置雜湊與熱更新 RFC。
- [ ] **更多認證方式** — JWT/JWKS、key auth、forward auth、CSRF；外掛系統完成後
  優先以外掛實作。
- [ ] **流量拆分** — 金絲雀／灰度比例路由。
- [ ] **回應體替換 `sub_filter`** — 必須串流，禁止全量緩衝。
- [ ] **mock 回應與可選延遲**。
- [ ] **DNS 服務發現** — A/SRV 定期重解析並更新 backend pool。
- [ ] **ACME DNS-01** — 泛域名與 DNS provider 抽象。
- [ ] **配置歷史與一鍵回滾**。
- [ ] **零停機 graceful restart** — 目前有 graceful shutdown／reload，但 listener
  變更仍需重啟；需 SO_REUSEPORT 或 fd 交接。
- [ ] **gRPC-web 轉發**。
- [ ] **目錄 autoindex**。
- [ ] **Web 管理介面** — 內嵌單頁 UI，避免引入前端建置鏈。
- [ ] **RequestContext 輕量化** — 每請求多個空 HashMap，低優先。
- [ ] **配置 backend 抽象** — 檔案／etcd／HTTP。

### P3：發佈與生態

- [ ] **H3 效能壓測** — 目前只有 VPS 冒煙，沒有 QUIC 單 task／埠模型的吞吐、
  延遲與高並發數據。
- [ ] **ACME `from_credentials` staging 實測**。
- [ ] **musl 靜態二進位**。
- [ ] **macOS x86_64／arm64 release artifact**。
- [ ] **官方 Docker image 發佈** — tag 時推 GHCR／Docker Hub。
- [ ] **免 root 安裝路徑** — `/usr/local/bin` 或 `~/.local/bin`，不依賴 systemd。

---

## 🧹 已完成的非 runtime 維護

這些項目不適用「遠端功能驗證」，保留作為變更紀錄：

- [x] 刪除未使用的 `pingclair-api/src/handlers.rs` 與 `mod handlers;`。
- [x] 修正 `pingclair-core/src/config/loader.rs` 過時 TODO。
- [x] 核實並改寫 proxy rate-limit 的過時 TODO 註釋。
- [x] 修正 `HandlerConfig::Pipeline`／`Handle` 的 serde round-trip。
- [x] README 三語版最低 Rust 更新為 1.88。

---

## ⚠️ 環境與驗證守則

- 本機 macOS 有系統代理 `127.0.0.1:1082`；reqwest 整合測試必須 `.no_proxy()`。
- 遇到固定 404／502 或 readiness 異常，先用 `lsof`／`ss` 查 port owner，再查
  child 是否已因 bind failure 退出；不要先假設是路由邏輯錯誤。
- timeout 時必須先 kill＋wait，再讀 stdout/stderr 到 EOF，否則會永久阻塞並留下
  幽靈程序。
- CI 與 Dockerfile 使用 stable Rust；nightly 曾在 release profile 編譯 tokio ICE。
- reqwest dev dependency 必須維持 rustls；native-tls／OpenSSL 會與 quiche 的
  BoringSSL 產生連結衝突。
- 遠端 `/root/pingclair` 有歷史未提交變更；禁止盲目 pull/reset/clean。
