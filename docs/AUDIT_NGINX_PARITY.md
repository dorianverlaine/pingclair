# 🧪 Pingclair vs Nginx 生產替代性審計

> **審計時間**: 2026-07-25(第二次審計,逐項對照程式碼核實)
> **上次審計**: 2026-04-20(v0.1.6,P0 四項已全部修復,見文末)
> **當前版本**: v0.1.7

---

## 🔴 上生產前必須修復(Blocker)

### 1. Admin API 完全無認證,且預設啟用 🚨

**檔案**: `pingclair-api/src/server.rs:52-113`(`handle_request`)

**問題**: 設定裡有 `AdminConfig.api_key`(`pingclair-core/src/config/types.rs:507`),
`ApiKeyAuth` 結構也寫好了(`pingclair-api/src/auth.rs`,還標著 `#![allow(dead_code)]`),
但 `handle_request` **從未呼叫它**。`/config` GET/POST(熱重載)和 `/metrics`
零認證暴露,且 `enabled` 預設為 `true`(`types.rs:511`)。任何能連到 admin
埠的人都可以讀取並改寫執行時設定。

**修復方案**:
- `handle_request` 入口統一校驗 `Authorization: Bearer <api_key>`
- 未設定 `api_key` 時只允許 loopback 客戶端,並在啟動日誌裡明確警告
- 移除 `#![allow(dead_code)]`

**預計耗時**: 2 小時

- [x] 已修復(2026-07-25)

---

### 2. auth_basic 是壞的 — 比沒有更糟 🚨

**檔案**: `pingclair-core/src/server/handlers.rs:177-192`(`BasicAuth` handler)

**問題**: handler 拿到 `credentials` 後直接忽略(`credentials: _`),
**無條件回傳 401** + `WWW-Authenticate`。設了 Basic Auth 的站點會把
**所有人**(包括合法使用者)擋在門外。整個程式碼庫沒有任何地方校驗
`Authorization` 標頭。

**修復方案**: 解析 `Authorization: Basic <base64>`,與設定的 credentials
比對(常數時間比較);不匹配才 401。補單元測試(正確密碼放行 / 錯誤密碼 401 /
缺 header 401)。

**預計耗時**: 半天

- [x] 已修復(2026-07-25)

---

### 3. ACME 每次簽發都註冊新帳戶

**檔案**: `pingclair-tls/src/acme.rs:350-371`(`ensure_account`)

**問題**: ACME 帳戶私鑰不持久化,每次簽發都 `create` 一個新帳戶。
會撞 Let's Encrypt 的註冊頻率限制(每 IP 3 小時 10 個帳戶),多域名 +
頻繁重啟的場景下簽發會直接失敗。已簽發的憑證有持久化(`cert_store.rs`),
唯獨帳戶沒有。

**修復方案**: 帳戶憑據(JSON)落盤到 TLS store 目錄(0600 權限),
啟動時優先載入;staging 與 production 分開存放。

**預計耗時**: 半天

- [x] 已修復(2026-07-25)

---

## 🟡 Nginx 功能差距(P1,替代 90% 場景需要)

| 功能 | 現狀 | 證據 | 預計耗時 |
|------|------|------|----------|
| ~~SSE / 流式反代~~ | ✅ 已修復(2026-07-25) | Pingora 本就逐 chunk 轉發;真正問題是我們的 gzip filter 壓了 SSE。現 `flush_interval: -1` 路由與 `text/event-stream` 回應都跳過 gzip(`pingclair-proxy/src/server.rs`) | — |
| `error_page` | ❌ 零實現 | 全庫無 `error_page` 匹配;502/404 只能出預設頁 | 半天 |
| LB weight / backup | ❌ 所有後端一視同仁 | `load_balancer.rs:194`;被動健康檢查(`max_fails`/`fail_timeout`)已有(`load_balancer.rs:53-104`) | 1 天 |
| 反代 Brotli | ❌ gzip only | `server.rs:1419`(flate2 `GzEncoder`);靜態路徑已有 br/zstd | 半天 |
| 正則 rewrite | ❌ 正則**匹配**已有,正則**改寫**沒有 | `router.rs:15-53`(Regex matcher,預編譯快取)vs `handlers.rs:170-171` | 半天 |
| RequestContext 輕量化 | 🟡 未做但影響小 | `server.rs:31-93` 每請求 3 個 `HashMap::new()`;空 HashMap 不配置堆記憶體,僅插入時才配置 | 2 小時 |

## 🟢 P2 — 進階 / 可觀測性

| 功能 | 現狀 | 說明 |
|------|------|------|
| `proxy_cache` | ❌ | HTTP 回應快取層,大功能(1 週+) |
| 存取日誌格式 | ❌ 固定 tracing JSON | `server.rs:1509` 自述 "we use tracing for now";`LogConfig` 是擺設 |
| Prometheus 指標 | 🟡 僅 3 個 series | `pingclair-proxy/src/metrics.rs:16-40`:requests_total / duration / active_connections |
| 外掛系統 | ❌ stub | `pingclair-plugin/src/loader.rs:10-13` 是 `// TODO`,`main.rs` 未接線 |
| QUIC 事件迴圈 | 🟡 單 task/埠 | `pingclair-proxy/src/quic.rs` 簡單模型,高並發 H3 下可能是瓶頸,**未壓測過** |
| 健康檢查 Host 標頭 | ❌ | `health_check.rs:106` TODO:虛擬主機場景需要自訂 Host |
| gzip_types 可設定 | ❌ 硬編碼 | 低優先 |

---

## ✅ 已修復確認(2026-07-25 程式碼核實)

上次審計 P0 四項 + 後續發現的問題,均已修復:

- ✅ **Gzip 全量緩衝 OOM** — `server.rs:1431-1452` 流式壓縮,逐 chunk sync-flush,
  記憶體以單個 chunk 為界;<256B 小 body 跳過(`server.rs:1415`)
- ✅ **`hosts` RwLock 競爭** — 已換 `ArcSwap<HashMap>`(`server.rs:337-348`),熱路徑無鎖
- ✅ **upstream 連線池上限** — `global.upstream_keepalive_pool_size`(`types.rs:48`),
  `main.rs:540-543` 套用並在啟動時輸出日誌(`main.rs:556-562`)
- ✅ **靜態壓縮快取驚群** — per-key `tokio::sync::Mutex` single-flight 去重
  (`file_server.rs:122-129, 555-609`),有並發冷快取測試覆蓋
- ✅ **靜態熱路徑 tokio::fs** — 已全改同步 `std::fs`(2.6x 吞吐,見 `benchmarks/README.md` #22/#23)
- ✅ **worker_threads 預設 1** — 改 `available_parallelism()`,可設定,啟動輸出日誌
- ✅ **正則 location 匹配** — `router.rs` Regex matcher,預編譯快取
- ✅ **DSL http3 開關** — `compiler.rs:180-182` + Caddyfile adapter 支援
- ✅ **優雅重載** — SIGHUP(`main.rs:839-918`)+ admin API 雙通道;SIGTERM 優雅關閉
- ✅ **靜態 Brotli/Zstd** — 預壓縮 `.br`/`.gz`/`.zst` + 即時壓縮(`file_server.rs:714-766`)
- ✅ **具名 server 區塊綁定** — `bench.local:8080` 綁 `0.0.0.0` 按 Host 路由(benchmarks #14)
- ✅ **HTTP/3** — quiche 0.29 重寫上線,九項 VPS 冒煙測試全過
- ✅ **Admin API 認證** — Bearer key 校驗接上,無 key 時僅限 loopback(見 Blocker #1)
- ✅ **auth_basic 執行時校驗** — 見 Blocker #2
- ✅ **ACME 帳戶持久化** — 見 Blocker #3
- ✅ **SSE / 流式反代** — `flush_interval: -1` 與 `text/event-stream` 自動跳過 gzip;
  Pingora 傳輸層本就对未知長度 body 逐 chunk flush(見上方 P1 表)

---

## 🧠 Pingora 已經幫我們做好的事(不需要自己實現)

- ✅ HTTP keep-alive 連線複用(上下游)
- ✅ Chunked Transfer-Encoding / 100-continue
- ✅ WebSocket 升級透傳
- ✅ HTTP/2 多路複用(上游自動)
- ✅ 連線池(內建 upstream 複用)
- ✅ Backpressure(流式 body,除了我們自己的 gzip 已修)
- ✅ Graceful shutdown(SIGTERM 等待在途請求)
- ✅ Worker 執行緒模型(多執行緒 epoll/kqueue)

---

## 🎯 建議的壓測策略

```bash
# 第一步:不開 gzip,純代理效能
wrk -t4 -c100 -d30s http://localhost:8080/api/test

# 第二步:開 gzip,檢測記憶體
wrk -t4 -c100 -d30s -H "Accept-Encoding: gzip" http://localhost:8080/api/test
watch -n1 "ps aux | grep pingclair"

# 第三步:長連線 + 高並發
wrk -t8 -c1000 -d60s --latency http://localhost:8080/

# 第四步:大 body(流式驗證)
curl -s http://localhost:8080/large-file.json -H "Accept-Encoding: gzip" > /dev/null

# 第五步:H3 壓測(QUIC 單 task 模型未壓過,重點觀察)
```

最新實測數據見 `benchmarks/README.md`(VPS 2 vCPU:靜態 50k rps ≈ nginx 94%,
gzip 反超 nginx,反代 20.1k vs nginx 22.0k,20MB 流式 RSS 17.7MiB)。

---

## 📊 預估時間線

| 階段 | 內容 | 耗時 |
|------|------|------|
| **階段 1** | 🔴 3 個 Blocker(admin auth / auth_basic / ACME 帳戶持久化) | ✅ 已完成(2026-07-25) |
| **階段 2** | 🟡 P1 功能(~~SSE~~ ✅ / error_page / LB weight / 反代 br / 正則 rewrite) | ~2.5 天 |
| **階段 3** | 🟢 P2 進階(proxy_cache / 日誌格式 / 指標 / 外掛 / H3 壓測優化) | 按週計 |

**結論**: 核心(效能、流式、熱重載、H3)已到生產水位;三個安全/正確性
口子與 SSE 流式反代已於 2026-07-25 修復,**可小規模試生產**。
剩下的 nginx parity 功能(`error_page`、LB weight、`proxy_cache`)按優先級跟進。
