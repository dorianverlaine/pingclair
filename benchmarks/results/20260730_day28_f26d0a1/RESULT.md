# Day 28 — H3 驗證（tokio-quiche 遷移後）

**Commit**: `f26d0a198bf0109e4f6fc1c1800c2c278860861b`
**日期**: 2026-07-30

觸發原因：`561d802` 同時改了 H3 實作與 TLS 依賴樹（新增 `tokio-quiche`）。
依 `docs/GUARDRAILS.md`「驗證」節，此時 macOS 單元測試不足以驗證鏈結與 QUIC 行為。

## 結論：**PASS**

## 1. Linux 鏈結與建置（macOS 補不了的那一半）

環境：`rust:1.88-bookworm`，linux/arm64，rustc 1.88.0

| 檢查 | 結果 |
|---|---|
| `cargo tree -i openssl-sys` | ✅ 無匹配——單一 BoringSSL 不變式成立 |
| `cargo build --locked --release --workspace` | ✅ 成功（2m14s） |
| `ldd` 動態 `libssl`／`libcrypto` | ✅ 無——BoringSSL 靜態鏈結 |
| `cargo test --locked --workspace` | ✅ **454 passed, 0 failed** |
| release binary 啟動 | ✅ `HTTP/3 (tokio-quiche) server listening ... (UDP)` |

建置依賴：BoringSSL 需要 `cmake`，bindgen 需要 `clang`／`libclang-dev`。
乾淨的 `rust:1.88-bookworm` 兩者都沒有——部署文件需要記這一條。

## 2. Linux 上的跨版本 H3 互通

客戶端 `ymuski/curl-http3`：curl 8.2.1-DEV，BoringSSL，**quiche 0.18.0**。
Pingclair 鏈結的是 quiche 0.29.3，所以這是真正的跨版本互通，不是自己驗自己。

    ready
    http_version=3
    linux-h3

詳見 `linux-h3-interop.txt`。

## 3. 功能矩陣（macOS，客戶端為 ngtcp2/nghttp3 curl 8.21.0）

**14/14 通過**，見 `h3-functional-matrix.log`。GUARDRAILS 點名的項目對照：

| GUARDRAILS 要求 | 覆蓋 |
|---|---|
| SNI | ✅ 同一 UDP port 兩個 server name 各自路由正確 |
| Alt-Svc | ✅ `alt-svc: h3=":52222"; ma=86400` |
| 多大小靜態 body | ✅ 64 B／256 KiB／8 MiB 逐位元組一致 |
| 代理 body | ✅ 4 MiB 長度正確 |
| 含 Content-Length 的 POST | ✅ 300 KiB SHA-256 一致 |
| 不含 Content-Length（chunked）的 POST | ✅ 300 KiB SHA-256 一致 |
| 413 | ✅ 5 MiB 超限回 413 |
| upstream keepalive | ✅ 四個 H3 請求共用一條上游連線 |

## 4. SSE／取消／trailer（專案既有腳本）

`scripts/test-h3-cancellation-local.sh` ✅ 通過：H3 SSE 串流、客戶端取消時
上游被關閉、request trailers 回 501、response trailers 拒絕。

## 過程中的兩個誤判（記錄下來，避免下次重踩）

1. **首次 Linux 冒煙「失敗」是測試腳本的錯**，不是產品的錯。腳本用
   `https://127.0.0.1:18443` 連線，**以 IP 連線不送 SNI**，伺服器因此挑不到憑證。
   加上 `--resolve h3.local` 後立即通過。
2. **第一版腳本有假通過**：`ldd ... || echo "無動態連結，符合預期"`，在 binary
   根本不存在時也會印出成功訊息。已改為硬性 `test -x` 加上明確 FAIL 分支。

## 尚未覆蓋

- 真實瀏覽器（Chrome／Firefox）的 H3。curl 兩種實作（ngtcp2、quiche）已覆蓋，
  但瀏覽器有自己的 QUIC 堆疊與 Alt-Svc 升級行為。
- 公網路徑（MTU、NAT、封包重排）。本次全部在 loopback 與 docker bridge。
- 0-RTT 非冪等拒絕策略——0-RTT 目前預設關閉，無可測。
