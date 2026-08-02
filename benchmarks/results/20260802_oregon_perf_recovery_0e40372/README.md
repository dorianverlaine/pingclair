# 2026-08-02 Oregon 效能回歸修復驗證

這份結果用來比較 `main`、修復前的 `0e40372`、修復後 working tree、nginx
與 Caddy。所有伺服器在同一台 `t4g.micro` 上輪流執行，唯一 client 是同一
Availability Zone 內的 `t4g.small`，流量只走 VPC 私網。

## 有效性檢查

- 每個 H1 candidate 起動後，先以 `Host: bench.local` 驗證 HTTP `200`、
  1024 bytes 與 payload SHA-256 `2eef22c3...92cf2a2e73`。
- H3 client 每輪只把 status `200` 且 body 恰為 1024 bytes 的 request 計為
  passed；下表各輪均為全數通過。
- 四個 candidate 共用同一份 payload 與同一張 ECDSA P-256 憑證。
- 曾有一輪 H1 未送正確 Host header，Pingclair 回的是 `404`。那批數字已棄用，
  沒有納入下列結果；這也是後續 benchmark 必須先驗證 body 的原因。

## 中位數摘要

| 場景 | main `f888938` | 修復前 `0e40372` | 修復後 | nginx 1.28.3 | Caddy 2.11.4 |
| --- | ---: | ---: | ---: | ---: | ---: |
| H1 1 KiB，metrics on | 32,483.31 | 30,965.66 | 31,756.65 | 64,790.20 | 16,503.92 |
| H1 1 KiB，metrics off | — | — | 32,221.17 | — | — |
| H3，每 request 新連線 | 94.76 | 96.27 | 110.87 | 134.90 | 130.84 |
| H3，20 條長連線／10,000 requests | 1,601.99 | 1,646.12 | 1,647.33 | 2,069.43 | 1,955.73 |

單位都是 requests/second；每格是三輪的中位數。H1 使用
`wrk -t2 -c100 -d10s`，另有 5 秒暖機。H3 新連線使用 30 concurrency／
300 requests；長連線使用 20 connections／10,000 requests。

## 解讀

- H1 修復後比修復前快 2.6%；停用 metrics 時快 4.1%，只比 `main` 慢 0.8%。
  回歸來自 ingress 已正規化路徑卻在 Router 再配置一次 `Vec`／`String`，以及
  metrics 關閉後仍解析 label、查找 Prometheus collector。
- H3 新連線比修復前快 15.2%。封包證據顯示修復前每條連線都是
  `Initial 1200 B -> Retry 95 B -> Initial 1200 B`；修復後第一個 server
  packet 直接是 1200 B handshake response。對 nginx 的差距由 28.6% 收窄到
  17.8%，對 Caddy 的差距由 26.4% 收窄到 15.3%。
- H3 長連線修復前後相差 0.1%，表示改善集中在連線建立，沒有用停用 middleware、
  streaming、request cancellation 或 Caddy 相容功能換取數字。

原始三輪輸出在 `raw-results.txt`；完整環境、binary hash 與命令在
`metadata.txt`。`head-retry.pcap` 與 `final-no-retry-2.pcap` 保留修復前後的
QUIC 封包證據，client 原始碼與三份 server 設定亦一併保留。

## 效能量測後的功能閘

遠端量測完成後，Day 28 的真實 H3 功能 matrix 在 5 MiB POST 提早回覆 `413`
的路徑發現 bounded body receiver 關閉後未喚醒 event loop，client 因而可能
卡住。最終 working tree 已補上關閉後的喚醒，並通過 14/14 matrix，以及 SSE、
downstream cancellation、upstream teardown 和 trailer rejection 測試。這個
正確性修補發生在表內 binary 建置之後；上表與 `raw-results.txt` 仍只描述
`metadata.txt` 所列 hash 的實際量測，沒有將不同 binary 的數字混在一起。
最終 working tree 另在 ARM Linux／Rust 1.88 完成 fat-LTO release build；
完整 binary hash 記錄在 `metadata.txt`，不冒充同一組遠端壓測結果。
