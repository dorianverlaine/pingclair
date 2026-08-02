# 2026-08-02 OrbStack 熱路徑效能修復

本次測試只在本機 OrbStack Linux VM 內執行。client 與候選 server 位於同一個
隔離 bridge network，沒有經過 macOS published-port NAT；每個容器限制為
2 vCPU／512 MiB，候選 server 逐一執行。所有協定共用 1 KiB payload，TLS
候選共用同一張臨時 ECDSA P-256 憑證。

表格是三輪中位數，單位均為 requests/second。每個 H1/H2 candidate 起測前
都驗證 `200`、1024 bytes 與 SHA-256；H2 每輪 30,000 requests 全數成功；
H3 client 只把 `200` 且 body 恰為 1024 bytes 的 request 計為成功，各輪均
零失敗。

| 場景 | 修復前 `0e40372` | 修復後 | nginx 1.31.3 | Caddy 2.11.4 |
| --- | ---: | ---: | ---: | ---: |
| H1 1 KiB | 55,207.20 | 56,965.75 | 64,719.17 | 25,464.92 |
| H2 1 KiB | 45,099.76 | 48,779.06 | 49,499.64 | 18,829.32 |
| H3，每 request 新連線 | 190.66 | 247.34 | 249.26 | 234.90 |
| H3，20 條重用連線 | 5,164.49 | 5,304.48 | 6,020.13 | 4,108.13 |

修復後 H1 比修復前快 3.2%，達 nginx 的 88.0%；H2 快 8.2%，達 nginx 的
98.5%。H3 新連線快 29.7%，與 nginx 相差 0.8%；H3 重用連線快 2.7%，達
nginx 的 88.1%。修復後四個場景均高於 Caddy。

Linux `strace -c` 先確認了主要固定成本：修復前一次靜態 request 會深複製
`ProxyState` 及其多個 `Vec`，並重複複製 handler tree；檔案路徑還會做兩次
`statx`。現在虛擬主機表發佈 `Arc<ProxyState>`，request 只保留同一份 immutable
snapshot 並借用 handler；請求 scheme 與 client IP 不再做無效的配置與
字串往返；一般檔案沿用第一次 metadata。Native macOS debug A/B 亦由
18,369.08 提升至 21,590.54 req/s（+17.5%），方向一致。

剩餘約 12% 的 H1／H3 長連線差距沒有用整檔快取或改變檔案更新可見性來換取。
nginx 的靜態路徑使用 `sendfile`，Pingclair/Pingora 仍在 userspace 讀取並傳送；
下一步若要處理這個差距，應先建立等價的 zero-copy response API，而不是繞過
Caddy 相容的 routing、middleware 或即時檔案語義。

詳細版本、binary/image hash、命令與憑證 fingerprint 在 `metadata.txt`；每輪
輸出在 `raw-results.txt`。量測 binary 的 SHA-256 是 `5a760d87...e49509`；
量測後只修正三處 Rust 等價借用寫法並新增 Arc identity regression test，最終
working tree 的 Rust 1.88 ARM Linux release SHA-256 是
`90dc1be0...cbbc89`。本目錄不保存臨時憑證或私鑰。
