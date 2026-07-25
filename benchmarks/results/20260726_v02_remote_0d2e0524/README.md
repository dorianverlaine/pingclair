# 2026-07-26 公網 80／443 驗證

- 被測 commit：`0d2e05247e186ed205ad7c1a8c1c98de53282b5b`
- 伺服器：阿里雲深圳，Ubuntu 24.04，2 vCPU／1.6GB
- 執行方式：VPS 上由乾淨 checkout 建置 release Pingclair，實際綁定
  80 TCP、443 TCP+UDP；macOS 本機透過公網發送 HTTP/1.1、HTTP/2、HTTP/3
  請求。Admin 2019 僅綁定 loopback。
- 測試憑證：為 `pingclair-v02.test` 即時建立的短效自簽憑證；私鑰未收錄。

## 結果

- 通過：HTTP 80、HTTPS H1、HTTP 308 redirect、自訂 404、CORS simple 與
  preflight、UA deny、regex rewrite＋query、primary 全掛時 backup 8/8 接手。
- 通過：真實 QUIC/H3，連續 10 次公網請求皆為 HTTP/3 200。
- 通過：Admin 2019 從公網無法連線。
- 失敗：H2 未協商 ALPN，curl 退回 HTTP/1.1。
- 失敗：LB 設定 3:1，40 次請求實測為 20:20。
- 已知缺口：H3 的 CORS、access control、rewrite 回 501；自訂
  `error_page` 未套用。

H2 ALPN 與 LB weight 的根因已分別在 `e9213ec` 修正；本目錄保留失敗證據，
不可當成修正後驗收結果。修正後須使用新的精確 commit 與獨立結果目錄重測。
