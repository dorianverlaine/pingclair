# 2026-07-26 公網 H1／H2／H3 與 LB 修正驗收

- 被測 commit：`af497fdd2dee46a97a06c98f7add119982c102f8`
- release binary SHA-256：
  `11db2872500a3d4398018a598e336e84faa4373618b4fbdea3e8a82d3af65d60`
- 伺服器：阿里雲深圳輕量應用伺服器，Ubuntu 24.04，2 vCPU／1.6GB
- 流量來源：macOS 本機經公網送往 VPS 80 TCP、443 TCP+UDP
- 結果：`PASS`

## 已通過

- HTTP/1.1 80 與 HTTPS 443。
- HTTP/2 200，curl 回報 version 2；OpenSSL ALPN 協商 `h2`。
- HTTP/3 連續 10 次皆為 version 3／200。
- H2 自訂 404、CORS simple／合法 preflight／非法 origin 不輸出允許標頭、
  UA deny 403、regex rewrite 與 query。
- LB 3:1 的 40 次請求精準分布為 30:10。
- 兩個 primary 停止後，backup 8/8 接手。
- Admin 2019 從公網不可連線。

fixture 結束時逐一核對自己記錄的 PID 與 cmdline，停止 Pingclair 和三個
upstream。遠端 80/443/2019/9001–9003 及 21209 最終均無本次 listener。

## 仍未完成

本次未宣稱 H3 middleware parity 完成；舊 commit 的證據已確認 H3 CORS、
access control、rewrite 與自訂 `error_page` 仍是 R3 缺口。IP／Referer 完整
allow／deny、死亡 upstream 502 自訂頁，以及 primary recovery 也留待後續矩陣。
