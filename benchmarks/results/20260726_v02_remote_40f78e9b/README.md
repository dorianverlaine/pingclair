# 2026-07-26 公網 H3 存取控制驗收

- 精確 commit：`40f78e9bd8b298021ac2d8972c48358ac87f5f42`
- 執行端：阿里雲深圳 VPS，Ubuntu 24.04。
- 流量來源：macOS 本機經公網送往 VPS `443/UDP`。
- 客戶端：Homebrew curl 8.21.0，ngtcp2 1.24.0、nghttp3 1.17.0。
- fixture：真實 Pingclair binary，綁定 80 TCP、443 TCP+UDP，Admin 僅綁
  loopback。
- binary SHA-256：
  `6518af95c563023b70bb62d95c813021bcf04bb1427f4e2e223f6852b410e2b5`

## 結果

- H1、H2、H3 對 `BlockedBot/1.0` 均回 `403`。
- H3 deny 連續 10 次皆為 `HTTP/3 403`。
- H1/H2 對允許的 UA 與 Origin 均回 `200`。
- H3 對允許的 UA 通過共用 access gate，但 pipeline dispatch 仍回 `501`。這證明
  本次 H3 access control 已生效，也保留了 CORS／pipeline parity 尚未完成的真實
  缺口。
- H3 `/ready` baseline 回 `HTTP/3 200`。
- VPS tcpdump 捕獲 40 個 `443/UDP` 公網封包，66 個封包通過 filter，kernel
  drop 為 0。
- fixture 停止後，80、443、2019、9001–9003 均無本次 listener，也無本次
  Pingclair、upstream、tcpdump 或編譯程序殘留。

## 編譯說明

第一次使用全新 target 與 workspace fat LTO，在 1.6 GiB VPS 的最終 link
階段造成 SSH 排程困難；確認完整 cmdline 與專屬 PGID 後，只終止本次 run
directory 的 process group。第二次復用已完成的 target，設定
`CARGO_PROFILE_RELEASE_LTO=false`、
`CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16`、`CARGO_BUILD_JOBS=2`，8 分鐘完成。
此 binary 用於功能與協議驗證，不作為正式發布 artifact 或效能結果。

原始檔案：

- `client-results.txt`：本機 curl 協議與狀態碼結果。
- `h3-tcpdump.log`：VPS 公網 UDP 封包證據。
- `functional-release-build.log`：低記憶體 release build log。
- `listeners-ready.txt`／`listeners-after-stop.txt`：啟動與清理後 listener。
- `metrics-before.prom`、`pingclair.log`：fixture runtime 證據。
- `commit.txt`、`binary-sha256.txt`：來源與 binary 身分。
