# 2026-07-26 乾淨 Linux 驗證

- 被測 commit：`57e10f9226bf39ef190ad8007ff2c936a8d385e8`
- 環境：阿里雲深圳輕量應用伺服器，Ubuntu 24.04，x86_64，2 vCPU／1.6GB
- 工具：`scripts/validate-linux-commit.sh`
- 結果：`PASS`

腳本以完整 SHA 建立唯一暫存 checkout，完成 release workspace build、全
workspace tests、20 輪真 binary integration isolation，以及 release binary
與 Admin API 的 loopback smoke。結束後 listener 已釋放，暫存 checkout 已由
腳本自己的 cleanup 移除。

小記憶體主機使用 `CARGO_PROFILE_TEST_DEBUG=0` 與 `CARGO_INCREMENTAL=0`，
只移除測試 binary 的 debug info 並關閉 incremental cache，不改變測試程式、
release profile 或 runtime 行為。
