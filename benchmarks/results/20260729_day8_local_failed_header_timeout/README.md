# Day 8 本機失敗證據：header timeout 未涵蓋 h2c preface

- 日期：2026-07-29
- 分支：`codex/m2-day8-10`
- 指令：`cargo test -p pingclair --test integration test_listener_resource_limits_reject_before_dispatch_without_hanging -- --nocapture`
- 結果：失敗。只送出不完整 HTTP/1 header 的 client 在測試期限內未被關閉。

原因是 Pingora 在建立 HTTP/1 session 前，會先用 `try_peek` 判斷 h2c preface；
該等待原本不在新設定的 `header_timeout` 範圍內，因此 slowloris 連線可停在 parser
之前。修正後，preface peek 與其後剩餘的 header read 共用同一個期限，測試轉綠。

這是本機真 binary regression，未在 Linux/VPS 驗證。
