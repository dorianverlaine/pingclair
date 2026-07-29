# Day 8 本機失敗證據：SSE content type 被一般 request deadline 中止

- 日期：2026-07-29
- 分支：`codex/m2-day8-10`
- 指令：`cargo test -p pingclair --test integration test_streamed_limits_and_timeout_phases_are_explicit_and_bounded -- --nocapture`
- 結果：失敗。未設定 `flush_interval -1`、但 upstream 回傳
  `Content-Type: text/event-stream` 的 response，在 300 ms event 抵達前被關閉。

Pingora 0.8 的 H1/H2 upstream session 只有一個 read timer，而且在收到 response
header 前就從 peer options 複製；若把一般 request deadline 提前壓進該 timer，
後續在 `response_filter` 辨識 SSE 時已無法放寬。修正後，明確設定的
first-byte／between-reads phase bound 保持不變；未設定 phase timer 時，H1/H2
以明確配置的 long-connection idle bound 保留升級空間。response header
抵達後再切換 long-connection request／downstream idle policy；同一測試轉綠。

這是本機真 binary regression，未在 Linux/VPS 或真 QUIC client 驗證。
