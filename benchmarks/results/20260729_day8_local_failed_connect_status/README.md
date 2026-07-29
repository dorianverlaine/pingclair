# Day 8 本機失敗證據：connect timeout 遺失 504 語意

- 日期：2026-07-29
- 分支：`codex/m2-day8-10`
- 指令：`cargo test -p pingclair --test integration test_streamed_limits_and_timeout_phases_are_explicit_and_bounded -- --nocapture`
- 結果：失敗。飽和 accept backlog 的上游在 100 ms connect timeout 後回傳
  `502 Bad Gateway`，測試預期 `504 Gateway Timeout`。

首次 connect timeout 會把唯一 upstream 標為暫時不健康；Pingora redispatch
接著看見「無可選 upstream」，使原本的 timeout 類型退化成一般 502。
修正會在 request context 保留 connect-timeout 原因；只有此情況在 pool
耗盡後維持 504，其他無可選 upstream 仍維持既有 502 語意。修正後測試轉綠。

這是本機真 binary regression，未在 Linux/VPS 驗證。
