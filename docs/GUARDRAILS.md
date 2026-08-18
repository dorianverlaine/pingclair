# ⚠️ Pingclair 實作守則

> 動手改程式碼或跑驗證**之前**先讀這份。這裡記錄的都是踩過的坑，
> 不是理論建議——每一條後面都有一次實際失敗。
>
> 這份文件本身只是索引：內容依子系統拆成四份，只讀跟這次改動相關的那一兩份。
> 2026-08-05 拆分，內文逐字搬移，一條規則都沒有改寫或刪去。

| 文件 | 涵蓋 |
| --- | --- |
| [`guardrails/testing.md`](guardrails/testing.md) | 測試與除錯環境、幽靈程序、本機工具鏈與代理、CI 工作流、驗證證據的存放規則 |
| [`guardrails/config.md`](guardrails/config.md) | **驗證放哪一層**（adapter 的規則 = Admin API 繞得過的規則）、不能兌現的設定要 fail closed、量測工具自己的缺陷、「編得過」不等於「編對」 |
| [`guardrails/tls.md`](guardrails/tls.md) | 依賴與鏈結（BoringSSL 單一鏈結、`[patch.crates-io]` 對 audit 的影響）與安全預設（fail closed、遮罩、憑證與信任素材） |
| [`guardrails/proxy.md`](guardrails/proxy.md) | HTTP/3 為什麼釘在 quiche／BoringSSL、`quic.rs` 的架構與正確性、串流與記憶體 |

- 接下來要做什麼 → `docs/TODO.md`（🔒 維護者本機文件，未進倉庫）
- 新發現但還不該現在修的問題 → `TRIAGE.md`（倉庫根目錄）
- 已完成與驗證證據 → 本機 `benchmarks/results/`（不入倉庫）

> 📌 新增一條守則時寫進對應的子文件，不要寫回這份索引——索引一長出內容，就會變成第五份要同步的文件。
