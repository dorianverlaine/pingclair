# Getting Started 需求文檔（官方教學流程 vs Pingclair）

> 📌 Caddy 官方「Getting Started」教學把同一件事用四種方式各做一遍：
> 空 daemon → API 餵 config → Caddyfile → CLI 啟動。本專項不做
> 重複審查，而是把教學的每一步對應到先前專項的發現，提供一份
> **「照教學走會卡在哪」**的單一視圖。

## 1. 教學流程 × Pingclair 對照

| 教學步驟 | Caddy 行為 | Pingclair | 對應發現 |
|---|---|---|---|
| `caddy`（無子命令） | 顯示 help | ✅ clap 預設顯示 help | — |
| `caddy run`（無 config） | 空 config + admin API（localhost:2019）啟動 | ❌ 必須有 config 檔，`Pingclairfile` 不存在直接 exit 1 | CLI C6、admin A2/A6 |
| `curl localhost:2019/config/` | 回傳空 config | ❌ admin 預設不啟動；`GET /config/`（尾斜線）404 | admin A6/A7 |
| `POST /load` 上傳 JSON | 整包替換 | ❌ 沒有 `/load`；`POST /config` 只收單一 ServerConfig | admin A2/A8 |
| 測試 `localhost:2015` | Hello, world! | —（依賴上述兩步） | — |
| 寫 `:2015` Caddyfile | 單站簡寫 | ❌ 每行 directive 變獨立 server（U1）；`:2015` 本身 OK | tutorial U1 |
| `caddy adapt` | Caddyfile→JSON | ❌ 無此命令（能力存在但沒 CLI） | CLI C1 |
| `caddy run`（有 Caddyfile） | 自動偵測 `Caddyfile` | ❌ 預設只找 `Pingclairfile` | CLI C7 |
| `--resume` | 恢復上次 API config | ❌ 無 persistence | admin A5、CLI C6 |
| `caddy start`／`caddy stop` | 背景啟動/停止 | ❌ 只有 systemd `service` 包裝 | CLI 對照表 |
| `caddy reload` | 零停機換 config（新舊並存、失敗 rollback） | ❌ 只能 SIGHUP；global 被丟、新 listen 要重啟 | admin A1/A8、CLI C3 |

## 2. 教學隱含但值得記錄的語義

### S1：config file 只是 API 的另一個入口

Getting Started 明說：「Under the hood, even config files go through
Caddy's API endpoints; the `caddy` command just wraps up those API
calls for you.」Pingclair 的架構相反：**啟動必讀檔案，API 是
附屬的熱更新**，兩者不是同一條管道——這解釋了為什麼 `/load`、
`reload`、`--resume` 全部缺。如果 Pingclair 要把 API 工作流當
一等公民（admin 文檔 A 系列），這個「檔案→API 統一入口」的模型
是設計決策，需要明確選擇。

### S2：「一個 source of truth」

教學建議不要混用 API 與 config file。Pingclair 現況下 API 熱更新
與檔案重啟本來就不同步（A1/A5），文件應直接寫明「API 變更重啟
即失；不要混用」。

### S3：零停機 reload 的承諾

教學強調「new config 先啟動、舊 config 後停止；失敗就 rollback」。
Pingclair 的 SIGHUP reload 是**就地更新既有 listener 的 server
狀態**（`proxy.update_config`），不是新舊並存；新 listen 位址
直接警告「需要重啟」——即 reload 會造成該位址的停機。這是
「zero-downtime」宣稱的實質差距（admin 文檔 A1 已記錄一半）。

## 3. 補充建議

1. 把「Getting Started 流程」加入整合驗收：**從零啟動 → 用 API
   餵 config → 訪問網站**的端到端測試（目前第一步就卡住）；
2. 文件（README 三語）加一段「Pingclair 與 Caddy 工作流差異」：
   Pingclair 以 config file 為 source of truth，API 為輔；
3. `pingclair run` 無 config 時的錯誤訊息改為
   「找不到 Pingclairfile/Caddyfile（目前不支援空 config 啟動）」，
   避免使用者以為是漏裝檔案。

## 4. 本專項沒有新 bug

Getting Started 的內容全部落在先前專項已記錄的發現內（見對照表）。
本檔的作用是把分散的發現組回「教學流程」視圖，供修復排期與
README 撰寫使用。
