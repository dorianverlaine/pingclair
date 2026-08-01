# Automatic HTTPS 需求文檔（對照 Caddy 官方 automatic-https）

> 📌 本專項以 Caddy 官方文檔（`automatic-https`，本機
> `~/code/caddy-website`）為基準，對照 Pingclair 的
> `pingclair-tls` crate 與 `main.rs` 的 TLS 啟動路徑。這是
> Caddyfile 相容性的核心：**「寫好網域就能上 HTTPS」是 Caddy 的
> 招牌，也是本專案宣告的承諾（README.md:215）。**

## 1. Caddy 官方語義（需求基準）

### 1.1 預設全站 HTTPS

- hostname/IP site 位址 → 自動 HTTPS（公開網域走 ACME、localhost／
  本機 IP 走本機 CA）；
- 自動：簽發＋續期所有合格網域憑證、HTTP→HTTPS 308 轉跳、ACME
  HTTP-01（port 80）＋TLS-ALPN-01（port 443）challenge；
- 停用條件（任一）：`auto_https off`、無 hostname/IP、只監聽 HTTP
  port、site 位址是 `http://`、手動載入憑證。

### 1.2 Hostname 資格

- 合格：非空、只含 alphanumeric/hyphen/dot/wildcard、不以點開頭結尾；
- 公開信任：非 localhost（含 `.localhost`／`.local`／`.internal`／
  `.home.arpa`）、非 IP、wildcard 只在最左 label 且唯一。

### 1.3 Challenge 三型

| Challenge | 需要 | 預設 |
|---|---|---|
| HTTP-01 | port 80 對外 | ✅ 預設啟用 |
| TLS-ALPN-01 | port 443 對外 | ✅ 預設啟用 |
| DNS-01 | DNS provider 憑證（wildcard 必須） | 設定後才啟用（啟用後其他停用） |

### 1.4 錯誤處理與 issuer fallback

- 憑證管理在**背景**執行，不擋啟動；
- 失敗：立即重試一次 → 換 challenge 型別 → 換 issuer
  （Let's Encrypt → ZeroSSL）→ 指數退避（最長 1 天）→ 最多 30 天；
- 退避期間 LE 失敗會切 staging 避開 rate limit；
- 內建 rate limit（每帳戶每 10 秒 10 次）；
- config reload 會中止 in-flight ACME task。

### 1.5 儲存

- 公開憑證/私鑰存 data directory；`$HOME` 需可寫、持久；
- 多實例共用 storage 可叢集協調（同網域只發一次）；
- 發 ACME 前先測 storage 可寫與容量。

## 2. 現況盤點

| Caddy 能力 | Pingclair 現況 |
|---|---|
| hostname site 預設 443 | ❌ **被位址 bug 擋住**（`tls auto` 只開明文 80，見位址文檔 B0/B1） |
| localhost／IP 預設 HTTPS | ❌ 預設明文 80（位址文檔 B5）；`tls internal` 有能力但不自動 |
| 背景簽發 | ❌ 只在 **TLS handshake 惰性觸發**（`resolve_cert` → `get_certificate`） |
| HTTP-01 | ✅ PersistentChallengeHandler（token 落盤、可跨重啟） |
| TLS-ALPN-01 | ❌ enum 有 `TlsAlpn01` 但**沒有 handler 實作** |
| DNS-01（wildcard） | ❌ enum 有 `Dns01` 但**沒有 handler 實作**；`tls { dns }` adapter 也不認 |
| issuer fallback | ❌ 只支援 Let's Encrypt，無 ZeroSSL |
| 失敗退避 | ❌ renewal task 每 12h 掃一次，失敗只 log、等下次 |
| 續期 | ✅ 30 天閾值 + 12h 掃描（`needs_renewal`） |
| 本機 CA（internal） | ✅ `tls internal`：atomic authority.json、root.crt 發佈、H1/H2/H3 共用 |
| storage 叢集協調 | ❌ 本機檔案，無共享 storage 機制 |
| ACME 前 storage 測試 | ❌ 無 |
| 每帳戶 rate limit | ⚠️ 依賴 instant_acme default RetryPolicy，無自訂節流 |

## 3. 已確認問題（依影響排序）

### 🔴 T1：`tls auto` 的簽發路徑被位址 bug 完全擋住（B0 的後果）

`example.com { tls auto }` 編譯出 `listen=["0.0.0.0:80"]`、TLS=false
（位址文檔 B 系列已實測）。更糟的是：**就算 443 開了，Pingclair
也沒有 eager issuance**——ACME 只在 TLS handshake 的
`resolve_cert()` 裡觸發。443 不開 → 沒有 handshake → ACME 永遠不跑，
與 bug 報告的「ACME manager 初始化但從未簽發」完全吻合。

**修復順序**：先修位址推導（B0/B1），再補 eager issuance（T2），
兩者缺一不可，否則 `tls auto` 在真 binary 上依然只有 80。

### 🔴 T2：沒有背景 eager issuance——首次 handshake 阻塞式簽發

Caddy：config load 後背景為所有合格網域簽發，失敗指數退避，server
不等憑證即可啟動。Pingclair：`get_certificate` 只在 handshake 時呼叫，
第一個訪客的 TLS handshake 要等 ACME 跑完（可能數秒到數分鐘），且
沒有 retry 隊列——失敗就 `warn` 然後下一次 handshake 再試。

**期望**：`main.rs` 啟動時（或獨立 task）對所有
`tls auto` 且具名 site 的網域發起背景簽發；handshake 時 store 有
憑證就直接用。

### 🟠 T3：TLS-ALPN-01 沒有實作

Caddy 預設啟用 HTTP-01 與 TLS-ALPN-01（challenge 隨機選、累積偏好）。
Pingclair 的 `ChallengeType` enum 有 `TlsAlpn01`，但唯一的 concrete
handler 是 HTTP-01（Memory/Persistent）。443 打不開或 CA 探測被
防火牆擋時，Pingclair 沒有備援 challenge。**注意**：實作 TLS-ALPN-01
需要改 H3/TLS acceptor 的 ALPN 處理，是 GUARDRAILS 級別的改動。

### 🟠 T4：wildcard 憑證完全不可用（DNS-01 缺）

`*.example.com` site 需要 DNS-01（LE 規定）。Pingclair：`Dns01` 無
handler、`tls { dns <provider> }` adapter 不認、`abort` directive
缺、`host` matcher DSL 缺（matchers 文檔 M5）。wildcard 場景四缺四。

### 🟠 T5：無 issuer fallback 與失敗退避

Caddy：LE 失敗 → ZeroSSL → 指數退避（最長 1 天）→ 30 天；退避期間
切 staging。Pingclair：renewal task 每 12h 掃描，`get_certificate`
失敗直接 `error` log，下次掃描再試——沒有退避、沒有 fallback issuer、
沒有 staging 切換。CA 故障時每次掃描都會硬碰 LE rate limit。

### 🟡 T6：localhost／本機 IP 沒有自動 HTTPS

Caddy：`localhost`、`127.0.0.1` 預設 HTTPS（本機 CA 簽發、root 安裝
到 trust store）。Pingclair 有 `tls internal`（本機 CA），但
`localhost { }` 預設明文 80；使用者必須**手動**寫 `tls internal`。
Caddy 語意是「寫網域就有 HTTPS」，本機網域不該是例外。

### 🟡 T7：storage 無容量預檢、無叢集協調

Caddy 發 ACME 前測試 storage 可寫/容量；多實例共用 storage 時同網域
只發一次。Pingclair 的 CertStore/account store 都是本機檔案，無預檢、
無跨實例鎖。這對單機部署不是 bug，但文件應標明「多實例需自己協調」，
避免兩台同時對同網域發 ACME 撞 rate limit。

### 🟡 T8：reload 時 in-flight ACME 不中止

Caddy 明確「config 變更時中止 in-flight ACME task」。Pingclair 的
SIGHUP reload（admin 文檔 A1）不碰 TLS manager 的 processing set，
reload 期間進行中的 `get_certificate` 照跑；且 `tls auto` 的 renewal
task 是 tokio::spawn，reload 後可能與新設定並存。

## 4. 驗證需求

1. **位址層**（先於一切）：`example.com { tls auto }` 編譯後 listen
   空或「無顯式 listen」，main.rs 走 443 分支；
2. **真 binary 整合**（本機可用 staging）：
   - `tls auto` + `acme_ca staging`（或測試目錄）→ 啟動後
     `ss` 有 443（TLS）+ 80 companion；首次簽發**不需手動觸發
     handshake**（T2 修完的判準）；
   - HTTP→HTTPS 308；ACME HTTP-01 應答正常；
   - 斷網情境：啟動不阻塞、log 有退避跡象、恢復後自動簽到；
3. **Linux/VPS**（AGENTS.md 要求）：release binary + 公網 staging
   全流程一次；`docs/STATUS.md` 記錄 commit、命令、結果路徑；
4. **回歸**：`tls internal`、manual cert、`listen :8443` +
   `tls auto`（現況唯一正常的路）行為不變。

## 5. 明確不做（本文件範圍外）

- ECH（Encrypted ClientHello）——列 v0.3+，依賴 DNS provider 生態。
- On-Demand TLS——列 v0.3+（需要 handshake-time 簽發與 ask 限制）。
- DNS provider 生態（acme-dns 外掛）——列 v0.3+。
- `.ts.net`（Tailscale）等特殊網域處理。
