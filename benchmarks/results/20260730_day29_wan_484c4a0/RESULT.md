# Day 29 級別公網協議矩陣

**Commit**：`484c4a0`  
**日期**：2026-07-30  
**結論**：**PARTIAL／發布閘門失敗**

這次以同一個 linux/arm64 release binary 部署到 Oregon 與 Paris 的真實 EC2，
雙向經公網測試 H1、H2、H3、ACME、20 MiB 串流、連線重用，以及額外的
延遲／丟包／重排。H3 與資料完整性通過，但 TCP TLS 的公開信任鏈不完整，
因此整體不能判定 PASS。

## 1. 測試環境

| 位置 | Instance | 類型 | 公網位址 | 系統 |
|---|---|---|---|---|
| Oregon | `i-0ea09828bede16c8a` | `t4g.micro` spot | `35.163.216.237` | Amazon Linux 2023 arm64 |
| Paris | `i-06a471dc0608422d9` | `t4g.micro` on-demand | `35.181.1.70` | Amazon Linux 2023 arm64 |

- Server binary SHA-256：
  `f0cdf2e6847cc14686e4bfa2a79d72cabb2a3d89509b45a38d44b18703e1fb9e`。
- H1／H2 client：Amazon Linux curl 8.17.0，OpenSSL 3.5.5，nghttp2 1.59.0。
- H3 client：aioquic 1.2.0 官方 `http3_client.py`。
- 測試檔 SHA-256：
  - 1 MiB：`0f983ceffa84ba1cc14a7863034d73af98422028535d9a40380d70dc0f8de6a3`
  - 20 MiB：`88a31cc6e974d27437264f571b6ef12369f43839cb374956ddc8acacce497e9e`

兩端部署檔的 hash 均與本機相同。環境原始資料見
[`oregon/environment.txt`](oregon/environment.txt) 與
[`paris/environment.txt`](paris/environment.txt)。

## 2. 真實 ACME：簽發成功，但發現兩個問題

### 2.1 同一個 TLS site block 不能同時承載 HTTP-01 的 port 80

原始 fixture 在同一個 block 內設定 `listen :80`、`listen :443` 與
`tls auto { http3 }`。設定驗證會通過，但執行時顯式 TLS 會套用到該 block
的所有 listener。Let's Encrypt 對 port 80 傳送 HTTP-01 請求時，listener
把明文 HTTP 當成 TLS，記錄 `[HTTP_REQUEST]`，ACME order 變成 `Invalid`。

失敗證據：

- [`oregon/original-config-failure.log`](oregon/original-config-failure.log)
- [`paris/original-config-failure.log`](paris/original-config-failure.log)
- 原始設定：
  [`oregon/Pingclairfile.original`](oregon/Pingclairfile.original)、
  [`paris/Pingclairfile.original`](paris/Pingclairfile.original)

為了繼續驗證而沒有修改程式碼，本次把 port 80 改成獨立的 wildcard plaintext
block，port 443 保留具名 TLS block。兩份 workaround 設定先以本機 binary
執行 `validate`，均通過：

- [`oregon/Pingclairfile`](oregon/Pingclairfile)
- [`paris/Pingclairfile`](paris/Pingclairfile)

拆開 listener 後，兩端皆由 Let's Encrypt Production 完成 HTTP-01 與簽發：

- Oregon：`pingclairtest-oregon.aqeo.dev`
- Paris：`pingclairtest-paris.aqeo.dev`
- 事件摘要：
  [`oregon/acme-summary.txt`](oregon/acme-summary.txt)、
  [`paris/acme-summary.txt`](paris/acme-summary.txt)

### 2.2 H1／H2 只送 leaf，公開信任鏈驗證失敗

兩端都取得正確 SAN、有效期與 Let's Encrypt `YE1` issuer，但 curl 在沒有
`--insecure`、沒有自訂 CA 的情況下只收到一張憑證，均以 exit 60 失敗：

```text
SSL certificate OpenSSL verify result: unable to get local issuer certificate (20)
```

原始證據：

- Oregon → Paris：
  [`oregon/strict-tcp-tls-to-paris.txt`](oregon/strict-tcp-tls-to-paris.txt)
- Paris → Oregon：
  [`paris/strict-tcp-tls-to-oregon.txt`](paris/strict-tcp-tls-to-oregon.txt)

H3 的憑證路徑沒有同樣問題。aioquic 在**沒有** `--insecure` 時，雙向皆成功
驗證憑證、協商 QUIC v1／ALPN `h3`，並取得 200：

- [`oregon/strict-h3-to-paris.txt`](oregon/strict-h3-to-paris.txt)
- [`paris/strict-h3-to-oregon.txt`](paris/strict-h3-to-oregon.txt)

因此缺陷範圍是 Pingora TCP TLS callback 的 chain publication，不是 ACME
沒有簽發，也不是 H3 certificate table。

## 3. 雙向公網基線

TCP TLS 信任鏈失敗已由上一節獨立記錄。以下 H1／H2 功能矩陣使用 `-k`，
只驗證協議與 body；H3 基線也使用 `--insecure` 以保持矩陣條件一致，另有
上一節的嚴格 H3 驗證。

| 方向 | H1 health | H1 20 MiB | H2 health | H2 1 MiB | H2 20 MiB | H3 health／1 MiB／20 MiB |
|---|---:|---:|---:|---:|---:|---:|
| Oregon → Paris | 200 | hash 相符 | 200 | hash 相符 | hash 相符 | 全部 200／hash 相符 |
| Paris → Oregon | 200 | hash 相符 | 200 | hash 相符 | hash 相符 | 全部 200／hash 相符 |

H2 每個方向都以同一個 curl process 連續送出五次 health request：
第一筆 `num_connects=1`，後四筆皆為 `0`，證明連線重用。H3 每個方向將
health、1 MiB、20 MiB、health 四筆 request 放在同一個 aioquic invocation；
log 只有一個 QUIC connection ID，四筆 response 都在該連線完成。

原始證據：

- H1／H2：
  [`oregon/h1h2-summary.txt`](oregon/h1h2-summary.txt)、
  [`paris/h1h2-summary.txt`](paris/h1h2-summary.txt)
- H3：
  [`oregon/h3-baseline.log`](oregon/h3-baseline.log)、
  [`paris/h3-baseline.log`](paris/h3-baseline.log)
- H3 hash：
  [`oregon/h3-sha256.txt`](oregon/h3-sha256.txt)、
  [`paris/h3-sha256.txt`](paris/h3-sha256.txt)

## 4. netem 丟包／重排

在 Paris 的真實 egress `ens5` 暫時套用：

```text
delay 40ms 10ms distribution normal loss 0.5% reorder 5% 50%
```

Paris → Oregon 的同一條 H3 連線仍完成 health、1 MiB 與 20 MiB；兩個檔案
SHA-256 均相符。核心 qdisc 統計為 2,108 packets、實際 dropped 11：

- 套用前後：
  [`paris/qdisc-before.txt`](paris/qdisc-before.txt)、
  [`paris/qdisc-after.txt`](paris/qdisc-after.txt)
- H3 log：[`paris/h3-netem.log`](paris/h3-netem.log)
- Hash：[`paris/h3-netem-sha256.txt`](paris/h3-netem-sha256.txt)

測試命令使用 trap 移除 netem；最後
[`paris/qdisc-final.txt`](paris/qdisc-final.txt) 只剩原本的 `mq/fq_codel`，
沒有殘留 netem。

本次沒有另外降低 `ens5` MTU，也沒有保存 packet capture；MTU／NAT 覆蓋來自
EC2 私網位址到公網位址的真實跨區域路徑，而人為故障注入只涵蓋
delay／loss／reorder。不得把這份結果延伸成任意 path MTU 都已通過。

## 5. 20 MiB 串流期間 RSS

Paris 經 H3 下載 Oregon 的 20 MiB 檔案時，每 250 ms 採樣一次 Oregon
Pingclair RSS，共 60 筆。下載完成 20,971,520 bytes、SHA-256 相符；
服務端 60 筆 RSS 全部是 **46,824 KiB**，沒有隨 body 大小增加。

- Server RSS 時序：[`oregon/stream-rss-server.txt`](oregon/stream-rss-server.txt)
- Client H3 log：[`paris/stderr.log`](paris/stderr.log)

這證明本次真實 WAN 傳輸沒有重新引入 20 MiB response 全量記憶體緩衝。

## 6. 清理

驗證完成後已執行並確認：

- `i-0ea09828bede16c8a`：`terminated`
- `i-06a471dc0608422d9`：`terminated`
- `sg-0e5aa0932820decba`：刪除成功，API `Return: true`
- `sg-076b15e84c42121d0`：刪除成功，API `Return: true`
- AWS key pair 保留，未刪除。

## 7. 後續修正

本次是 frozen commit 的驗證日，沒有修改程式碼。後續 coding Day 應分開處理：

1. 讓 ACME HTTP-01 的 plaintext port 80 配置不會被同 block 的顯式 TLS
   意外轉成 TLS listener，或在設定驗證階段明確拒絕這種組合並給出可操作訊息。
2. 讓 `DynamicCertResolver` 在 H1／H2 TLS handshake 發佈完整 certificate
   chain，而不只是 leaf；新增真實 chain fixture 的負向回歸測試。
