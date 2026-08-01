# Caddy 官方 Examples 需求文檔

> 📌 官方網站首頁/文件內嵌的 examples 區塊（custom CA、file
> server、FrankenPHP、local HTTPS、on-demand TLS、proxy、
> website Caddyfile）。**這些是使用者「直接複製貼上」的片段**，
> 逐個實測（2026-08-01，探針已刪除）。

## 1. 逐範例結果

| 範例 | 結果 | 卡點 |
|---|---|---|
| Custom CA（`pki` + `acme_server`） | ❌ | `Unknown directive 'global: pki'`；`acme_server` 也不存在 |
| File server（`precompressed`/`fs`/`encode`/`browse`） | ❌ | 無大括號簡寫（U1）＋ `precompressed`/`fs` 靜默吞（E-1/E-2） |
| FrankenPHP（`frankenphp`/`php_server`） | ❌ | 兩者都不存在（v0.3+） |
| Local HTTPS（`localhost`/`192.168.1.10`/`http://localhost`） | ❌ | `Duplicate server name: localhost`（E-3）＋ 本機 HTTPS 缺口（T6） |
| On-demand TLS（`on_demand_tls`/`https://`/`tls { on_demand }`） | ❌ | `on_demand_tls` 不存在；`https://` catch-all 解析錯（E-4）；`tls { on_demand }` 不認 |
| Proxy（`dynamic srv`/`lb_try_duration`/`fail_duration`） | ❌ | `root` 缺（P1）＋ `dynamic`/`lb_try_duration`/`fail_duration` 靜默吞（E-5）＋ 單行多 `to` 被拒（E-6） |
| Website Caddyfile（`templates`/`redir`/`rewrite`） | ❌ | `root`/`templates` 缺＋ `redir` 尾斜線被當 status（P4 同源） |

7 個官方範例全滅。

## 2. 新確認問題

### 🔴 E-1：`file_server` block 子指令靜默吞（`precompressed`、`fs`）

```caddy
file_server /downloads/* {
    precompressed
}
```

實測（braced 寫法）：編譯成功，`precompressed` 被忽略、
`root: "/downloads/*"`（連 path matcher 也當成 root）、route 是
`/*`——**所有請求都進 file_server 且不做 precompressed 查找**。
`fs sqlite data.sql` 同理被吞。file_server adapter 的
`_ => {}` catch-all（adapter/caddyfile.rs :811）與 reverse_proxy/
log 是同一個 bug class。

需求：`precompressed`（runtime 其實有 `precompressed: true` 預設——
見 server.rs FileServer 建構）與 `fs` 至少 fail closed；完整
`precompressed <formats>`／`fs <module>` 列 v0.3。

### 🔴 E-2：`file_server /path/*` 的 inline path matcher 被當 root

Caddy：`file_server /downloads/* { ... }` 的 `/downloads/*` 是
**matcher**（只服務該路徑）。Pingclair：當成 root 目錄字串
（`root: "/downloads/*"`）且 route `/*`——全部請求都打到一個不
存在的路徑。與 P3（`reverse_proxy /api/*`）同一根因：`/` 開頭
第一參數沒被解析為 matcher。

### 🟠 E-3：`localhost` 與 `http://localhost` 撞名

```caddy
localhost { respond "https" }
http://localhost { respond "http" }
```

Caddy：一個 HTTPS（本機 CA）一個明文 HTTP，兩者都合法且不同
server。Pingclair：兩個 site 的 name 都變成 `localhost` →
`Duplicate server name`（位址文檔 B3 的 name 處理 + semantic
duplicate 檢查共同造成）。修 A-2（name 不塌陷）時要確保不同
scheme 的 site 可共存；修 T6（localhost 自動 HTTPS）時這個範例
是驗收 case。

### 🟠 E-4：`https://` catch-all 被當字面 hostname

```caddy
https:// {
    respond "x"
}
```

編譯成功但 `name="https://"`、listen `0.0.0.0:80`——Caddy 語意是
HTTPS catch-all（443，無 Host matcher）。`parse_server_address`
對 `https://`（rest 為空）回 None，名稱卻保留字面值。

### 🟠 E-5：`dynamic`、`lb_try_duration`、`fail_duration` 靜默吞

```caddy
reverse_proxy /api/* {
    dynamic srv _api._tcp.example.com
}
reverse_proxy /service/* {
    to 10.0.1.1:80 10.0.1.2:80 10.0.1.3:80
    lb_policy least_conn
    lb_try_duration 10s
    fail_duration 5s
}
```

實測：`dynamic srv ...` 被 catch-all 吞掉（upstream 只剩
`/api/*` 這個假位址）；`lb_try_duration`/`fail_duration` 也吞掉。
這些是 Caddy 官方 proxy 範例的核心（SRV 動態後端、LB 嘗試時間窗、
失敗視窗），靜默無效 = 使用者以為有 HA/自動擴容，實際只有靜態
轉發。

### 🟠 E-6：單行多 `to` 被拒

`to 10.0.1.1:80 10.0.1.2:80 10.0.1.3:80` 是 Caddy 官方寫法；
Pingclair 的 `to` 只收一個 address（`expect exactly one upstream
address`）。`to` 支援多個 + `{ weight/backup }` 子 block 是 LB
範例的基礎。

## 3. 驗證需求

1. 官方 examples 頁 7 段原文全部進 compile fixture（紅燈清單）；
2. `file_server /downloads/* { precompressed }`：path matcher 生效、
   precompressed 查找生效（或明確拒絕）；
3. `localhost` + `http://localhost` 共存（一個 TLS 一個明文）；
4. `https://` catch-all：443 + 無 Host matcher；
5. `dynamic srv`/`lb_try_duration`/`fail_duration`/多 `to` 至少
   fail closed。

## 4. 明確不做（本文件範圍外）

- `pki`/`acme_server`（自建 CA + 內嵌 ACME server）——v0.3+。
- FrankenPHP——v0.3+（patterns 文檔同）。
- On-demand TLS——v0.3+（automatic-https 文檔同）。
- `fs` 模組（sqlite/embedded file system）——v0.3+。
