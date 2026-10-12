# Pingclair 官方網站

[English](README.md) · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · **繁體中文**

## 概述

官方網站：[https://pingclair.com](https://pingclair.com)

網站原始碼放在獨立的儲存庫
**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**。
這個目錄只保留正式環境的設定檔 [`Pingclairfile`](Pingclairfile)，作為用 Pingclair
部署靜態文件網站的實際範例：

- 自動 TLS 憑證與 HTTP/3
- 以主機名稱區分的三個虛擬主機
- 靜態檔案、自訂 404 頁面與壓縮
- 反向代理與回應快取
- 在同一個網址提供 Markdown 給 AI 代理
- 永久轉址到正規網域
- JSON 存取日誌與內建輪替

網站跑在一台 FreeBSD 伺服器上。`pingclair.pingclair.com` 保留作為測試用主機名稱，
`www.pingclair.com` 則永久轉址到主網域。設定檔是 Pingclairfile，也就是 Caddyfile
語法；以下的節錄都取自這份檔案。

## 設定逐段說明

### 1. 全域選項

```caddyfile
{
    email team@pingclair.com
    storage file_system /var/db/pingclair
    admin 127.0.0.1:2019
}
```

`email` 是自動憑證的 ACME 帳號聯絡信箱。`storage` 指定存放憑證、帳號金鑰與相關狀態
的目錄。`admin` 只在 loopback 上開放 Admin API，`pingclair reload` 因此能在不中斷
連線的情況下套用修改過的設定檔。

### 2. 用 snippet 收納重複的部分

重複出現的設定都只定義一次，寫成 snippet 再 import：

| Snippet | 內容 |
| --- | --- |
| `(edge_headers)` | 安全相關 header，以及 Cloudflare 部署時在 `_headers` 檔裡宣告、供代理程式探索的 `Link` header |
| `(installer)` | 從發布儲存空間提供 `install.sh` 的代理 |
| `(worker)` | `/mcp` 與 `/a2a` 代理端點的代理 |
| `(access_log)` | 所有站點共用的存取日誌 |
| `(docs)` | 整個文件網站，主網域與測試主機共用 |

### 3. 虛擬主機

```caddyfile
pingclair.com {
    import docs
}

pingclair.pingclair.com {
    import docs
}

www.pingclair.com {
    import access_log
    redir https://pingclair.com{uri} 308
}
```

帶有主機名稱的站點位址會自動得到：443 埠的 HTTPS、UDP 443 埠的 HTTP/3，以及一個
80 埠的監聽，負責轉址到 HTTPS 並回應 ACME 驗證。

| 主機名稱 | 用途 |
| --- | --- |
| `pingclair.com` | 官方網站與代理端點 |
| `pingclair.pingclair.com` | 測試環境，提供同一個網站 |
| `www.pingclair.com` | 永久轉址到主網域 |

### 4. 路由順序

```caddyfile
route {
    handle /install.sh {
        import installer
    }
    …
    handle {
        import edge_headers
        file_server
    }
}
```

在 `route` 裡，區塊依書寫順序執行，第一個符合的 `handle` 負責回應。網站的順序是：

1. 安裝腳本：`/install.sh` 與 `/install`；
2. 代理端點：`/mcp` 與 `/a2a`；
3. 建置產物、搜尋索引、Markdown 檔案與 `/.well-known` 探索文件的邊緣規則；
4. 提供 Markdown 給要求它的用戶端；
5. 其他一律從磁碟提供。

### 5. 代理安裝腳本並快取

```caddyfile
(installer) {
    rewrite * /pingclair/install.sh
    reverse_proxy releases.pingclair.com:443 {
        header_up Host releases.pingclair.com
        header_down ?X-Installer-Source r2
        transport http {
            tls
            tls_server_name releases.pingclair.com
        }
        cache {
            ttl 5m
            max_size 16777216
        }
    }
}
```

網站本身不保存安裝腳本的副本；每次發布都會把它上傳到發布儲存空間，網站再代理過去。
請求路徑會改寫成儲存空間裡的路徑，上游的 `Host` 與 TLS 伺服器名稱都明確指定，回應快取
五分鐘、上限 16 MiB，上游沒有設定時會補上 `X-Installer-Source: r2`。

明確指定 `Host` 在這裡很重要：如果上游請求保留了 `pingclair.com`，Cloudflare 可能把它
轉回這台伺服器，形成迴圈。

`/mcp` 與 `/a2a` 仍由 Cloudflare Worker 提供；`(worker)` snippet 用同樣的方式代理它們，
但不快取，所以網站搬家時這兩個網址都不必改。

### 6. 邊緣規則

```caddyfile
handle /_astro/* {
    import edge_headers
    header Cache-Control "public, max-age=31536000, immutable"
    file_server
}
```

這些規則原本由 Cloudflare 在邊緣套用，這裡每一條都是一個 `handle` 區塊：建置產物使用
不可變快取，搜尋索引快取一小時，直接抓取的 Markdown 以 `text/plain` 回應，`/.well-known`
文件開放跨來源存取，API 目錄使用 RFC 9727 的媒體型別。

### 7. 給 AI 代理的 Markdown

```caddyfile
@markdown header Accept *text/markdown*
handle @markdown {
    try_files {path}index.md {path}.md
    file_server
}
```

`Accept` header 含有 `text/markdown` 的用戶端，會在同一個網址拿到頁面的 Markdown 版本：
目錄的 `index.md`，或同名的 `<name>.md`。兩者都不存在時，請求會以原本的路徑繼續處理，
所以靜態資源和沒有 Markdown 版本的頁面照樣能取得；瀏覽器拿到的仍然是 HTML。`index.md`
副本在部署時產生。

這是 header 判斷，不是完整的 HTTP 內容協商。Pingclair 另外提供
`file_server { negotiate markdown }`，它依照 RFC 9110 的品質值判斷並設定
`Vary: Accept`，網站之後可能改用它。

背景說明可參考 Cloudflare 的 [Agent Readiness](https://blog.cloudflare.com/agent-readiness/)。

### 8. 404 頁面與壓縮

```caddyfile
encode zstd gzip

handle_errors 404 {
    rewrite * /404.html
    file_server
}
```

`encode` 對支援的用戶端提供 Zstandard 與 gzip。請求不存在的檔案時，回應 Starlight
產生的 `404.html`，狀態碼維持 404。

### 9. 存取日誌

```caddyfile
(access_log) {
    log {
        output file /var/log/pingclair-access.log {
            roll_size 100MiB
            roll_keep 7
        }
        format json
        headers {
            request User-Agent
        }
    }
}
```

每個請求在 `/var/log/pingclair-access.log` 裡記成一行 JSON，並記錄請求的
`User-Agent`。Pingclair 自己負責輪替：檔案達到 100 MiB 時輪替，保留七個舊檔，並加以壓縮。

## 參考資源

- **[官方文件](https://pingclair.com)**：設定參考與部署指南。
- **`pingclair validate`**：檢查設定檔，並標出錯誤所在位置。
- **`pingclair fmt`**：格式化 Pingclairfile，保留註解。
- **[網站原始碼](https://github.com/dorianverlaine/pingclair-docs)**：網站本身的儲存庫。
