# Pingclair 官方網站

[English](README.md) · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · **繁體中文**

## 概述

官方網站：[https://pingclair.com](https://pingclair.com)

網站原始碼放在獨立的儲存庫
**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**。
這個目錄保留正式環境的設定檔 [`Pingclairfile`](Pingclairfile)，以及讓網站檔案保持
最新的腳本 [`sync-docs.sh`](sync-docs.sh)，作為用 Pingclair 部署靜態文件網站的實際範例：

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
handle /install.sh {
    import installer
}
…
handle {
    import edge_headers
    file_server {
        negotiate markdown
    }
}
```

`handle` 區塊彼此互斥：第一個符合的負責回應。它們依路徑的明確程度排序，所以精確路徑
與前綴（安裝腳本、代理端點、建置產物、搜尋索引、Markdown 檔案與 `/.well-known` 文件）
排在前面，沒有條件的區塊排最後。這些路徑彼此沒有重疊，所以這個順序正是網站需要的
順序。

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

漏洞掃描器會照著一份固定清單探測這個靜態網站從來沒有過的路徑：環境變數檔、版本控制的
中繼資料、PHP 入口、管理後台。一個具名匹配器先把它們全部攔下：

```caddyfile
@scanner path */.env* */.git* *.php */wp-* */phpmyadmin* */.aws* *.sql …
handle @scanner {
    respond "😈" 404
}
```

它們拿到的是只有一個 emoji 的 404，而不是 404 頁面。狀態碼刻意維持 404：掃描器看狀態碼
做判斷，回 200 會讓它以為這裡有東西、值得再來。所有規則都不會匹配到建置產生的檔案。

### 7. 給 AI 代理的 Markdown

```caddyfile
handle {
    import edge_headers
    file_server {
        negotiate markdown
    }
}
```

偏好 Markdown 的用戶端，會在同一個網址拿到頁面的 Markdown 版本。以 `/start/install/`
為例，回應的是建置產生的 `start/install.md`；目錄裡有 `index.md` 時（例如首頁）則用
它。部署時不再複製任何檔案。沒有 Markdown 版本的頁面和靜態資源照舊提供。

偏好依 `Accept` 的品質值判斷（RFC 9110）：

| `Accept` | 回應 |
| --- | --- |
| `text/markdown` | Markdown |
| `text/markdown, text/html`（程式碼代理送的） | Markdown：用戶端明確寫出了它 |
| 瀏覽器的 `text/html,…,*/*;q=0.8` | HTML |
| `text/markdown;q=0, */*` | HTML：Markdown 被拒絕 |

每個頁面回應都帶 `Vary: Accept`，快取會把兩種版本分開存放。

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

## 讓網站保持最新

伺服器本身從不建置網站：Astro 建置的記憶體峰值接近 800 MB，而伺服器的記憶體不到
1 GiB。網站儲存庫的 CI 會建置每一次推到 `main` 的內容，把結果發佈到固定的
`site-latest` release，內容是 `site.tar.gz`，以及記錄 commit 與壓縮檔 sha256 的
`site.json`。

[`sync-docs.sh`](sync-docs.sh) 由 cron 每五分鐘執行一次。`site.json` 裡的 commit
跟伺服器正在提供的不同時，它會下載壓縮檔、檢查 sha256 與幾個關鍵頁面，解壓到
`/usr/local/www/pingclair-site/<commit>`，再把新的 symlink 改名覆蓋
`/usr/local/www/pingclair.pingclair.com`，也就是 Pingclairfile 提供的根目錄。改名是
原子操作，所以請求不會看到兩個版本各一半的內容，Pingclair 也不需要重載。切換後如果
網站沒有正常回應，連結會改回上一個版本。磁碟上保留最新的三個版本。

安裝步驟（只需一次，以 root 執行）：

```sh
install -m 755 sync-docs.sh /usr/local/sbin/pingclair-site-sync
mkdir -p /usr/local/www/pingclair-site
mv /usr/local/www/pingclair.pingclair.com /usr/local/www/pingclair-site/initial
ln -s /usr/local/www/pingclair-site/initial /usr/local/www/pingclair.pingclair.com
echo '*/5 * * * * root /usr/local/sbin/pingclair-site-sync' > /etc/cron.d/pingclair-site-sync
```

每次切換都會以 `pingclair-site-sync` 為標籤記錄到 syslog。

## 參考資源

- **[官方文件](https://pingclair.com)**：設定參考與部署指南。
- **`pingclair validate`**：檢查設定檔，並標出錯誤所在位置。
- **`pingclair fmt`**：格式化 Pingclairfile，保留註解。
- **[網站原始碼](https://github.com/dorianverlaine/pingclair-docs)**：網站本身的儲存庫。
