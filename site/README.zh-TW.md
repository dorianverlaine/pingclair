# Pingclair 官方網站

[English](README.md) · [Français](README.fr.md) · [简体中文](README.zh-CN.md) · **繁體中文**

## 概述

Pingclair 官方網站：[https://pingclair.com](https://pingclair.com)

官方網站的原始碼已遷移至獨立儲存庫：

**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**

遷移完成後，本目錄不再維護網站原始碼。原有的目錄結構，以及用於保留空目錄的 `.gitkeep` 佔位檔案，均已一併移除。

本目錄目前僅保留官方網站的正式環境設定，作為 Pingclair 原生設定語言的實際部署範例。

此設定展示如何透過單一 `Pingclairfile` 部署靜態文件網站，涵蓋以下功能：

- 自動 TLS 憑證管理及 HTTP/3 支援
- 基於主機名稱的虛擬主機設定
- 靜態檔案服務與自訂錯誤頁面
- 上游反向代理及回應快取
- 面向 AI Agent 的 Markdown 內容協商
- 永久重新導向與標準網域名稱管理
- 結構化存取日誌及自動輪替

## 正式環境設定

以下為 `pingclair.com` 正式環境使用的 `Pingclairfile`。

網站由部署於巴黎 FreeBSD 伺服器上的 Pingclair 提供服務。`pingclair.pingclair.com` 保留作為預發布環境網域，`www.pingclair.com` 則永久重新導向至主網域。

設定中的英文註解保留原文，以便與實際部署檔案進行對照。

```swift
// 🏝️ pingclair.com — the docs site, served by Pingclair from the
// FreeBSD node, with pingclair.pingclair.com kept as the staging alias and
// www redirected to the apex.

AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")

// 🔁 The Admin API on loopback, so `pingclair reload` can hot-reload this
// file instead of a restart dropping connections.
Admin(listen: "127.0.0.1:2019")

// 🧊 The one-line install address: `https://pingclair.com/install.sh`.
//
// The script lives in the server repository and is published to the release
// bucket by every release; proxying it here rather than keeping a copy is the
// same choice the Cloudflare Worker made — there is no second file to drift.
let installerHost = "releases.pingclair.com:443"

// 🤖 The agent endpoints still served by the documentation Worker; the
// Paris node proxies them so `pingclair.com/mcp` and `/a2a` keep the URL
// contract the Worker era established.
let cfWorker = "cf.pingclair.com:443"

HTTPListener(on: ":443") {
    Site(host: "pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/install")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 📄 Agents that ask for markdown get the twin on the same URL: the
        // directory's `index.md`, or the sibling `<name>.md`; a miss carries
        // on to the normal file server unchanged. The `index.md` copies are
        // made at deploy time.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback {
            // 🔗 `public/_headers` states these on the Cloudflare deployment;
            // the native file server does not read that file, so the Paris
            // node states the same rules here.
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", "</.well-known/api-catalog>; rel=\"api-catalog\", </llms.txt>; rel=\"describedby\", </sitemap.xml>; rel=\"sitemap\""))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
    }
    // 🧾 Starlight ships a 404 page; unknown paths answer with it, the same
    // as the Cloudflare deployment's `not_found_handling`.
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)

    Site(host: "www.pingclair.com") {
        // ➡️ 308 to the apex, the same permanent move the Cloudflare zone
        // answered. The native language has no request-time placeholders yet,
        // so the path does not ride along; a `keepPath:` argument on Redirect
        // is the design idea on file for that.
        Fallback { Redirect(to: "https://pingclair.com", status: .permanentRedirect) }
    }

    Site(host: "pingclair.pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 📄 The same markdown negotiation as the apex site.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback {
            // 🔗 The same header set as the apex site.
            ResponseHeader(.set("X-Content-Type-Options", "nosniff"), .set("Referrer-Policy", "strict-origin-when-cross-origin"), .set("X-Frame-Options", "DENY"), .set("Link", "</.well-known/api-catalog>; rel=\"api-catalog\", </llms.txt>; rel=\"describedby\", </sitemap.xml>; rel=\"sitemap\""))
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
    }
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)
}
.tls(.automatic(email: "team@pingclair.com"))
// 📓 One JSON line per request, rotated by Pingclair itself.
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(size: .mebibytes(100), keep: 7, compress: true),
)
```

## 設定說明

### 1. 全域設定與上游定義

`AutomaticTLS` 與 `Storage` 用於定義服務層級的 TLS 管理及持久化儲存行為。

```swift
AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")
Admin(listen: "127.0.0.1:2019")
```

`AutomaticTLS` 啟用自動憑證管理，並設定 HTTP 與 HTTPS 連接埠，以支援憑證簽發及續期流程。

`Storage` 指定持久化資料目錄，用於儲存 TLS 憑證、ACME 帳戶金鑰及相關狀態資訊。

`Admin` 在本機迴環位址上開放管理 API；這讓設定變更可以熱重載套用，而不必重新啟動服務。

此外，設定使用 `let` 宣告兩個上游位址：

```swift
let installerHost = "releases.pingclair.com:443"
let cfWorker = "cf.pingclair.com:443"
```

透過集中定義上游位址，可以減少重複設定，並確保相同上游在不同路由中的參照保持一致。

Pingclair 原生設定語言將字串視為字面值，不支援在字串內進行執行階段變數插值。上游位址透過明確的綁定進行參照，相關設定可於載入階段完成解析與檢查。

### 2. HTTP 監聽器與虛擬主機

```swift
HTTPListener(on: ":443") {
    Site(host: "pingclair.com") { ... }
    Site(host: "www.pingclair.com") { ... }
    Site(host: "pingclair.pingclair.com") { ... }
}
```

`HTTPListener` 定義監聽端點，`Site` 則根據請求的主機名稱設定虛擬主機。

多個 `Site` 可以共用同一個監聽器，無須分別建立網路監聽端點。

目前部署包含三個虛擬主機：

| 主機名稱 | 用途 |
|---|---|
| `pingclair.com` | 官方網站及主要 API 入口 |
| `www.pingclair.com` | 永久重新導向至主網域 |
| `pingclair.pingclair.com` | 預發布環境及相容性入口 |

此設計將網路監聽設定與網站層級的路由邏輯分離，便於集中管理 TLS、日誌及其他監聽器層級的功能。

### 3. 路由比對與執行順序

Pingclair 依照宣告順序對網站中的 `Route` 進行比對，由第一個符合條件的路由負責處理請求。

當沒有任何路由符合條件時，請求將由 `Fallback` 處理。

官方網站採用以下比對優先順序：

1. 安裝腳本：`/install.sh` 與 `/install`
2. Agent 介面：`/mcp` 與 `/a2a`
3. 根據 `Accept` 請求標頭選擇 Markdown 內容
4. 透過 `Fallback` 提供一般靜態檔案

精確路徑比對優先於通用請求標頭比對，可避免靜態檔案服務或內容協商邏輯影響專用介面。

路由執行順序直接體現在設定檔中，不依賴額外的優先權數值或隱含規則。

### 4. 上游代理與回應快取

官方網站的安裝腳本由獨立的發布服務維護，不在文件網站中儲存副本。

`/install.sh` 與 `/install` 均透過反向代理存取 `releases.pingclair.com`：

```swift
Rewrite(to: "/pingclair/install.sh")
Proxy(
    to: installerHost,
    headersUp: [.set("Host", "releases.pingclair.com")],
    headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
)
.upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
.cache(ttl: .minutes(5), maxSize: .mebibytes(16))
```

此設定包含以下處理步驟：

1. **路徑改寫**：`Rewrite` 將請求路徑轉換為發布服務使用的資源路徑。
2. **上游代理**：`Proxy` 將請求轉送至指定的 HTTPS 上游。
3. **Host 標頭設定**：`headersUp` 明確設定上游請求的 `Host`。
4. **TLS 伺服器名稱**：`upstreamTLS` 指定上游 TLS 連線使用的伺服器名稱。
5. **回應快取**：`cache` 設定五分鐘的快取有效期限，以及 16 MiB 的大小限制。
6. **回應來源識別**：`headersDown` 在回應標頭不存在時加入 `X-Installer-Source: r2`。

明確設定上游 `Host` 與 TLS 伺服器名稱，對目前的部署架構尤其重要。

若請求繼續使用原始主機名稱 `pingclair.com`，可能被 Cloudflare 路由回官方網站伺服器，形成非預期的代理迴圈。因此，此設定明確區分用戶端存取網域與上游服務網域。

安裝腳本透過獨立發布服務提供，也避免了網站部署與軟體發行版本之間出現多份需要同步維護的檔案。

#### Agent 介面代理

`/mcp` 與 `/a2a` 使用相同的反向代理機制，但不設定回應快取。

```swift
Route(when: .path(exact: "/mcp")) {
    Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
    .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
}
```

這些介面仍由 Cloudflare Worker 提供服務，官方網站伺服器則負責將請求轉送至既有上游。

此部署方式保留既有介面路徑，使網站基礎設施遷移時，無須同時變更用戶端使用的 API 位址。

### 5. 面向 AI Agent 的 Markdown 內容協商

官方網站支援根據 HTTP `Accept` 請求標頭，在相同 URL 下提供 HTML 或 Markdown 格式的內容。

```swift
Route(when: .header(name: "Accept", contains: "text/markdown")) {
    TryFiles(
        candidates: [
            .requestPath(appending: "index.md"),
            .requestPath(appending: ".md")
        ],
        root: "/usr/local/www/pingclair.pingclair.com"
    )
    ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
}
```

*以上程式碼僅為提高可讀性而調整排版，處理邏輯與正式環境設定一致。*

當用戶端傳送包含 `text/markdown` 的 `Accept` 請求標頭時，Pingclair 會嘗試尋找對應的 Markdown 檔案。

`TryFiles` 依序檢查以下候選路徑：

1. 請求路徑所對應目錄中的 `index.md`
2. 請求路徑所對應的 `.md` 檔案

找到檔案後，後續的 `ServeFiles` 會使用選定的路徑提供內容。

若兩個候選路徑均不存在，`TryFiles` 不會直接回傳錯誤，而是繼續使用原始請求路徑進行處理。

因此，一般靜態資源及沒有 Markdown 版本的路徑，仍可由檔案服務正常處理。

部署流程也會根據對應的 Markdown 來源檔案產生所需的 `index.md`，以支援目錄形式的文件路徑。

對於一般瀏覽器請求，網站會繼續提供 HTML 頁面。Markdown 檔案不在預設目錄索引清單中，因此不會取代一般的 HTML 索引頁面。

需要注意的是，目前的實作透過檢查 `Accept` 請求標頭是否包含 `text/markdown` 來選擇內容，屬於基於請求標頭條件的格式選擇，而非完整的 HTTP 內容協商演算法。

此機制旨在讓 AI Agent 能夠直接取得文件的結構化文字版本，同時維持既有 URL 與瀏覽器存取行為不變。

關於網站面向 AI Agent 的整體可存取性與內容組織方式，可參考 Cloudflare 的相關文章：

[Agent Readiness](https://blog.cloudflare.com/agent-readiness/)

### 6. 標準網域名稱與永久重新導向

官方網站使用 `pingclair.com` 作為標準網域名稱，並透過 HTTP 308 將 `www.pingclair.com` 的請求永久重新導向至主網域。

```swift
Site(host: "www.pingclair.com") {
    Fallback {
        Redirect(
            to: "https://pingclair.com",
            status: .permanentRedirect
        )
    }
}
```

HTTP 308 表示永久重新導向，並要求用戶端在重新導向過程中保留原始請求方法。

目前設定存在一項已知限制：**重新導向不會保留原始請求路徑。**

例如，存取 `https://www.pingclair.com/docs/example` 將被重新導向至 `https://pingclair.com`，而非對應的文件路徑。

這是因為目前的原生設定語言尚未提供可用於建構動態重新導向目標的請求路徑參照機制。

相關改善方案正在 [Issue #330](https://github.com/dorianverlaine/pingclair/issues/330) 中追蹤，其中包括為 `Redirect` 引入 `keepPath` 參數的設計提案。

### 7. TLS 與 HTTP/3

```swift
.tls(.automatic(email: "team@pingclair.com"))
```

監聽器透過自動 TLS 設定管理憑證簽發與續期。

`team@pingclair.com` 作為相關 ACME 帳戶的聯絡電子郵件地址。

目前部署同時支援 HTTP/3，透過 UDP/443 提供基於 QUIC 的 HTTP 連線。

HTTP/3 與傳統的 TLS-over-TCP 連線可以使用相同的連接埠號碼，但分別使用 UDP 與 TCP 作為傳輸協定。

### 8. 自訂錯誤頁面與內容壓縮

官方網站使用 Starlight 產生的 `404.html` 作為自訂錯誤頁面。

```swift
.errorPage(
    for: [.status(404)],
    file: "/usr/local/www/pingclair.pingclair.com/404.html"
)
.encode(.zstd, .gzip)
```

`errorPage` 將 HTTP 404 狀態對應至指定的靜態錯誤頁面，確保網站在資源不存在時維持一致的呈現方式。

`encode` 設定支援 Zstandard 與 Gzip 內容編碼，讓用戶端能夠依據支援的編碼格式接收壓縮後的回應。

### 9. 存取日誌與檔案輪替

```swift
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(
        size: .mebibytes(100),
        keep: 7,
        compress: true
    ),
)
```

此設定啟用 JSON 格式的存取日誌，並將其寫入：

`/var/log/pingclair-access.log`

每筆存取日誌均以獨立的 JSON 紀錄儲存，便於日誌蒐集、查詢及自動化分析。

日誌額外包含請求的 `User-Agent` 標頭，並由 Pingclair 內建的輪替機制管理日誌檔案：

- 單一日誌檔案達到 100 MiB 時觸發輪替
- 最多保留七個輪替檔案
- 對輪替後的日誌檔案啟用壓縮

因此，此部署無須額外依賴外部日誌輪替程式，即可完成上述日誌生命週期管理。

## 參考資料

關於 Pingclair 原生設定語言及其元件的完整說明，請參閱以下資源：

- **[官方文件](https://pingclair.com)**：設定語言、功能說明及部署指南
- **`pingclair describe`**：檢視解析器支援的設定元件及其定義
- **`pingclair validate`**：驗證設定檔，並回報語法或設定錯誤及其對應位置
- **[官方網站原始碼](https://github.com/dorianverlaine/pingclair-docs)**：網站內容與文件維護儲存庫

本文所示設定用於說明 Pingclair 在實際正式環境中的部署方式。具體設定參數及功能支援情況，請以對應版本的官方文件為準。
