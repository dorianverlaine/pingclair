<div align="center">

<img src="assets/logo.png" alt="Pingclair" width="520">

**基於 Pingora 打造的現代高效能 Web 伺服器與反向代理**  
*結合 Cloudflare Pingora 的極致效能與 Caddy 的極簡開發體驗*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.97%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dorianverlaine/pingclair/pulls)

[English](README.md) · **中文** · [Français](README.fr.md)

</div>

---

## 📖 專案簡介

**Pingclair** 是新一代的 Web 伺服器與反向代理工具。它的核心理念，是把 **Cloudflare Pingora**（處理過兆級請求的 Rust 代理框架）的強大能力，包裝在一層近似 **Caddy** 的易用外殼之下。

傳統 Nginx 的設定往往晦澀難懂，而 Caddy 雖然好用，卻建立在 Go 之上。Pingclair 想要填補這個空缺：提供一套 **100% 以 Rust 撰寫**、**記憶體安全**、**高效能**且**設定直覺**的方案。

無論你需要的是單純的靜態檔案伺服器，還是支援複雜負載平衡、自動 HTTPS 與 HTTP/3 的企業級閘道，Pingclair 都能勝任。

## ✨ 核心特性

*   🚀 **以 Pingora 為核心** — 站在巨人的肩膀上，倚靠 Cloudflare 歷經實戰驗證的基礎設施，提供企業級的穩定度與吞吐量。明文監聽器支援 HTTP/1.1 與 prior-knowledge h2c；TLS 監聽器則透過 ALPN 協商 HTTP/2。
*   🔒 **記憶體安全** — 受惠於 Rust 的語言特性，徹底杜絕緩衝區溢位這類常見的記憶體安全漏洞。
*   📝 **相容 Caddyfile 的設定** — 極簡的設定 DSL，支援**自動 HTTPS**、**多重監聽器**與**具名匹配器**，相容主流 Caddyfile 語法。
*   ⚡ **原生支援 HTTP/3 (QUIC)** — 基於 Cloudflare 的 [quiche](https://github.com/cloudflare/quiche)（支撐 Cloudflare 邊緣網路的生產級 QUIC 協定棧）打造，在不穩定的網路環境下提供更低的延遲與更好的連線遷移能力。明確設定 `tls` 後，任何監聽埠都可提供 HTTPS 與 H3；443 與 8443 仍保留自動辨識。目前所有下游協議都不轉送已宣告的 request trailers：回應尚未送出時會明確回傳 `501`，H3 已送出時則重設 stream。上游回應若宣告 trailers，會在完整的端到端轉送完成前明確回傳 `502`。H3 CONNECT 與 extended CONNECT 在 tunnel 支援完成前會回傳 `501`。
*   🔄 **智慧負載平衡** — 內建多種演算法（輪詢、最少連線等），支援健康檢查與故障自動轉移。
*   🔐 **自動與私有 HTTPS** — 整合 ACME（Let's Encrypt）申請公開憑證；`tls internal` 則提供持久化本機 CA，供私有源站與隧道使用。
*   📁 **高效能靜態檔案服務** — 支援 Gzip/Brotli 壓縮、Range 請求與高效率的檔案傳輸。
*   📊 **可觀測性** — 開箱即用的 Prometheus 指標匯出與 OpenTelemetry Tracing 支援。

## ⚡ 效能基準測試

最新對比：Pingclair HEAD `43ec589` 對 nginx 1.31.3，於 AWS `us-west-2a`
三台 `c7i-flex.large`（各 2 vCPU、非 burst）測量，反向代理的後端使用
獨立主機。負載為 1 KiB 檔案；H1 用 `wrk -t2 -c100`，H2/H1S 用
`h2load -t2 -c50`；所有記錄輪次皆為零失敗。

| 場景 | Pingclair | nginx 1.31.3 |
| --- | ---: | ---: |
| H1 靜態 | 84,208 | 105,588 |
| H2 靜態（50×10） | 74,587 | 94,712 |
| H1S 靜態 | 70,004 | 55,304 |
| H1 反向代理 | 38,938 | 85,744 |
| H2 反向代理（50×10） | 33,516 | 45,872 |
| H1S 反向代理 | 34,418 | 55,894 |

H1S 靜態是 Pingclair 的領先項目（+27%）。靜態 H1/H2 約落後 20%；
反向代理的 H1/H1S 仍是最大差距，H2 反向代理約落後 27%。逐次執行的
原始證據保留在本機 `benchmarks/results/20260803_c7iflex_nocase/`，不在
倉庫內。

## 📦 安裝指南

### 前置需求

*   **Rust 工具鏈** — 需要 Rust 1.97 或更新的版本。

### 從原始碼編譯安裝

建議從原始碼編譯，以取得針對你本機 CPU 最佳化的執行檔：

```bash
# 1. 複製儲存庫
git clone https://github.com/dorianverlaine/pingclair.git
cd pingclair

# 2. 編譯並安裝（release 模式）
cargo install --path ./pingclair
```

安裝完成後，`pingclair` 指令便會加入你的系統 `PATH`。

### Linux 一鍵安裝

任何 Linux 發行版都適用同一支安裝腳本：它會自動下載（或編譯）執行檔、設定 `systemd` 服務，並建立低權限的 `pingclair` 使用者（透過 `setcap` 綁定低號連接埠）。安裝完成後，可以使用 `pc`（pingclair 的縮寫）指令來管理服務。

```bash
# 執行安裝腳本（需要 sudo 權限）
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash
```

腳本提供兩個旗標，可以追蹤 `main` 而非穩定版：

安裝最新的 main 開發版建置（預先編譯好的 binary）：

```bash
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash -s -- --dev
```

Clone main 並在本機編譯（需要 Rust 1.97+）：

```bash
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash -s -- --main
```

### 開發版建置（不穩定）

專案仍在快速迭代，每次 push 到 `main` 都會產出供部署測試用的快照——
**不是穩定版**：

- **容器映像**（GHCR）：`dev` tag 跟隨最新 push，每個 build 另有完整的
  commit SHA tag，可以釘住特定快照。

  ```bash
  docker pull ghcr.io/dorianverlaine/pingclair:dev
  docker run --rm -p 8080:80 \
    -v "$PWD/Pingclairfile:/etc/pingclair/Pingclairfile:ro" \
    ghcr.io/dorianverlaine/pingclair:dev
  ```

- **Linux 二進位檔**（x86_64 與 aarch64）：附在對應的 GitHub Actions run，
  保留 14 天，從該次 run 的 artifact 清單下載。

每個開發版都是移動中的樹的快照，部署到重要環境前請自行驗證。

### 以 Docker Compose 做正式部署

正式部署建議跑 config-file 模式，並把 TLS store 放在持久 volume（裡面有
憑證、ACME 帳戶金鑰與 internal CA——刪掉等於全部重新簽發）：

```yaml
services:
  pingclair:
    image: ghcr.io/dorianverlaine/pingclair:dev
    restart: unless-stopped
    ports:
      - "80:80"
      - "443:443"
      - "443:443/udp"   # HTTP/3
    volumes:
      - ./conf:/etc/pingclair:ro
      - ./site:/srv
      - pingclair_tls:/var/lib/pingclair/certs
    command: ["pingclair", "run", "/etc/pingclair/Pingclairfile"]

volumes:
  pingclair_tls:
```

把 `Pingclairfile` 放 `./conf/`、靜態檔放 `./site/`（設定裡用
`root /srv` 指到它）。容器以 config 檔啟動，HTTPS、自動 80 轉跳與
HTTP/3 的行為與主機部署完全一致。

### 信任 `tls internal` 的根憑證

`tls internal` 用持久本機 CA 簽發 leaf。要驗證憑證的用戶端必須信任其根，
位置在 `$PINGCLAIR_TLS_STORE/internal/root.crt`（容器內：
`docker compose cp pingclair:/var/lib/pingclair/certs/internal/root.crt
./root.crt`）。安裝到系統信任庫：

- Linux：複製到 `/usr/local/share/ca-certificates/root.crt` 後執行
  `sudo update-ca-certificates`。
- macOS：`sudo security add-trusted-cert -d -r trustRoot -k
  /Library/Keychains/System.keychain root.crt`。
- 自帶信任庫的瀏覽器（Firefox、部分平台的 Chrome）需在憑證管理員手動匯入
  根憑證。

只對你控制的來源做這件事；internal CA 不是公開憑證機構。

## 🏃 快速上手

Pingclair 提供兩種執行模式：**CLI 命令列模式**（適合快速測試）與**設定檔模式**（適合正式環境）。

### 1. 命令列模式（CLI）

**啟動靜態檔案伺服器**  
將目前目錄下的檔案透過 HTTP 8080 連接埠對外提供服務：
```bash
pingclair file-server --listen :8080 --root .
```

**啟動反向代理**  
將本機 8080 連接埠的流量轉發到後端的 3000 連接埠：
```bash
pingclair reverse-proxy --from :8080 --to localhost:3000
```

**管理系統服務（Linux）**  
安裝後可使用內建指令管理 `systemd` 服務：
```bash
pc service start    # 啟動
pc service stop     # 停止
pc service status   # 查詢狀態
pc service reload   # 平滑重載設定（SIGHUP）
pc service restart  # 重新啟動
```

### 2. 設定檔模式（推薦）

在專案根目錄下建立一個名為 `Pingclairfile` 的檔案，接著執行：

```bash
pingclair run Pingclairfile
```

## 🛠️ 設定詳解（Pingclairfile）

Pingclair DSL 是專門用於描述伺服器行為的結構化設定語言；如同 Caddy 的 `Caddyfile`，其慣用檔名為 `Pingclairfile`。

### 基礎結構

最簡單的設定包含一個或多個站台區塊：

```caddyfile
# 定義一個監聽 localhost 的伺服器
localhost:8080 {
    # 靜態檔案服務
    file_server ./public
}
```

### 公開網域的自動 HTTPS

`tls auto` 透過 ACME（Let's Encrypt）申請並自動續簽公開憑證，不需要寫
`listen`：

```caddyfile
{
    email admin@example.com
}

example.com {
    tls auto
    reverse_proxy app:8080
}
```

這就是完整的設定。有 TLS 而沒寫 `listen` 的 site 會在 443 提供 HTTPS，
Pingclair 另外自動開一個 port 80 的明文 listener，做兩件事：回應 ACME 的
HTTP-01 挑戰——CA 是以**明文** HTTP 打在這個 port（RFC 8555 §8.3）——以及把
其餘請求以 308 導向 HTTPS。所以即使 block 裡設定了 TLS，port 80 仍維持明文：
那裡放 TLS listener 會拒絕 CA 的明文探測，憑證永遠簽不下來。

行為由全域區塊控制：

| `auto_https` | 效果 |
| --- | --- |
| `on`（預設） | 自動開 port 80、回應 ACME 挑戰、重導到 HTTPS。 |
| `disable_redirects` | 自動開 port 80 並回應 ACME 挑戰，但不重導。 |
| `off` | 什麼都不開，憑證管理也一併關閉。 |

在 block 裡自己寫 `listen :80` 就等於放棄自動 listener，Pingclair 會完全照你
的設定服務那個 port。若 port 80 無法綁定（已被占用，或權限不足），自動
listener 會被跳過並留下警告，HTTPS 照常服務，但 ACME HTTP-01 驗證不會運作。

Pingclair 安裝憑證時會一併送出 CA 簽發的中繼憑證。只送 leaf 的伺服器在瀏覽器
裡看起來是正常的——瀏覽器會快取中繼憑證，也會用 AIA 自行補抓——但 `curl`、
Go 與 Java 會直接拒絕連線。

要自己寫重導，`redir` 支援 `{host}` 與 `{uri}`。目標要加引號，否則 `{` 會被
當成 block 的開頭：

```caddyfile
http://example.com {
    redir "https://{host}{uri}" 308
}
```

### 私有源站的 internal TLS

當 TLS client 是可信隧道、負載平衡器或私有服務，而且無法完成公開 ACME 驗證時，
可使用 `tls internal`：

```caddyfile
https://origin.example.test:6688 {
    tls internal
    reverse_proxy app:8080
}
```

Pingclair 會在 `PINGCLAIR_TLS_STORE` 下持久化一個有效十年的本機 CA，以及
可續期的 90 天 leaf 憑證——裸二進位預設 `$XDG_DATA_HOME/pingclair`
（即 `~/.local/share/pingclair`），容器映像則為 `/var/lib/pingclair/certs`。
需要驗證源站的 client 應信任
`$PINGCLAIR_TLS_STORE/internal/root.crt`；CA 私鑰則保存在僅 owner 可讀的
`authority.json`。H1/H2 與 H3 共用同一份持久化 leaf。`tls internal`
必須搭配明確站台名稱，且不可和 `tls auto`、ACME email 或手動憑證路徑混用。

全域的 `local_certs` 選項對所有沒有自己憑證管理的站台套用同一選擇：所有
預設自動化改用持久化本機 CA，而不是公開 ACME。

若 Pingclair 位於你所管理的負載平衡器或 CDN 後方，只能在全域區塊列出可信
代理網段。未受信任的上一跳不能透過 `X-Forwarded-For`、`X-Real-IP` 或
`X-Forwarded-Proto` 偽造 client identity：

```caddyfile
{
    trusted_proxies 10.0.0.0/8 2001:db8::/32
}

example.com {
    listen :8443 proxy_protocol
    reverse_proxy app:8080
}
```

存取控制、rate limit、IP-hash 負載平衡、上游轉送、placeholder 與 access log
會共用同一個已驗證 client IP。目前變更 `trusted_proxies` 後需要重新啟動。
`listen … proxy_protocol` 會要求每條 TCP 連線帶有 PROXY v1 或 v2，並在 TLS／HTTP
解析前拒絕不在 `trusted_proxies` 的 transport peer。XFF 與 RFC 7239
`Forwarded` chain 都有上限；畸形或彼此衝突的身分會 fail closed。PROXY
protocol 不適用於 UDP HTTP/3 listener。

### 資源上限與 timeout

下游上限設定在站台層級，上游各階段 timeout 則設定於 `reverse_proxy`。
時間長度必須附帶單位。WebSocket upgrade、`flush_interval -1` 與
`text/event-stream` 會套用長連線覆寫；`off` 代表明確移除該長連線期限。

```caddyfile
example.com {
    limits {
        header_timeout 5s
        body_timeout 30s
        idle_timeout 30s
        request_timeout 2m
        max_headers 100
        max_header_bytes 65536
        max_connections 10000
        upload_bytes_per_sec 10485760
        download_bytes_per_sec 52428800
        long_connections {
            idle_timeout 5m
            request_timeout off
        }
    }

    reverse_proxy app:8080 {
        retry {
            max_attempts 4
            total_timeout 2s
            backoff 50ms
            status_codes 429 502 503 504
            methods GET HEAD
        }
        overload {
            max_in_flight 256
            max_pending 64
            pending_timeout 250ms
            upstream_max_connections 64
        }
        circuit_breaker {
            consecutive_failures 5
            error_rate_percent 50
            minimum_requests 20
            window_requests 100
            open_for 30s
            half_open_requests 1
            failure_statuses 429 502 503 504
        }
        transport http {
            connect_timeout 3s
            first_byte_timeout 30s
            between_reads_timeout 15s
        }
    }
}
```

`max_attempts` 包含第一次嘗試。連線建立失敗時，因尚未有 request bytes
送到該後端，可安全改送其他後端；狀態碼重試則只接受設定允許的冪等方法，
而且 request 必須實際沒有 body。Pingclair 不會為此策略緩衝或重送 request
body。省略 `retry` 時會保留舊有的連線失敗切換上限，也不會因 response
status 進行重試。

`max_in_flight` 限制 route 內正在執行的工作，`max_pending` 則提供有界等待佇列；
佇列已滿會快速回 429，等待逾時回 503。`upstream_max_connections` 是保守的
單一 backend request 占用上限；H2 多工也受同一上限約束，而不是猜測實體 socket
數量。Circuit breaker 依具體 backend 分開計算，任一設定門檻成立就 open 並快速
回 503；`open_for` 到期後只允許設定數量的 half-open probe。未列
`failure_statuses` 時，所有 5xx 都算失敗。相容的 Admin／SIGHUP reload 會保留
既有 circuit 狀態；變更保護政策或 upstream 集合則建立全新狀態。

header、body 與整體 request 超限時，只要協議仍能送出回應，就會回傳明確的
HTTP 錯誤；idle transport 與超出上限的 HTTP/2、HTTP/3 連線則會關閉。
Pingora 0.8 對 H1/H2 僅提供一個上游 read timer，因此兩個階段會採用
`first_byte_timeout` 與 `between_reads_timeout` 中較嚴格者；H3 bridge
則會在收到 response header 後切換 timer。目前修改 H1/H2 pre-routing
`header_timeout`、H2 field-section cap 或 H1/H2 connection limit 後，
需要重新啟動 listener。

### 路由與匹配

Pingclair 提供強大的路由匹配能力，你可以依照路徑、網域、標頭等條件分流請求。

```caddyfile
example.com {
    # 1. 使用具名匹配器匹配 API 路徑
    @api {
        path /api/v1/*
    }

    # 針對 API 請求的邏輯
    handle @api {
        header {
            set Content-Type "application/json"
        }
        reverse_proxy localhost:3000
    }

    # 2. 匹配靜態資源
    handle /assets/* {
        header {
            set Cache-Control "public, max-age=86400"
        }
        file_server ./assets
    }

    # 3. 預設回退（Fallback）
    handle {
        respond "Page Not Found" 404
    }
}
```

### 進階特性：巨集（Macros）

這是 Pingclair 最強大的特性之一。你可以定義「巨集」來封裝重複的設定片段，並在多個伺服器或路由中重複使用，讓設定檔保持整潔（DRY 原則）。

```rust
// 定義一個名為 security_headers 的巨集，用於加入安全標頭
macro security_headers!() {
    headers {
        remove: ["Server", "X-Powered-By"];
        set: {
            "X-Frame-Options": "DENY",
            "X-XSS-Protection": "1; mode=block",
            "Strict-Transport-Security": "max-age=31536000",
        };
    }
}

// 定義通用的日誌設定巨集
macro standard_log!(path) {
    log {
        output: File(path);
        format: Json;
        level: Info;
    }
}

server "blog.example.com" {
    listen: "0.0.0.0:443";

    // 使用巨集
    use security_headers!();
    use standard_log!("/var/log/pingclair/blog.log");

    route {
        _ => { file_server "./blog"; }
    }
}

server "shop.example.com" {
    listen: "0.0.0.0:443";

    // 重複使用相同的安全設定
    use security_headers!();
    use standard_log!("/var/log/pingclair/shop.log");

    route {
        _ => { proxy "http://shop-backend:8000"; }
    }
}
```

### 反向代理與負載平衡

```caddyfile
:80 :8080 {
    reverse_proxy {
        lb_policy least_conn
        to 10.0.0.1:8080 { weight 3 }
        to 10.0.0.2:8080
        # 🛟 僅在所有主要後端皆不可用時使用。
        to 10.0.0.3:8080 { backup }
        health_check {
            path /health
            interval 5s
            timeout 2s
            status 200 204
            consecutive_failure 3
            consecutive_success 2
            max_response_body_bytes 65536
            slow_start 30s
        }
    }
}
```

主動健康檢查在請求之外執行，因此閒置的故障後端會在使用者請求碰到它之前退出
輪詢，並在連續探測成功後重新加入。探測可設定 method、Host、header、狀態碼集合、
有 byte 上限的 body 比對、獨立連接埠、連線重用、門檻與 slow-start。HTTPS 探測
會沿用該 route 的 pinned CA、client certificate、SNI 與協議政策。

### 精確的本機 rate limit

```caddyfile
api.example.com {
    @api path /api/*
    route @api {
        rate_limit 100 60s {
            burst 20
            key tenant X-Tenant-ID
        }
        reverse_proxy app:8080
    }
}
```

Token bucket 會輸出精確的 `RateLimit-Limit`、`RateLimit-Remaining` 與
`RateLimit-Reset` response header，拒絕時另有 `Retry-After`。在 block 加上
`dry_run` 可只計數與回報、不回 429。key 可選 `ip`、`global`、`route`、
`api_key`、`header <name>` 或 `tenant [name]`。這是 process-local limiter；
Redis distributed limit 不在 v0.2 範圍內。

上游 scheme 會決定連線協議：裸位址或 `http://` 使用 HTTP/1.1；`https://`
透過 ALPN 協商 HTTP/2，並可回退至 HTTP/1.1；`h2c://` 強制使用明文
prior-knowledge HTTP/2；`h2://` 則強制使用 TLS HTTP/2。原生 gRPC 應使用
`h2c://` 或 `h2://`，確保 response trailers 以端到端 metadata 傳遞。

Unix socket upstream 寫成 `unix//path/to.sock`，直接撥接該 socket；
`unix+h2c//path/to.sock` 則在其上使用 prior-knowledge HTTP/2。
Unix upstream 不會進入 DNS refresher。

上游也可以由 DNS 在執行期間動態發現：`dynamic a name port` 解析 `name` 的
所有位址記錄，`dynamic srv _svc._tcp.example.com` 解析 SRV 記錄並使用
記錄自帶的 port。查詢一律在背景 refresher 進行，絕不在請求路徑上。
dial 字串也可以含請求 placeholder（例如 `reverse_proxy {re.dial.1}`），
每個請求展開一次，並以 host＋port 快取。

retry 政策接受 Caddy 的 `lb_retry_match` 拼法：`method`、`path`、`header`
與 CEL expression。method、path 與 status-code expression 會在執行期求值；
執行期無法求值的 expression 會保留在編譯後的設定中，並在啟動時記錄。
`lb_policy weighted_round_robin` 支援每個 upstream 一個權重；reverse_proxy
區塊裡的 `method`／`rewrite` 會在請求送往上游前改寫請求。

`reverse_proxy` 也接受 `handle_response` 區塊，搭配 response matcher
（`@name status …`／`@name header …`）、`replace_status`、`copy_response` 與
`copy_response_headers`。決策只讀回應標頭；替換回應只發一次靜態 body，
其餘上游 body 逐塊丟棄，所以攔截絕不會整份緩衝。`intercept { … }` 會對
proxied response 註冊同一組 handler。

`forward_auth <gateway> { uri …; copy_headers … }` 在請求繼續送往後端前先做
一次 auth round trip：2xx 會把列出的回應 header 複製到請求上（先刪掉
客戶端自帶的版本），其餘狀態直接回給客戶端。含 `_` 的傳入 header 名稱
會被丟棄，與 Caddy 預設一致。

以主機名寫的 upstream 會在執行期間定期重解析，容器換 IP 重啟後不需 reload 即可跟上。
解析失敗時會保留上一個位址繼續服務 —— resolver 故障不該讓站台跟著掛掉；啟動當下
還解析不到的名稱，也會在解析成功後自動加入 pool，因此代理可以先於 app 啟動。
IP 字面位址完全不會經過 resolver。

```caddyfile
{
    # 預設 30s。`dns_refresh off` 會把每個 upstream 釘在啟動時的位址。
    # 單位是必填的：`30` 不等於 `30s`。
    dns_refresh 15s
}
```

### 單頁應用：`try_files`

`try_files` 會把請求改寫成第一個「在站台 `root` 底下確實存在」的候選路徑，
它本身不回應任何東西——真正送出檔案的是排在它後面的 `file_server`。
官方的單頁應用寫法可以原樣貼上：

```caddyfile
example.com {
    root * /srv
    encode gzip
    try_files {path} /index.html
    file_server
}
```

請求打到真實檔案就送那個檔案，其餘一律改寫成 `/index.html`，交給前端自己路由。
改寫會保留 query string。

候選路徑結尾有 `/` 的只匹配目錄，沒有 `/` 的只匹配一般檔案——**決定的是設定檔裡
寫的那個斜線，不是請求帶進來的那個**。

與 Caddy 有四項差異，全部**fail closed**，並且錯誤訊息會講出理由，
而不是編譯成一個語意悄悄不同的東西：

| 不支援 | 理由 |
| --- | --- |
| `{path}` 以外的 placeholder | 只有 `{path}` 會展開，其他會被當成字面上的目錄名去找。 |
| 帶 query string 的候選（`/index.php?{query}`） | query 會被無聲丟掉。 |
| 候選裡的 glob 字元 | Caddy 會展開 glob，Pingclair 是字面比對。 |
| `{ policy … }` 區塊 | 只實作了「取第一個匹配」。 |
| 候選裡的 `..` 片段 | 限制在 document root 內是詞法層做的，所以有可能跳出去的候選直接拒絕。 |

`try_files {path} {path}/ /index.html` 也可以：第二個候選匹配目錄，所以請求
`/docs` 會找到 `/docs/`，剩下的交給 file server。

### 路徑手術：`uri`

```caddyfile
example.com {
    uri strip_prefix /api
    uri strip_suffix .php
    uri path_regexp /{2,} /
    reverse_proxy 127.0.0.1:3000
}
```

`uri replace` 與 `uri query` 會**指名拒絕**。在 Caddy 裡 `replace` 是取代路徑中的
一段子字串，而 Pingclair 的 rewrite 是整條路徑換掉；收下它會編得過、然後送出一個
跟你寫的不一樣的 URL，所以改成報錯。改寫 query string 這件事目前還沒有。

### Caddy parity 控制項

```caddyfile
example.com {
    error_page 404 /srv/errors/404.html

    @legacy path /legacy/*
    redir @legacy https://example.com/new permanent

    handle /api/* {
        cors https://app.example.com {
            methods GET POST
            allow_credentials
        }
        access_control {
            allow_ip 10.0.0.0/8
            deny_user_agent "(?i)bot"
        }
        # 正則 capture 使用 $1、$2……，並會保留 query string。
        rewrite "^/api/(.*)$" "/v1/$1"
        reverse_proxy 127.0.0.1:3000
    }
}
```

### 片段與 import

片段（snippet）是以 `(name) { … }` 定義、用 `import name` 引用的可重用片段。
import 可以把一個區塊交給片段，片段裡寫 `{block}` 的地方會被該區塊取代；
具名子區塊用 `{blocks.<key>}` 定址：

```caddyfile
(site) {
    https://{args[0]} {
        {block}
    }
}

import site test.domain {
    reverse_proxy 127.0.0.1:3000 {
        header_up Host {host}
    }
}
```

沒有餵內容的佔位符就取代為空，所以寫了 `{block}` 的片段在呼叫端沒給區塊時
仍然可以編譯。參數列內的佔位符會被拒絕：Caddy 的 token 層可以在取代後重新
解析那一行，directive 樹做不到，所以 Pingclair 會明說而不是猜測。從檔案
import 進來的片段定義，對之後的 import 都看得到。

### 日誌文法

`log <name> { … }` 跟 Caddy 一樣：區塊設定一個**具名的站台 logger**，名字就是
它的 handle。沒有區塊的 `log <name>` 仍指向全域選項宣告的 channel；單獨一個
`log` 則開啟站台預設的 access log。log 區塊接受 `hostnames`、`include`／
`exclude`（全域）、`sampling`，以及檔案輪替選項（`mode`、`dir_mode`、
`roll_*`）；`log_skip` 會把符合的請求排除在 access log 之外。

### 尚未支援

Pingclair 對外宣稱相容 Caddyfile，那麼這個宣稱誠實的另一半，就是講清楚它到哪裡
為止。以下每一個名字都是**認得的**：寫了會得到「這個功能還沒做」的錯誤，
不會被當成拼錯，也不會被安靜忽略。用到它們的設定**啟動不了**。

Directive：

  `abort` `acme_server` `copy_response` `copy_response_headers`
  `fs` `intercept` `invoke` `log_append` `log_name`
  `map` `method` `metrics` `push`
  `request_body` `request_header` `skip_log` `tracing`

全域選項：

  `acme_ca` `acme_ca_root` `acme_dns` `acme_eab` `cert_issuer` `cert_lifetime`
  `default_bind` `default_sni` `dns` `ech` `events` `fallback_sni`
  `filesystem` `frankenphp` `key_type` `ocsp_interval` `ocsp_stapling`
  `on_demand_tls` `pki` `preferred_chains` `renew_interval` `renewal_window_ratio`
  `shutdown_delay` `skip_install_trust` `storage` `storage_clean_interval`

其中三件值得直接講明白，因為它們決定的是「Pingclair 適不適合你」，
而不是之後才會踩到的細節：

- **沒有 DNS-01 challenge**（`acme_dns`、`tls { dns … }`），所以**沒有萬用字元
  憑證**，80 埠不通的機器也簽不到憑證。
- **PHP 透過 `php_fastcgi` 以 FastCGI 提供**（HTTP/1.1 與 HTTP/2）；
  HTTP/3 在 H3 planner 自備 FastCGI client 之前，會對 FastCGI route 回 501。
- **憑證與狀態只存在本機磁碟**（`storage`），多個實例無法共用同一份憑證儲存。

`handle_errors` 值得單獨一行：這個型別在程式碼裡存在但什麼都不做，
所以它是**被拒絕**而不是被接受。自訂錯誤頁請用 `error_page`——
那是 Pingclair 自己的 directive，不是 Caddy 的。

> 🔁 只要 parser 拒絕的名字沒出現在這份文件裡，測試就會紅，所以這份清單不會
> 悄悄落後 parser 查的那張表。README 宣稱一個 binary 沒有的能力，比宣稱得少還糟。

## 🏗️ 架構概觀

Pingclair 採用模組化的 Cargo Workspace 結構管理程式碼：

| Crate（模組） | 說明 |
|---------------|------|
| **`pingclair`** | **CLI 進入點**。負責解析命令列參數、初始化日誌，並引導系統啟動。 |
| **`pingclair-core`** | **核心執行期**。定義核心資料結構、Trait 與伺服器生命週期管理。 |
| **`pingclair-config`** | **設定編譯器**。負責解析 `Pingclairfile`，進行詞法分析、語法分析與語意檢查，產生執行期設定物件。 |
| **`pingclair-proxy`** | **代理實作**。基於 Pingora Proxy Trait 實作的 HTTP／TCP 代理邏輯，包含負載平衡器，以及基於 Cloudflare quiche 打造的 HTTP/3（QUIC）監聽器。 |
| **`pingclair-static`** | **靜態檔案服務**。實作高效率的檔案讀取、MIME 類型推斷與串流傳輸。 |
| **`pingclair-tls`** | **TLS 管理**。處理手動憑證、持久化 internal CA 與 ACME 自動申請（Let's Encrypt）。 |
| **`pingclair-api`** | **Admin API**。提供 RESTful 介面，可在執行期動態檢視狀態或熱更新設定。 |
| **`pingclair-plugin`** | 🚧 **骨架，尚不可用**。未來外掛介面的雛形，整個 workspace 沒有任何呼叫者。設定裡寫 `plugin` handler 會被**拒絕**，而不是接受後靜默忽略。規劃於 v0.3。 |

## 🤝 參與貢獻

我們非常歡迎社群的貢獻！無論你想修正 Bug、新增特性，或僅僅是改善文件。

請先閱讀 **[CONTRIBUTING.md](CONTRIBUTING.md)**。裡面說明了每個 commit 都必須通過的四道 gate、對一個 Web 伺服器而言什麼才算測試充分，以及從程式碼本身看不出來的架構限制（BoringSSL 鏈結、HTTP/3 路徑、bounded memory）。

各版本之間改了什麼——以及哪些已經在 `main` 上但尚未發布——記在 **[CHANGELOG.md](CHANGELOG.md)**。

首次貢獻者需簽署一次性的 [CLA](CLA.md)。**你的著作權仍屬於你自己。**

## 📄 授權條款

本專案採用 **Apache 2.0 授權條款** 開源。完整條款見 [LICENSE](LICENSE)，
散布時的姓名標示義務與第三方元件見 [NOTICE](NOTICE)。

---

<div align="center">
  <sub>以 ❤️ 與 Rust 打造</sub>
</div>
