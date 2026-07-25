<div align="center">

# 🦀 Pingclair

**基於 Pingora 打造的現代高效能 Web 伺服器與反向代理**  
*結合 Cloudflare Pingora 的極致效能與 Caddy 的極簡開發體驗*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](https://github.com/dorianverlaine/pingclair/pulls)

[English](README.md) · **繁體中文** · [Français](README.fr.md)

</div>

---

## 📖 專案簡介

**Pingclair** 是新一代的 Web 伺服器與反向代理工具。它的核心理念，是把 **Cloudflare Pingora**（處理過兆級請求的 Rust 代理框架）的強大能力，包裝在一層近似 **Caddy** 的易用外殼之下。

傳統 Nginx 的設定往往晦澀難懂，而 Caddy 雖然好用，卻建立在 Go 之上。Pingclair 想要填補這個空缺：提供一套 **100% 以 Rust 撰寫**、**記憶體安全**、**高效能**且**設定直覺**的方案。

無論你需要的是單純的靜態檔案伺服器，還是支援複雜負載平衡、自動 HTTPS 與 HTTP/3 的企業級閘道，Pingclair 都能勝任。

## ✨ 核心特性

*   🚀 **以 Pingora 為核心** — 站在巨人的肩膀上，倚靠 Cloudflare 歷經實戰驗證的基礎設施，提供企業級的穩定度與吞吐量。
*   🔒 **記憶體安全** — 受惠於 Rust 的語言特性，徹底杜絕緩衝區溢位這類常見的記憶體安全漏洞。
*   📝 **相容 Caddyfile 的設定** — 極簡的設定 DSL，支援**自動 HTTPS**、**多重監聽器**與**具名匹配器**，相容主流 Caddyfile 語法。
*   ⚡ **原生支援 HTTP/3 (QUIC)** — 基於 Cloudflare 的 [quiche](https://github.com/cloudflare/quiche)（支撐 Cloudflare 邊緣網路的生產級 QUIC 協定棧）打造，在不穩定的網路環境下提供更低的延遲與更好的連線遷移能力。
*   🔄 **智慧負載平衡** — 內建多種演算法（輪詢、最少連線等），支援健康檢查與故障自動轉移。
*   🔐 **全自動 HTTPS** — 整合 ACME 協定（如 Let's Encrypt），自動申請與續期 SSL/TLS 憑證，零設定即可啟用加密傳輸。
*   📁 **高效能靜態檔案服務** — 支援 Gzip/Brotli 壓縮、Range 請求與高效率的檔案傳輸。
*   📊 **可觀測性** — 開箱即用的 Prometheus 指標匯出與 OpenTelemetry Tracing 支援。

## ⚡ 效能基準測試

完整方法論、原始數據，以及——更重要的——這次測試過程中揪出並修好的臭蟲都寫在
[`benchmarks/README.md`](benchmarks/README.md)（英文）。下結論前請務必先讀完整版。

**測試環境**：裸機 VPS（阿里雲，2 vCPU／1.6GB，Ubuntu 24.04），每台伺服器輪流監聽
`127.0.0.1:8080`，`wrk -t2 -d15s` 走 loopback（原始數據見 `results/20260725_vps_onbox/`）。

| 場景 | Pingclair | Nginx | Caddy |
|------|-----------|-------|-------|
| 靜態 1KB、純文字（c100） | 50,145 req/s | **53,579 req/s** | 17,337 req/s |
| 靜態 1KB、gzip（c100） | **42,982 req/s** | 42,510 req/s | 15,302 req/s |
| 反向代理（c100） | 20,154 req/s | **21,961 req/s** | 9,870 req/s |
| 大檔案 20MB、gzip（c20） | **703 req/s、0 逾時** | 9.1 req/s、110 逾時 | 10.1 req/s、65 逾時 |

**如何解讀**

- 小檔案靜態服務現在與 nginx 基本打平（純文字 94%、gzip 101%），約為 Caddy 的 2.9 倍。
  早期測試曾落後 nginx 約 2.9 倍，根因是 `tokio::fs`：每次調用都是一次
  `spawn_blocking` 跨執行緒往返，每個請求要付出約 8 次 futex 喚醒/等待。
  靜態熱路徑現已改為同步 `std::fs`（與 nginx 同模型：本地檔案讀取實際不阻塞），
  futex 從每請求 8 次降到約 0，吞吐從 18.7k 提升到 50k req/s。
  完整過程見 `benchmarks/README.md`。
- 反向代理約為 nginx 的 92%、Caddy 的 2 倍，三者均零錯誤。
- 大型可壓縮檔案是壓縮快取的主場：pingclair 吞吐量約為 nginx/caddy 的 70 倍且
  **零逾時**，因為重複命中完全跳過壓縮，而 nginx 和 caddy 每次都重新壓縮 20MB 檔案。
  快取的代價是設計上的記憶體預算（峰值 RSS 74 MiB，nginx 為 21 MiB——上限 64MB）。
- 各引擎的壓縮等級並未完全對齊（nginx 用 `gzip_comp_level 1`，其他用各自預設值），
  所以 gzip 數字僅供參考，不是精確的同比。

另有一次較早的 Docker bridge 測試（2 vCPU／512MB 容器，Apple M2），完整矩陣以及
**透過基準測試發現並修復的 20 個臭蟲** 的完整清單——包括一個讓 20 秒測試跑成
16 分鐘的靜態壓縮臭蟲——都記錄在
[`benchmarks/README.md`](benchmarks/README.md)。

## 📦 安裝指南

### 前置需求

*   **Rust 工具鏈** — 需要 Rust 1.88 或更新的版本。

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

### Ubuntu／Debian 一鍵安裝（推薦）

如果你使用 Ubuntu 或 Debian，可以直接執行安裝腳本。該腳本會自動下載（或編譯）執行檔、設定 `systemd` 服務，並建立低權限的 `pingclair` 使用者（透過 `setcap` 綁定低號連接埠）。

```bash
# 執行安裝腳本（需要 sudo 權限）
curl -fsSL https://raw.githubusercontent.com/dorianverlaine/pingclair/main/scripts/install.sh | sudo bash
```

安裝完成後，可以使用 `pc`（pingclair 的縮寫）指令來管理服務。

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

Pingclairfile 是一種結構化的設定語言。它看起來很像 Rust 程式碼，但專門用於描述伺服器的行為。

### 基礎結構

最簡單的設定包含一個或多個站台區塊：

```caddyfile
# 定義一個監聽 localhost 的伺服器
localhost:8080 {
    # 靜態檔案服務
    file_server ./public
}
```

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
        # 僅在所有主要後端皆不可用時使用。
        to 10.0.0.3:8080 { backup }
    }
}
```

### Caddy parity 控制項

```caddyfile
example.com {
    error_page 404 /srv/errors/404.html

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

## 🏗️ 架構概觀

Pingclair 採用模組化的 Cargo Workspace 結構管理程式碼：

| Crate（模組） | 說明 |
|---------------|------|
| **`pingclair`** | **CLI 進入點**。負責解析命令列參數、初始化日誌，並引導系統啟動。 |
| **`pingclair-core`** | **核心執行期**。定義核心資料結構、Trait 與伺服器生命週期管理。 |
| **`pingclair-config`** | **設定編譯器**。負責解析 `Pingclairfile`，進行詞法分析、語法分析與語意檢查，產生執行期設定物件。 |
| **`pingclair-proxy`** | **代理實作**。基於 Pingora Proxy Trait 實作的 HTTP／TCP 代理邏輯，包含負載平衡器，以及基於 Cloudflare quiche 打造的 HTTP/3（QUIC）監聽器。 |
| **`pingclair-static`** | **靜態檔案服務**。實作高效率的檔案讀取、MIME 類型推斷與串流傳輸。 |
| **`pingclair-tls`** | **TLS 管理**。處理憑證載入與 ACME 自動申請（Let's Encrypt）。 |
| **`pingclair-api`** | **Admin API**。提供 RESTful 介面，可在執行期動態檢視狀態或熱更新設定。 |
| **`pingclair-plugin`** | **外掛系統**。定義外掛介面，讓第三方開發者得以擴充功能。 |

## 🤝 參與貢獻

我們非常歡迎社群的貢獻！無論你想修正 Bug、新增特性，或僅僅是改善文件。

### 開發流程

1.  **Fork** 本儲存庫。
2.  **建立分支**：`git checkout -b feature/my-cool-feature`
3.  **撰寫程式碼**：遵循 Rust 的程式碼風格。
4.  **執行測試**：確保所有測試皆通過。
    ```bash
    cargo test --workspace
    ```
5.  **送出 PR**：在 Pull Request 中描述你的改動。

## 📄 授權條款

本專案採用 **Apache 2.0 授權條款** 開源。詳情請見 [LICENSE](LICENSE) 檔案。

---

<div align="center">
  <sub>以 ❤️ 與 Rust 打造</sub>
</div>
