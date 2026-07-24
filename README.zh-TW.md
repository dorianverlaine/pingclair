<div align="center">

# 🦀 Pingclair

**基於 Pingora 打造的現代高效能 Web 伺服器與反向代理**  
*結合 Cloudflare Pingora 的極致效能與 Caddy 的極簡開發體驗*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
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
*   ⚡ **原生支援 HTTP/3 (QUIC)** — 擁抱新一代網路協定，在不穩定的網路環境下提供更低的延遲與更好的連線遷移能力。
*   🔄 **智慧負載平衡** — 內建多種演算法（輪詢、最少連線等），支援健康檢查與故障自動轉移。
*   🔐 **全自動 HTTPS** — 整合 ACME 協定（如 Let's Encrypt），自動申請與續期 SSL/TLS 憑證，零設定即可啟用加密傳輸。
*   📁 **高效能靜態檔案服務** — 支援 Gzip/Brotli 壓縮、Range 請求與高效率的檔案傳輸。
*   🔌 **模組化外掛系統** — *（開發中）* 透過 Rust trait 擴充自訂功能，無需修改核心程式碼。
*   📊 **可觀測性** — 開箱即用的 Prometheus 指標匯出與 OpenTelemetry Tracing 支援。

## ⚡ 效能基準測試

完整方法論、原始數據，以及——更重要的——這次測試過程中揪出的臭蟲（包含一個尚未修復的）都寫在
[`benchmarks/README.md`](benchmarks/README.md)（英文）。下表只是靜態檔案的重點數字；下結論前請務必先讀完整版，尤其是反向代理吞吐量與高負載下 gzip 壓縮的部分。

**測試環境**：Docker bridge 網路，每台伺服器各自跑在獨立容器內，限制 2 vCPU／512MB，MacBook Pro（M2），`wrk -t4 -d15s`，1 KB 靜態檔案。

| 伺服器 | RPS @ c50 | RPS @ c500 | 備註 |
|--------|-----------|------------|------|
| **Nginx (Alpine)** | ~28,801 | ~27,853 | 在此檔案大小、各並發層級下都是最快的 |
| **Pingclair (Debian)** | ~22,942 | ~21,162 | 約達 Nginx 的 75-80% |
| **Caddy (Alpine)** | ~18,309 | ~18,448 | 表現穩定，約達 Nginx 的 65% |

> **比表格數字更重要的但書**
> 在這個容器限流的測試環境下，反向代理吞吐量測試中 pingclair 在較高並發時反而領先 nginx 和 caddy——這個結果是真實的，但尚未在無限流的硬體上驗證，不應當作一般性結論。更重要的是，大檔案（20MB）gzip 壓力測試揪出了一個真實、目前仍未修復的臭蟲：pingclair 的靜態檔案壓縮路徑會把整個檔案完整緩衝在記憶體、且沒有快取，在持續並發負載下，原本 20 秒的測試跑了 **16 分鐘**（沒有當機、沒有 OOM，純粹是嚴重的排隊塞車）。完整細節請見
> [`benchmarks/README.md`](benchmarks/README.md)。

## 📦 安裝指南

### 前置需求

*   **Rust 工具鏈** — 需要 Rust 1.85 或更新的版本。

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
    # 反向代理到多個後端
    reverse_proxy 10.0.0.1:8080 10.0.0.2:8080 {
        # 負載平衡策略：round_robin、random、least_conn
        lb_policy least_conn

        # 失敗重試
        failover true
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
| **`pingclair-proxy`** | **代理實作**。基於 Pingora Proxy Trait 實作的 HTTP／TCP 代理邏輯，包含負載平衡器。 |
| **`pingclair-static`** | **靜態檔案服務**。實作高效率的檔案讀取、MIME 類型推斷與串流傳輸。 |
| **`pingclair-tls`** | **TLS 管理**。處理憑證載入、ACME 自動申請（Let's Encrypt）以及 QUIC 交握邏輯。 |
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
