# The Caddyfile 首頁範例需求文檔

> 📌 Caddy 官方首頁（`docs/caddyfile`）用一段「production-ready、
> 服務 WordPress」的 Caddyfile 當作整個格式的門面。本專項把這段
> 原文當**驗收 fixture**：如果首頁範例不能跑，Caddyfile 相容性的
> 宣稱對任何讀過首頁的人都不成立。

## 1. 官方範例原文

```caddy
example.com {
	root /var/www/wordpress
	encode
	php_fastcgi unix//run/php/php-version-fpm.sock
	file_server
}
```

四個元素：`root`（站台根目錄）、`encode`（壓縮）、
`php_fastcgi unix//...`（FastCGI over Unix socket）、`file_server`
（靜態檔）。外加隱含承諾：`example.com` 自動 HTTPS。

## 2. 驗證結果（2026-08-01 實測）

| 元素 | 結果 | 細節 |
|---|---|---|
| `example.com` 自動 HTTPS | ❌ | 位址文檔 B 系列（`tls auto` 只開明文 80） |
| `root` | ❌ | `Unknown directive 'root'`（patterns 文檔 P1） |
| `encode` | ✅ | braced 寫法下有效 |
| `php_fastcgi` | ❌ | `Unknown directive 'php_fastcgi'`（patterns 文檔） |
| `unix//run/...` socket 語法 | ❌ | **新發現：編譯過但 runtime 必壞**（見 H1） |
| `file_server` | ✅ | 有效（braced 寫法） |

整段原文：**編譯失敗**（卡在 `root`）。

## 3. 新確認 bug

### 🔴 H1：`unix//` Unix socket upstream 語法編譯過、runtime 必壞

```caddy
example.com {
    reverse_proxy unix//run/php/php-version-fpm.sock
}
```

`UpstreamSpec::parse()`（`pingclair-proxy/src/upstream.rs` :77）只認
`h2c://`／`h2://`／`https://`／`http://` 四種 scheme 與裸位址；
`unix//run/php/...` 不匹配任何 scheme，被當成「bare host」解析——
`host = "unix//run/php/php-version-fpm.sock"`、port 80。編譯層
（adapter）**照單全收**，runtime 的 `to_socket_addrs()` 解析該
「hostname」必然失敗，log 一個 warning、upstream 永遠不可用。

Caddy 的 `unix//` 是官方 network-address 慣例（`unix//` + path，
concepts 文檔「Tokens and quotes」外的位址章節也用它）。WordPress
範例正是這種寫法。**這是「編譯成功但行為壞」的另一個實例**，
與 P3（`/api/*` 被當 upstream）、`encode gzipp` 同類。

**需求**：

1. `UpstreamSpec::parse` 支援 `unix//<path>`（及
   `unix://<path>`／`unix:///<path>` 的常見變體），把 upstream
   標記為 Unix socket backend（Pingora `SocketAddr::Unix` 有對應
   能力，load_balancer.rs :177 也已為 Unix backend 做特殊處理）；
2. 不支援時，adapter 至少要在編譯期拒絕 `unix//` 並給出明確錯誤，
   不能放任 runtime 失敗。

### 🟠 H2：首頁範例是「README 宣稱」的驗收基準

`README.md` 宣稱「Caddyfile-compatible config」；首頁範例是最
簡短的 counter-example。需求：`pingclair-config/tests/` 增加
`test_caddy_homepage_example.rs`，把官方首頁、tutorial、patterns
三頁的**原文**當 fixture（見 patterns 文檔 P 系列與 tutorial 文檔
U 系列的同一建議），任何一個不能編譯就是紅燈。

## 4. 驗證需求

1. `example.com { root /var/www/wordpress; encode; php_fastcgi unix//run/php/php-version-fpm.sock; file_server }`
   編譯成功（root、php_fastcgi、unix socket 三個缺口都補上後）；
2. `reverse_proxy unix//run/app.sock`：真 binary 對 Unix socket
   backend 正確代理（或用測試 socket 驗證連線）；
3. 不支援 `unix//` 的過渡期：編譯期明確錯誤 + 錯誤訊息提示
   「Unix socket upstream 尚未支援」。

## 5. 明確不做（本文件範圍外）

- FastCGI client 本身（`php_fastcgi` 的完整實作）——列 v0.3+
  （patterns 文檔已列）。
- WordPress 的 PHP 生態細節（`index.php` fallback 等）——隨
  `php_fastcgi` 一起排期。
