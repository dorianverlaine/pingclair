# Caddyfile Tutorial 需求文檔

> 📌 本專項以 Caddy 官方文檔（`caddyfile-tutorial`，本機
> `~/code/caddy-website`）為基準。Tutorial 是新手的第一份文件，
> **如果 tutorial 的範例不能跑，文件宣稱的「Caddyfile-compatible」
> 對新使用者就是假的**。

## 1. 官方 Tutorial 內容與 Pingclair 驗證結果（2026-08-01 實測）

> 全部以 `compile()` 實測；臨時探針已刪除，工作區無改動。

| Tutorial 步驟 | 官方寫法 | Pingclair 結果 |
|---|---|---|
| 第一個 site | `localhost` + `respond "Hello, world!"`（**無大括號**） | ❌ 兩行各自變成 server block |
| 靜態檔案 | `file_server browse` | ❌ `browse` 被當成 root 目錄 |
| Templates | `templates` | ❌ Unknown directive |
| 壓縮 | `encode` | ✅（braced 寫法下有效） |
| 多站台 | `:8080 { }` + `:8081 { }` | ❌ 編譯失敗（duplicate `_`） |
| 共用位址 | `:8080, :8081 { }` | ⚠️ 編譯過但位址解析有誤 |
| Matchers | `reverse_proxy /api/* 127.0.0.1:9005` | ❌ `/api/*` 被當 upstream |
| 環境變數 | `{$SITE_ADDRESS}` | ❌ 被當成字面 directive 名 |
| Comments | `# ...` | ✅ |

## 2. 已確認 bug（依影響排序）

### 🔴 U1：單站「無大括號」簡寫完全壞掉

Tutorial 最前面的寫法：

```caddy
localhost

respond "Hello, world!"
```

在 Caddy 等於：

```caddy
localhost {
    respond "Hello, world!"
}
```

Pingclair 實測：編譯出**兩個 server block**——`name="localhost"`
（無 routes）與 `name="respond"`（listen `0.0.0.0:80`、無 routes）。
因為 `parse_config()` 把每個頂層 directive 都當成獨立的 site
block。三行範例：

```caddy
localhost

encode
templates
file_server browse
```

變成四個 server（localhost/encode/templates/file_server），全部空轉。
**Tutorial 的核心入門寫法在 Pingclair 完全不可用**，而且編譯成功、
不報錯——比失敗更糟。

**需求**：實作「單一 site block 可省略大括號」的 Caddy 語義：
第一個 token 是 site 位址，後續行全部屬於該 site。實作上需要在
parser 或 adapter 層判斷「檔案只有一個未加括號的 site」。

### 🟠 U2：`file_server browse` 的 inline 形式被誤解

```caddy
localhost {
    file_server browse
}
```

編譯結果：`FileServer { root: "browse", browse: false }`——Caddy 的
`browse` 是「啟用目錄列表」的旗標參數；Pingclair 把它當成 root。
正確寫法 `file_server { browse }` 可以跑（探針確認 browse=true），
但官方 tutorial 教的是 inline 形式。需求：`file_server` 的第一個
參數若是 `browse`，設 browse=true；若是路徑，設 root（現況）。

### 🟠 U3：環境變數沒有在 parse 前展開

```caddy
{$SITE_ADDRESS}

file_server
```

Caddy：parse 前把 `{$SITE_ADDRESS}` 展開成
`localhost:9055`（可展開成多個 token、可空值）。Pingclair：
lexer 產生 `EnvVar("SITE_ADDRESS")` token，parser 把它當
**directive 名**（`name="SITE_ADDRESS"`），編譯成一個名叫
SITE_ADDRESS 的 server。`VariableResolver` 存在但沒有在
`parse()` 前執行（或在 site address 位置生效）。

**需求**：parse 前展開 env var（含 `{$VAR:default}` 預設值語法），
並處理「展開為空」的合法情況（Caddy 文檔明確支援）。

### 🟠 U4：`:8080` 與 `:8081` 兩個裸 port site 編譯失敗

```caddy
:8080 {
    respond "I am 8080"
}
:8081 {
    respond "I am 8081"
}
```

實測：`Semantic error: Duplicate server name: _`——兩個裸 port site
的 name 都塌成 `_`（位址文檔 B3 的同一根因），semantic analyzer
把 `_` 當重複名稱拒絕。Caddy 允許多個裸 port site（這是 tutorial
「多站台」的標準示範）。修 B3（name 不因 listen 塌陷）時，這個
case 要一起過。

### 🟡 U5：`templates` directive 不支援

Tutorial 的 templates 章節整段不能跑。`templates` 是
`file_server` 的姊妹功能（server-side template rendering），
Pingclair 沒有。需求：錯誤訊息明確提示「templates 尚未支援」，
或列 v0.3 排期（同 directives 文檔 D6 的未支援清單）。

### 🟡 U6：`localhost` 教學開頭就撞自動 HTTPS 缺口

Tutorial 第一行 `localhost` 在 Caddy 會自動 HTTPS（本機 CA + 第一次
跑時裝 trust root）。Pingclair 預設明文 80（automatic-https 文檔
T6；位址文檔 B5）。新手照 tutorial 打開 `https://localhost` 會直接
失敗。修 T6（localhost 預設走 `tls internal`）後 tutorial 第一步
才能成立。

## 3. 驗證需求

1. **單元**：把 tutorial 每一段原始範例做成 compile 測試（同
   patterns 文檔的建議——官方原文當 fixture）；
2. **單元**：`{$VAR}` 展開（含 default 值與多 token 展開）；
3. **真 binary**：`localhost` + `respond`（無大括號）跑出 200；
   `file_server browse` 列出目錄；`:8080`＋`:8081` 同時服務；
   `reverse_proxy /api/* 127.0.0.1:9005` 分流正確。

## 4. 明確不做（本文件範圍外）

- `templates` 的完整實作（模板引擎）——列 v0.3+。
- `--watch`（自動重載設定檔）——CLI 功能，列 v0.3。
