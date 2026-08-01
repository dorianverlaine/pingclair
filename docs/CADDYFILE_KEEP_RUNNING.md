# Keep Caddy Running 需求文檔（服務管理與部署）

> 📌 本專項以 Caddy 官方文檔（`docs/running`，本機
> `~/code/caddy-website`）為基準，對照 Pingclair 現有的
> systemd unit、Dockerfile、install script 與 README。

## 1. Pingclair 現有素材（比預期完整）

- **systemd unit**：`scripts/pingclair.service`（與
  `deployment/pingclair.service` 兩份，內容有差異）；
  `ExecStartPre=pingclair validate`、`AmbientCapabilities=
  CAP_NET_BIND_SERVICE`、`ProtectSystem=full`、`PrivateTmp`、
  `NoNewPrivileges`、`LimitNOFILE`；
- **install/uninstall script**：`scripts/install.sh`（README 宣稱
  會建 `pingclair` user、setcap、systemd unit；`pc` 命令包裝）；
- **Docker**：根目錄 `Dockerfile`（dev 用，預設 CMD 是
  `file-server --listen :8080`）、`deployment/Dockerfile`（build
  stage）、GHCR dev image（README）；
- **service 子命令**：`pingclair service start|stop|restart|reload|
  status` = systemctl 包裝。

## 2. 已確認缺口（依影響排序）

### 🟠 K-1：unit 的 `Restart=always` 與 Caddy 的「exit 1 不要自動重啟」衝突

Caddy 文件明確：

```systemd
RestartPreventExitStatus=1
Restart=on-failure
```

原因是 exit code 1 = **failed startup**（config 壞了），自動重啟只會
重複失敗、刷 log；要等管理員修好 config。Pingclair 兩份 unit 都是
`Restart=always`——`ExecStartPre` 的 validate 雖然擋住大部分 config
錯誤，但 validate 只到 compile 層（CLI 文檔 C2：不檢查 cert 檔案
存在性），runtime 啟動失敗一樣會無限重啟。

**需求**：unit 改 `Restart=on-failure`＋`RestartPreventExitStatus=1`
（並與 CLI-10 的 exit code 語意一起做）。

### 🟠 K-2：兩份 unit 內容不一致

`scripts/pingclair.service` 有 `ProtectSystem=full`、
`CapabilityBoundingSet`、`LimitNPROC`、`ExecStartPre=validate`；
`deployment/pingclair.service` 沒有這些、路徑大小寫也不同
（`/etc/Pingclair` vs `/etc/pingclair`）。使用者照哪一份裝，硬化
程度不同。**需求**：單一來源（建議 `scripts/`），deployment 改
引用或刪除。

### 🟡 K-3：沒有 API 工作流的 service variant

Caddy 提供 `caddy-api.service`（`caddy run --resume`，配
autosave）。Pingclair 沒有 `--resume`（admin 文檔 A5），自然沒有
對應 variant。API 工作流實作（API-8）時要一起補。

### 🟡 K-4：沒有 production Docker Compose 範例

README 只給 dev 的 `docker run`（bind mount Pingclairfile、:8080）。
Caddy 官方提供 production compose：80/443/443-udp（H3）、
`caddy_data`/`caddy_config` 持久化 volume、`restart:
unless-stopped`。Pingclair 缺：

- 官方 compose 範例（含 UDP 443 給 H3、`PINGCLAIR_TLS_STORE`
  volume）；
- 容器內 local HTTPS（`tls internal`）的 trust 安裝指引
  （root.crt 從容器複製到 host trust store）。

### 🟡 K-5：root Dockerfile 的預設 CMD 只是 file-server demo

`CMD ["pingclair", "file-server", "--listen", ":8080", ...]`——
`docker run ghcr.io/...` 起的是 demo 不是「讀 /etc/pingclair 的
config 跑 server」。README 的 dev 用法有 bind mount config 但沒有
預設 CMD 對應。需求：README 提供 `docker run ... pingclair run
/etc/pingclair/Pingclairfile` 的完整範例（含 port 80/443/443-udp
與 TLS store volume）。

### 🟡 K-6：local HTTPS 的 trust 安裝流程沒有文件化

Caddy 文件給 systemd（`sudo caddy trust`）與 Docker（複製 root.crt
到 host trust store）的完整流程。Pingclair 的 `tls internal` 有
`root.crt` 發佈（GUARDRAILS），但 README 沒有「安裝到 trust store」
的指示（macOS/Linux/Windows/browser 各別）。至少補 README 段落。

### 🟡 K-7：reload 訊號差異（承接 CLI C3）

unit 的 `ExecReload=/bin/kill -HUP $MAINPID`。Caddy v2.11+ 的
Docker 範例用 SIGUSR1，systemd 用 `caddy reload`（admin API）。
承接 CLI 文檔 C3：支援 SIGUSR1 後，unit 的 ExecReload 可改用
`pingclair reload --config ...`（配合 API-2）或維持 SIGHUP 並
寫清楚。

## 3. 驗證需求

1. unit 檔案單一來源；`Restart=on-failure`＋`RestartPreventExitStatus=1`
   （config 壞掉時 systemctl status 顯示 failed 而非 restart loop）；
2. install script 產出的 unit 與 `scripts/` 一致；
3. README 補 production compose（80/443/443-udp、TLS store
   volume）與 local HTTPS trust 安裝流程；
4. `docker run ghcr.io/dorianverlaine/pingclair:dev pingclair run
   /etc/pingclair/Pingclairfile` 的完整範例可用。

## 4. 明確不做（本文件範圍外）

- Windows service（sc.exe/WinSW）——Pingclair 目標是 Linux/macOS，
  列 v0.3+。
- SELinux label 指引——Linux distro 打包時再做。
