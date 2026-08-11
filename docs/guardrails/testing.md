# ⚠️ Pingclair 實作守則 — 測試與除錯

## 🧪 測試與除錯

- **同一件事不要有兩份建置設定。** 2026-08-05 的 Day 22 發現：倉庫根目錄有一份
  `Dockerfile`，`docker build .` —— 從乾淨 checkout 最顯然的那條命令 ——
  **會失敗**，因為它逐項列出要 COPY 的 crate 而漏了 `[patch.crates-io]` 需要的
  `vendor/`。CI 建的是 `deployment/Dockerfile`（`COPY . .`），所以根目錄那份
  **從來沒有被任何工作流建過**，而 `benchmarks/docker-compose.yml` 正指著它。

  更早的 2026-07-31 事故已經記過同一個形狀（見下方鏈結一節：Dockerfile 漂移
  導致線上 image 與 CI 不同）。當時的結論是「改一邊就要改另一邊」，
  **那個結論不夠**——需要人記得的一致性，遲早會有人不記得。

  > 🎯 **可操作的規則**：重複的建置設定要**刪掉**，不是靠紀律同步。
  > 根目錄那份已於 2026-08-05 移除，`deployment/Dockerfile` 是唯一一份，
  > 而 `ci.yml` 的 `docker-image` job 每次都建它。

- **一個綠燈的單元測試，可能檢查的是對的東西、錯的層級。**
  2026-08-04 加 `lb_policy header X-Session` 時，同時寫了
  `an_absent_or_empty_value_yields_no_key`：請求沒帶那個 header 時，
  `extract_hash_key` 必須回 `None`。它是綠的，而且**斷言本身完全正確**。

  但沒有人問：**balancer 拿到那個 `None` 會做什麼？** 答案是
  `key.unwrap_or(b"")`，然後雜湊空字串——完全一致，所以每一個沒帶 header
  的請求都落到同一個後端。以 session header 而言那是所有尚未登入的使用者，
  也就是站上最忙的流量全部打一台。

  當天的 Day 22 驗證用四個真後端跑在容器裡，40 次請求全部落在同一台，
  一眼就看見了。

  > 🎯 **可操作的規則**：測「A 在某情況回傳哨兵值」時，**同一次一併測
  > 「A 的呼叫端拿到那個哨兵值之後做了什麼」**。`None`／`""`／`0`／空集合
  > 這些值的意義不在產生它的函式裡，在消費它的地方。單獨測產生端，
  > 等於驗證了一半的合約然後宣稱整份成立。

- **自簽憑證測不出憑證鏈的缺陷。** 自簽憑證自己就是自己的簽發者，它**沒有**
  中繼憑證——「只送 leaf」和「送完整鏈」產生的位元組完全相同。所以任何用
  自簽 fixture 的 TLS 測試，對「伺服器把中繼憑證丟掉了」這類 bug 是**物理上
  不可觀測**的。2026-07-30 的雙區域公網驗證就是這樣抓到 H1／H2 只送 leaf：
  在那之前 474 個測試沒有一個可能發現它。要驗憑證鏈，fixture 必須是
  root → intermediate → leaf 的真實兩層信任路徑（`rcgen` 可以直接建，見
  `pingclair/tests/integration.rs` 的 `build_two_level_chain`），
  斷言用 client 端的 `peer_cert_chain().len()`。
- **瀏覽器不能當 TLS 憑證鏈的驗收工具。** Chrome 與 Firefox 會快取中繼憑證，
  也會用 AIA 自己去補抓缺少的那張，所以**伺服器少送中繼，瀏覽器照樣顯示綠鎖**。
  curl、Go、Java、Python requests 則會直接以
  `unable to get local issuer certificate (20)` 硬失敗。驗收要用嚴格 client，
  不要用瀏覽器「看起來正常」當證據。
- **本機 macOS 有系統代理 `127.0.0.1:1082`**；reqwest 整合測試必須 `.no_proxy()`，
  否則請求會被代理攔截，症狀看起來像路由錯誤。
- **本機 `dig` 會回假 IP。** 系統代理用 fake-IP DNS，直接 `dig example.com`
  得到的是 `198.18.x.x`，看起來像 DNS 還沒生效。查真實解析必須指定公開
  resolver：`dig @8.8.8.8 example.com`。
- **遇到固定 404／502 或 readiness 異常**，先用 `lsof`／`ss` 查 port owner，
  再查 child 是否已因 bind failure 退出。**不要先假設是路由邏輯錯誤**——
  這個誤判浪費過整輪除錯。
- **timeout 時必須先 kill＋wait，再讀 stdout/stderr 到 EOF**。
  順序反了會永久阻塞並留下幽靈程序。
- 真 binary 測試一律用**動態 port**與**唯一 readiness token**。固定 port 會讓
  舊程序被誤判為 ready，測試看似通過實則測到別的東西。
- **真 binary drill 必須設 `PINGCLAIR_TLS_STORE` 指向可寫目錄**，即使配置裡
  完全沒有 TLS。TLS manager 在讀配置前就無條件初始化 store。預設路徑現在是
  每使用者可寫的 `$XDG_DATA_HOME/pingclair`（`~/.local/share/pingclair`），
  不可建立或不可寫時會在啟動時以**指名路徑的明確錯誤**失敗（write-probe，
  見 `pingclair/src/main.rs`），不再是看不出來歷的一行 `PermissionDenied`
  panic——但 drill 仍要設變數：CA、ACME 帳號金鑰與 autosave 文件才不會掉進
  CI runner 的 HOME，測試之間也不會互相污染。
- **`zsh` 不會對未加引號的變數做 word splitting**。`for x in "a 1" ...; set -- $x`
  在 bash 能拆成兩個參數，在 zsh 只會得到一個——症狀是 `$2` 空白，很容易誤讀成
  被測程式的問題。測試腳本改用明確參數的 function。
- **壓縮測試的 payload 必須逐 chunk 唯一且不可壓縮**。重複同一塊資料會被
  zstd 的 window 去重（64MiB → 15KB），讓「輸出有在流動」這類斷言**假性失敗**。
- **本機 gate 必須用 `cargo +1.97.1`,不是預設工具鏈**。CI 釘 `1.97.1`
  （2026-08-02 拆分前是單一 `rust.yml`,現在分散在 `ci.yml`、`lint.yml`
  等六個 workflow），workspace 也宣告 `rust-version = "1.97"`。工具鏈版本
  一不對,型別推論與 rustfmt 換行決策就不同,本機四項全綠然後 CI 全紅——這個
  坑兩個方向都踩過：2026-07-29 是本機比 CI 新（混型陣列 `&[&String, &String,
  &str]` 在 1.88 是 `E0308`）；2026-08-02 反過來,release image 還釘 1.88.0
  而 lockfile 已需要 ≥1.97（`rustc 1.88.0 is not supported`）。
- 🎩 **2026-08-01 起 CI 的 `test` job 跑在 `ubuntu-latest` runner 上**（當天
  在 `rust.yml`；2026-08-02 拆成六個 workflow 後在 `ci.yml`,`lint.yml`
  環境相同）,跟 `deployment/Dockerfile` 同一個 base（Ubuntu）、同一份 rustup
  釘版 1.97.1、同一份 `apt` 套件清單。這條規則源自 2026-07-31 的事故：那份
  Dockerfile 從 H3 換 tokio-quiche 之後**從沒被建過**,線上跑的 image 是
  依賴樹改變前建的,Rust 版本也早就跟 `Cargo.toml` 的宣告不一致。CI 跑在
  別的發行版上會完全遮住這件事。**兩份套件清單必須手動保持同步**——CI 的
  `apt-get install` 跟 Dockerfile builder stage 那份改一邊就要改另一邊,
  目前沒有機制強制同步,這條本身就是下一個可能重犯的坑。
- 🐳 **CI 新增 `docker-image` job（拆分後在 `ci.yml`）,真的建
  `deployment/Dockerfile` 並開機驗證**（`docker run ... version`、
  `docker run ... validate` 一份真 Pingclairfile）。這是「一份沒人跑的建置
  腳本等於沒測試過的程式碼」這句話的直接對策——上面那次 Dockerfile 漂移,
  如果這個 job 當時存在,第一次 push 就會紅。
- 🧑‍🔧 **在容器裡跑整合測試必須加
  `--sysctl net.ipv4.ip_unprivileged_port_start=1024`**。
  `test_admin_adapt_export_and_load`、
  `test_admin_config_for_an_unknown_listener_applies_nothing`、
  `test_admin_config_traversal_unbindable_listener_rolls_back` 這三支證明的是
  「設定裡有綁不上的 listener 就要拒絕並回滾」，而它們把「綁不上」寫成
  `127.0.0.1:1`。**Docker 預設把這個 sysctl 設成 `0`**，於是容器裡的**任何**使用者
  都綁得上 port 1；設定被接受，三支同時以 `200 != 400` 失敗。

  > 🤡 2026-08-10 的除錯順序值得記下來，因為第一個結論是錯的：先看到容器以 root
  > 執行，判斷是 `CAP_NET_BIND_SERVICE`，於是 `useradd` 一個使用者用 `runuser` 重跑
  > ——**三支照樣紅**。真正的機制是那個 sysctl，跟使用者是誰無關。
  > 「以 root 執行」是個看起來足以解釋現象、而且改起來很自然的假設，
  > 這正是它耗掉一整輪的原因。
  >
  > 非 root 仍然該做（那才是產品實際跑的樣子，也是過去 Linux 證據的取得方式），
  > 但它不是這件事的解法。

  > 🪤 **2026-08-10 補正：上面那句「跟使用者是誰無關」只對了一半，害我又踩一次。**
  > K3 那輪為了讓 `CARGO_HOME` 可寫，改回以 root 跑、**只**帶那個 sysctl
  > ——三支又紅了。原因是 root 有 `CAP_NET_BIND_SERVICE`，
  > 那個 capability 直接**繞過** `ip_unprivileged_port_start`（顧名思義：
  > 它只管 unprivileged）。
  >
  > 📌 正確的說法是**兩個條件缺一不可**：
  > **非 root 使用者 ＋ `--sysctl net.ipv4.ip_unprivileged_port_start=1024`**。
  > 上一輪先試非 root（沒帶 sysctl）失敗、這一輪先試 sysctl（用 root）失敗，
  > 兩次都得到「那不是原因」的結論——**逐一排除法在需要兩個條件的情況下
  > 會把兩個真原因都判成無關**。
  >
  > 以非 root 跑時記得 `chown` `CARGO_HOME`、`CARGO_TARGET_DIR` 與 workspace，
  > 否則 `cargo` 直接 `Permission denied`（`rust:1.97-bookworm` 的
  > `/usr/local/cargo` 是 root 所有）。

  > 📌 更一般的形狀：**任何用「這個操作會失敗」當斷言的測試，都隱含一個環境前提**。
  > 前提沒寫下來時，換一個環境就從「證明了某件事」變成「證明不了任何事」，
  > 而且失敗訊息不會提到那個前提。

- ⚖️ **round-robin 測試不可斷言「誰先」**。負載平衡保證的是相鄰請求交替、
  總量平均；**起始的那一台由共用計數器的初始值決定**，設定裡沒有任何東西釘住它。
  2026-08-10：`test_php_fastcgi_round_robins_across_multiple_responders` 斷言
  `["first","second","first","second"]`，在 macOS 綠、在 Linux 紅成
  `["second","first",…]`——同一個正確行為，差一個相位。斷言要寫成性質
  （相鄰不重複 ＋ 各收到一半），不是寫成某一次觀察到的序列。

- 🎲 **`test_websocket_upgrade_tunnels_bytes_in_both_directions` 是已知的
  上游（Pingora）flaky**。`ci.yml` 的 `Run tests` 步驟會重跑整輪測試
  （最多三次），但**僅限**該測試是唯一失敗項；其他測試失敗或三次都失敗
  仍然直接紅。**不要為了這個 flake 改測試代碼**——它偶發失敗不代表有
  回歸，用 retry 消掉雜訊就好。

  > 📌 **依據**（2026-08-10 補；在此之前這條只有結論，沒有出處，
  > 而本倉庫的規則是「只寫結論的否決註解會變成一道沒人敢推的門」）：
  > 已回報上游 [cloudflare/pingora#946](https://github.com/cloudflare/pingora/issues/946)
  > 〈HTTP/1 upgrade torn down when the upstream's 101 is read before the
  > request's empty body〉（2026-07-30 開，仍 open），修正在
  > [#947](https://github.com/cloudflare/pingora/pull/947)
  > 〈Keep an upgraded tunnel open when the request body ends after 101〉
  > （2026-08-04 開，**尚未合併**）。症狀是等 tunnel marker 時收到
  > `UnexpectedEof`。
  >
  > **這條的有效期綁在 #947**：合併並進入我們釘的 pingora 版本之後，
  > 這個 flake 應該消失，屆時要拿掉 `ci.yml` 的 retry 並讓它恢復成一次
  > 就該綠的測試。留著 retry 而 flake 已經修好，等於留一個永遠不會紅的
  > 測試。
- 🔒 **新增 `security-audit` job（`cargo audit`）,每次 push 都跑**,不只在
  發布前跑一次。RustSec 公告的時間不受這個專案控制,一個已合併但後來被公告
  漏洞的依賴,只有持續跑才抓得到。真的出現 finding 時的例外處理是**書面風險
  接受**（既有的書面風險接受規則),不是把這個 job 改成
  `continue-on-error`。
- **要在容器 log 裡看到 ERROR 以下的內容必須設 `RUST_LOG`**。subscriber 是
  `EnvFilter::from_default_env()` 建的，沒設等於只留 ERROR——症狀是功能明明
  正常卻「什麼都沒 log」。
- **grep 容器 log 前要先剝掉 ANSI**。tracing 的 fmt layer 即使 stdout 不是 tty
  也會給欄位名上色，`from=1.2.3.4` 實際上是 `from<ESC>[0m<ESC>[2m=<ESC>[0m1.2.3.4`，
  直接 grep 字面字串會**假性失敗**。
- **改 bind-mount 的單一檔案禁止用 `sed -i`**。bind mount 綁的是 **inode 不是路徑**：
  `sed -i` 寫新檔再改名蓋過去，宿主看到改動、**容器繼續讀舊 inode**。這個失敗
  完全無聲——reload 會回報「成功」（它確實重載了，只是內容一模一樣），於是
  「壞配置被拒」「last-known-good 還在」這類斷言**全部假性通過**。
  一律用 `cat new > target` 這種**原地截斷改寫**，並在演練開頭斷言
  `stat -c %i` 宿主與容器一致。2026-07-28 Day 7 實際踩到，兩條 ✅ 是假的。
- **`grep -q` 不要放在 `set -o pipefail` 的 pipeline 尾端**。命中即提前退出會把
  上游 SIGPIPE 掉，141 變成整條 pipeline 的狀態，**命中反而被讀成失敗**；
  而且只有輸出夠長才輸掉這個 race，所以會間歇性假性失敗。先存檔再 grep 檔案。
- **腳本收 results 目錄參數時要處理絕對路徑**。`-v "$(pwd)/$conf"` 遇到絕對路徑
  會變成 `/tmp//tmp/...`，Docker 靜默建一個空目錄當掛載點，程式起不來。
- **測 DNS 重解析時容器位址要用 `--ip` 明確指定**。讓 Docker 自己配，
  「backend 有沒有跟著搬」就變成看 daemon 的位址回收策略；只有在剛好拿到新
  IP 時才會過的測試不算測試。要製造「名稱解析不到但舊位址還健康」，用
  `docker network disconnect` 後再 `connect --ip <同一個位址>`（不帶 alias）——
  同一個容器、同一個位址，只是名稱查不到了。

---

## 📁 驗證證據

- 結果寫進本機 `benchmarks/results/<date>_<commit-prefix>/`（**不入倉庫**）。
- **失敗的證據不可覆寫**。修好之後另開目錄，保留舊的失敗紀錄作為對照。
- 驗證必須記錄**完整 commit SHA**，不能只寫「最新版」。

## 📊 效能量測：三種「成功的錯誤數字」

2026-08-11 重拉基準線時，三種都真的發生了，而且**沒有一種會讓程式報錯**——
全部要靠事後檢查才發現。這一節存在的目的是讓下一次不必重新發現它們。

- **量測與建置不可並行。** 那天第一次跑基準線時，同一台機器上有一個
  `--platform linux/amd64`（Rosetta 2）的 release 編譯在跑。而這份 harness 量的正是
  **CPU/request**，所以背景負載直接就是被量的東西。污染在資料裡逐輪可見
  （代理 H2 53,836 → 39,447 → 36,172 rps，單調衰退）。

  > 🎯 **可操作的規則**：先把所有二進位編完，確認機器安靜，再開始量。
  > 「只是背景跑一下」不存在。作廢的那一組留在
  > `benchmarks/results/20260811_baseline/contaminated/`，因為逐輪衰退的數字
  > 比規則本身有說服力。

- **每一列都要印 `succeeded`，對不上就作廢。** `h2load -H "host: bench.local"`
  **設不了 HTTP/1.1 的 Host**——Host 取自 URL 的 authority。於是 nginx 和 Pingclair
  都收到 `Host: 127.0.0.1`、都不匹配 vhost，**30000 個請求全是 4xx**；
  而沒有虛擬主機概念的對照組照樣 200，看起來完全正常。
  那張表會顯示我們「贏」四倍，真相是兩邊都在量 404 的成本。

  > 🎯 **可操作的規則**：`h2load` 自己會報 `succeeded/failed`，harness 必須把它
  > 印在每一列旁邊，並在不等於請求總數時把該列當作沒有發生。
  > 想改 Host 就用 `--connect-to=<ip>:<port>` 搭配 URL 裡的真實主機名，
  > 不要用 `-H`。

- **跨機器比較，只能比「除了機器以外全部相同」的兩次執行。** 曾經拿 Mac 的靜態
  結果（`--cpus=2`、`-t2 -c50 -n100000`）去比 athlon 的（`--cpus=1`、`-t1 -c25 -n30000`），
  並把差異解讀成「機器世代的影響」——**那其實是在比較設定**。
  同一次還漏掉一個變因：athlon 沒有 AES-NI，Pingclair 協商到 ChaCha20-Poly1305、
  nginx 協商到 AES-256-GCM，**兩邊根本不是同一件工作**。

  > 🎯 **可操作的規則**：**cipher 也算變因**。跨機器前先確認兩邊協商到同一個
  > cipher suite（`openssl s_client` 看得到），併發、client 執行緒、容器 CPU
  > 配額全部固定，否則得到的是自己的方法而不是機器的性質。
