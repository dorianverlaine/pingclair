# 🧪 Pingclair vs Nginx 生产替代性审计

> **审计时间**: 2026-07-25(第二次审计,逐项对照代码核实)
> **上次审计**: 2026-04-20(v0.1.6,P0 四项已全部修复,见文末)
> **当前版本**: v0.1.7

---

## 🔴 上生产前必须修复(Blocker)

### 1. Admin API 完全无认证,且默认启用 🚨

**文件**: `pingclair-api/src/server.rs:52-113`(`handle_request`)

**问题**: 配置里有 `AdminConfig.api_key`(`pingclair-core/src/config/types.rs:507`),
`ApiKeyAuth` 结构也写好了(`pingclair-api/src/auth.rs`,还标着 `#![allow(dead_code)]`),
但 `handle_request` **从未调用它**。`/config` GET/POST(热重载)和 `/metrics`
零认证暴露,且 `enabled` 默认为 `true`(`types.rs:511`)。任何能访问 admin
端口的人都可以读取并改写运行时配置。

**修复方案**:
- `handle_request` 入口统一校验 `Authorization: Bearer <api_key>`
- 未配置 `api_key` 时默认只绑 `127.0.0.1`,并在启动日志里大字警告
- 移除 `#![allow(dead_code)]`

**预计耗时**: 2 小时

- [ ] 修复

---

### 2. auth_basic 是坏的 — 比没有更糟 🚨

**文件**: `pingclair-core/src/server/handlers.rs:177-192`(`BasicAuth` handler)

**问题**: handler 拿到 `credentials` 后直接忽略(`credentials: _`),
**无条件返回 401** + `WWW-Authenticate`。配了 Basic Auth 的站点会把
**所有人**(包括合法用户)挡在门外。整个代码库里没有任何地方校验
`Authorization` 头。

**修复方案**: 解析 `Authorization: Basic <base64>`,与配置的 credentials
比对(常量时间比较);不匹配才 401。补单元测试(正确密码放行 / 错误密码 401 /
缺 header 401)。

**预计耗时**: 半天

- [ ] 修复

---

### 3. ACME 每次签发都注册新账户

**文件**: `pingclair-tls/src/acme.rs:350-371`(`ensure_account`)

**问题**: ACME 账户私钥不持久化,每次签发都 `create` 一个新账户。
会撞 Let's Encrypt 的注册频率限制(每 IP 3 小时 10 个账户),多域名 +
频繁重启的场景下签发会直接失败。已签发的证书有持久化(`cert_store.rs`),
唯独账户没有。

**修复方案**: 账户私钥(pem/jwk)落盘到 TLS store 目录,启动时优先加载;
同时记录 account URL 供后续复用。

**预计耗时**: 半天

- [ ] 修复

---

## 🟡 Nginx 功能差距(P1,替代 90% 场景需要)

| 功能 | 现状 | 证据 | 预计耗时 |
|------|------|------|----------|
| SSE / 流式反代 | ❌ `flush_interval` 只解析不生效 | DSL→`types.rs:445` 有管道,但 `pingclair-proxy` 里零读取;反代 LLM/SSE 场景不可用 | 半天 |
| `error_page` | ❌ 零实现 | 全库无 `error_page` 匹配;502/404 只能出默认页 | 半天 |
| LB weight / backup | ❌ 所有后端一视同仁 | `load_balancer.rs:194`;被动健康检查(`max_fails`/`fail_timeout`)已有(`load_balancer.rs:53-104`) | 1 天 |
| 反代 Brotli | ❌ gzip only | `server.rs:1419`(flate2 `GzEncoder`);静态路径已有 br/zstd | 半天 |
| 正则 rewrite | ❌ 正则**匹配**已有,正则**改写**没有 | `router.rs:15-53`(Regex matcher,预编译缓存)vs `handlers.rs:170-171` | 半天 |
| RequestContext 轻量化 | 🟡 未做但影响小 | `server.rs:31-93` 每请求 3 个 `HashMap::new()`;空 HashMap 不分配堆内存,仅插入时才分配 | 2 小时 |

## 🟢 P2 — 进阶 / 可观测性

| 功能 | 现状 | 说明 |
|------|------|------|
| `proxy_cache` | ❌ | HTTP 响应缓存层,大功能(1 周+) |
| 访问日志格式 | ❌ 固定 tracing JSON | `server.rs:1509` 自述 "we use tracing for now";`LogConfig` 是摆设 |
| Prometheus 指标 | 🟡 仅 3 个 series | `pingclair-proxy/src/metrics.rs:16-40`:requests_total / duration / active_connections |
| 插件系统 | ❌ stub | `pingclair-plugin/src/loader.rs:10-13` 是 `// TODO`,`main.rs` 未接线;README 不应再当卖点 |
| QUIC 事件循环 | 🟡 单 task/端口 | `pingclair-proxy/src/quic.rs` 简单模型,高并发 H3 下可能是瓶颈,**未压测过** |
| 健康检查 Host 头 | ❌ | `health_check.rs:106` TODO:虚拟主机场景需要自定义 Host |
| gzip_types 可配置 | ❌ 硬编码 | 低优先 |

---

## ✅ 已修复确认(2026-07-25 代码核实)

上次审计 P0 四项 + 后续发现的问题,均已修复:

- ✅ **Gzip 全量缓冲 OOM** — `server.rs:1431-1452` 流式压缩,逐 chunk sync-flush,
  内存以单个 chunk 为界;<256B 小 body 跳过(`server.rs:1415`)
- ✅ **`hosts` RwLock 竞争** — 已换 `ArcSwap<HashMap>`(`server.rs:337-348`),热路径无锁
- ✅ **upstream 连接池上限** — `global.upstream_keepalive_pool_size`(`types.rs:48`),
  `main.rs:540-543` 应用并在启动时打日志(`main.rs:556-562`)
- ✅ **静态压缩缓存惊群** — per-key `tokio::sync::Mutex` single-flight 去重
  (`file_server.rs:122-129, 555-609`),有并发冷缓存测试覆盖
- ✅ **静态热路径 tokio::fs** — 已全改同步 `std::fs`(2.6x 吞吐,见 `benchmarks/README.md` #22/#23)
- ✅ **worker_threads 默认 1** — 改 `available_parallelism()`,可配置,启动打日志
- ✅ **正则 location 匹配** — `router.rs` Regex matcher,预编译缓存
- ✅ **DSL http3 开关** — `compiler.rs:180-182` + Caddyfile adapter 支持
- ✅ **优雅重载** — SIGHUP(`main.rs:839-918`)+ admin API 双通道;SIGTERM 优雅关闭
- ✅ **静态 Brotli/Zstd** — 预压缩 `.br`/`.gz`/`.zst` + 实时压缩(`file_server.rs:714-766`)
- ✅ **具名 server 块绑定** — `bench.local:8080` 绑 `0.0.0.0` 按 Host 路由(benchmarks #14)
- ✅ **HTTP/3** — quiche 0.29 重写上线,九项 VPS 冒烟测试全过

---

## 🧠 Pingora 已经帮我们做好的事(不需要自己实现)

- ✅ HTTP keep-alive 连接复用(上下游)
- ✅ Chunked Transfer-Encoding / 100-continue
- ✅ WebSocket 升级透传
- ✅ HTTP/2 多路复用(上游自动)
- ✅ 连接池(内置 upstream 复用)
- ✅ Backpressure(流式 body,除了我们自己的 gzip 已修)
- ✅ Graceful shutdown(SIGTERM 等待在途请求)
- ✅ Worker 线程模型(多线程 epoll/kqueue)

---

## 🎯 建议的压测策略

```bash
# 第一步:不开 gzip,纯代理性能
wrk -t4 -c100 -d30s http://localhost:8080/api/test

# 第二步:开 gzip,检测内存
wrk -t4 -c100 -d30s -H "Accept-Encoding: gzip" http://localhost:8080/api/test
watch -n1 "ps aux | grep pingclair"

# 第三步:长连接 + 高并发
wrk -t8 -c1000 -d60s --latency http://localhost:8080/

# 第四步:大 body(流式验证)
curl -s http://localhost:8080/large-file.json -H "Accept-Encoding: gzip" > /dev/null

# 第五步:H3 压测(QUIC 单 task 模型未压过,重点观察)
```

最新实测数据见 `benchmarks/README.md`(VPS 2 vCPU:静态 50k rps ≈ nginx 94%,
gzip 反超 nginx,反代 20.1k vs nginx 22.0k,20MB 流式 RSS 17.7MiB)。

---

## 📊 预估时间线

| 阶段 | 内容 | 耗时 |
|------|------|------|
| **阶段 1** | 🔴 3 个 Blocker(admin auth / auth_basic / ACME 账户持久化) | ~1.5 天 |
| **阶段 2** | 🟡 P1 功能(SSE / error_page / LB weight / 反代 br / 正则 rewrite) | ~3 天 |
| **阶段 3** | 🟢 P2 进阶(proxy_cache / 日志格式 / 指标 / 插件 / H3 压测优化) | 按周计 |

**结论**: 内核(性能、流式、热重载、H3)已到生产水位;差的是 3 个安全/正确性
口子(约 1.5 天)和一批 nginx  parity 功能。堵完 Blocker 即可小规模试生产。
