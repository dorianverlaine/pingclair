# 🧪 Pingclair vs Nginx 生产替代性审计

> **审计时间**: 2026-04-20
> **审计范围**: 压测稳定性 + Nginx 功能覆盖度
> **当前版本**: v0.1.6

---

## 🔴 压测会翻车的问题（P0 — 先修这些再压）

### 1. Gzip 压缩全量缓冲 — 🚨 OOM 风险

**文件**: `pingclair-proxy/src/server.rs` (`upstream_response_body_filter`)

**问题**: `upstream_response_body_filter` 把所有 body chunk 写入 `GzEncoder<Vec<u8>>`，
在 `end_of_stream` 一次性 flush。如果上游返回 100MB 大文件 + `Content-Type: text/plain`，
整个响应被缓存在内存。

**修复方案**:
- 增加 **最大压缩体积限制** (e.g. 10MB)，超过阈值直接 pass-through
- 或实现 **真正的流式压缩** — 每个 chunk 独立 flush 出去

**预计耗时**: 1-2 小时

- [ ] 修复

---

### 2. RequestContext 分配开销

**文件**: `pingclair-proxy/src/server.rs` (`RequestContext::default()`)

**问题**: 每个请求创建 5 个 `HashMap::new()` + 1 个 `Vec::new()` + 2 个 `String::new()`
+ 1 个 `generate_request_id()` (涉及 syscall `SystemTime::now()`)。
在 10k QPS 下每秒 5 万次堆分配。

**修复方案**:
- 使用 `SmallVec<[(String, String); 4]>` 代替 HashMap（大多数请求 header 数量 < 4）
- 用 `AtomicU64` 计数器代替 `SystemTime` 生成 request ID
- 或者用对象池回收 `RequestContext`

**预计耗时**: 2-3 小时

- [ ] 修复

---

### 3. `hosts` RwLock 竞争

**文件**: `pingclair-proxy/src/server.rs` (`PingclairProxy.hosts`)

**问题**: `get_state(host)` 在每个请求的热路径上 `.read()` 这个 `RwLock<HashMap>`。
虽然 `parking_lot::RwLock` 性能不错，但高并发下仍是共享状态。

**修复方案**: 采用 `ArcSwap<HashMap>` 或 `crossbeam-epoch` 做无锁读。
写操作（热更新）频率极低，可以接受 Copy-on-Write。

**预计耗时**: 1 小时

- [ ] 修复

---

### 4. 无 upstream 连接池上限

**问题**: Pingora 默认连接池无上限。如果 upstream 慢（300ms），10k QPS 意味着
3000 个并发连接到后端。后端可能被打满。

**修复方案**: 在 `HttpPeer` 设置 `max_keepalive_connections` 和 `connection_timeout`
(已部分实现，需确认 Pingora level 的 pool size 配置)

**预计耗时**: 30 分钟

- [ ] 修复

---

## 🟡 Nginx 常用功能差距

### 功能对照表

| Nginx 功能 | Pingclair | 差距 | 优先级 |
|------------|-----------|------|--------|
| `proxy_pass` | ✅ `ReverseProxy` | 完整 | — |
| `upstream { }` 组 + weight | 🟡 有 LB 但无 weight | 缺 weight/backup | P1 |
| `location /path { }` | ✅ path matcher | 完整 | — |
| `location ~ regex { }` | 🟡 `Matcher::Path` 只有 glob | 缺正则 | P1 |
| `proxy_set_header` | ✅ `header_up` | 完整 | — |
| `add_header` / `more_set_headers` | ✅ `Headers` handler | 完整 | — |
| `gzip on` | ✅ 已实现 | 完整（需 OOM 修复） | — |
| `gzip_types` | ✅ 硬编码常见类型 | 可配置化 | P2 |
| `try_files` | ✅ 已实现 | 完整 | — |
| `error_page 404 /404.html` | ❌ | 缺 | P1 |
| `return 301 https://...` | ✅ `Redirect` | 完整 | — |
| `rewrite ^(.*)$ /index.html break` | 🟡 有 Rewrite 但无 regex | 缺正则 | P2 |
| `proxy_read_timeout` | ✅ `read_timeout` | 完整 | — |
| `proxy_connect_timeout` | ✅ `connection_timeout` | 完整 | — |
| `client_max_body_size` | ✅ 已实现 | 完整 | — |
| `keepalive` | ✅ Pingora 内置 | 完整 | — |
| `ssl_certificate` / ACME | ✅ AutoHTTPS + TlsManager | 完整 | — |
| `limit_req` | ✅ RateLimiter | 完整 | — |
| `auth_basic` | 🟡 配置类型有但运行时缺 | 缺 | P1 |
| `proxy_cache` | ❌ | 缺 | P2 |
| `access_log` JSON | ✅ 已实现 | 完整（结构化 tracing） | — |
| `log_format` | 🟡 字段固定 | 可配置化 | P3 |
| WebSocket proxying | 🟢 Pingora 透传 | 基本完整 | — |
| `proxy_buffering off` (SSE/streaming) | 🟡 `flush_interval -1` 已解析 | 运行时未设置 | P1 |
| Graceful shutdown | ✅ Pingora 内置 | 完整 | — |
| Graceful reload (SIGHUP) | ✅ 已实现 | 完整 | — |
| IP whitelist / deny | ✅ ConnectionFilter | 完整 | — |

---

## 📋 按优先级排列的 TODO

### 🔴 P0 — 压测前必须修复（~4h）

- [ ] **Gzip 最大体积限制** — 超过 10MB 直接 pass-through，避免 OOM
- [ ] **upstream 连接池上限** — 设置 `pool_size` 防止打满后端
- [ ] **`hosts` RwLock → ArcSwap** — 消除热路径上的锁竞争
- [ ] **RequestContext 轻量化** — SmallVec 代替 HashMap

### 🟡 P1 — Nginx 功能追平（~8h）

- [ ] **`error_page`** — 自定义错误页面（404/500/502/504）
- [ ] **`auth_basic`** — Basic Auth 运行时校验（header 解析 + bcrypt 比对）
- [ ] **`flush_interval -1` 运行时** — 禁用 response buffering 支持 SSE/EventStream
- [ ] **`location ~ regex`** — 路径匹配支持正则表达式
- [ ] **`upstream weight/backup`** — 加权负载均衡 + 备用后端

### 🟢 P2 — 进阶功能（~12h）

- [ ] **`proxy_cache`** — HTTP 缓存层（ETag/Last-Modified/Cache-Control）
- [ ] **`rewrite` 正则支持** — `regex` crate 集成
- [ ] **Brotli 压缩** — 除 gzip 外支持 br
- [ ] **`gzip_types` 可配置** — 通过配置控制可压缩的 MIME 类型
- [ ] **请求/响应 body size 限制** — 流式检查不缓存

---

## 🧠 Pingora 已经帮我们做好的事（不需要自己实现）

- ✅ **HTTP keep-alive 连接复用** — 上下游都自动管理
- ✅ **Chunked Transfer-Encoding** — 自动处理
- ✅ **100-continue** — 自动处理
- ✅ **WebSocket 升级** — Pingora 透传 Connection: Upgrade + Upgrade: websocket
- ✅ **HTTP/2 多路复用** — 上游自动支持
- ✅ **连接池** — 内置 upstream 连接复用
- ✅ **Backpressure** — 流式 body 传输不会无限缓冲（除了我们自己的 gzip）
- ✅ **Graceful shutdown** — SIGTERM 时等待在途请求完成
- ✅ **Worker 线程模型** — 多线程 epoll/kqueue

---

## 🎯 建议的压测策略

```bash
# 第一步：不开 gzip，纯代理性能
wrk -t4 -c100 -d30s http://localhost:8080/api/test

# 第二步：开 gzip，检测内存
wrk -t4 -c100 -d30s -H "Accept-Encoding: gzip" http://localhost:8080/api/test
watch -n1 "ps aux | grep pingclair"

# 第三步：长连接 + 高并发
wrk -t8 -c1000 -d60s --latency http://localhost:8080/

# 第四步：大 body（OOM 测试）
curl -s http://localhost:8080/large-file.json -H "Accept-Encoding: gzip" > /dev/null
```

---

## 📊 预估时间线

| 阶段 | 内容 | 耗时 |
|------|------|------|
| **阶段 1** | P0 性能修复（可以安心压测） | 4h |
| **阶段 2** | P1 功能追平（可以替代 90% 的 Nginx 场景） | 8h |
| **阶段 3** | P2 进阶功能（可以替代 99% 的 Nginx 场景） | 12h |
| **总计** | | **~24h 工作量** |
