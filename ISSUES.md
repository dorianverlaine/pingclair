# 🛠️ Pingclair Issues & Roadmap (Master List)

This document tracks historical bugs, deployment friction, and a comprehensive roadmap for the evolution of Pingclair.

## 🚨 紧急修复与核心限制 (Urgent Fixes & Critical Limits)

- [x] **Single Listener Limitation**: `main.rs` used to read only the `.first()` address.
    - *Fixed in v0.1.6*: Now iterates over all listen entries.
- [x] **Strict Host Matching**: Port-only addresses failed host validation.
    - *Fixed in v0.1.6*: Automatically defaults to `_` for port-only blocks.
- [ ] **证书缓存优化**: 避免在每次 TLS 握手时重复解析证书（已在代码中标识为 TODO）。
- [ ] **持持久化 ACME 挑战处理器**: 确保服务重启后挑战令牌不丢失。
- [ ] **安全增强**: 添加更全面的安全头部配置，默认启用重要的安全防护机制。
- [ ] **Diagnostic Opacity**: `INFO` logs are too quiet about internal binding state.
    - *Todo*: Log exact bind addresses and resolved site names during bootstrap.

## ⚙️ 功能完善任务 (Feature Parity & Extensions)

- [x] **Caddyfile Syntax Overhaul (v0.1.6)**:
    - [x] Support directives without colons/semicolons.
    - [x] Support matcher syntax `@name { ... }`.
    - [x] Implement environment variable expansion `{$VAR}`.
- [ ] **扩展指令兼容形**: 实现更多原生 Caddy 指令（如 `rewrite`、`uri`、模板等）。
- [ ] **认证模块**: 实现 HTTP Basic Auth 和其他身份验证模块。
- [ ] **宏支持 (Macros)**: 完成宏定义和调用功能（当前标记为 TODO）。
- [ ] **高级匹配**: 增加请求体匹配、IP 地址范围匹配等。
- [ ] **Directive Parity Nuances**: Ensure arguments like compression algorithms are case-insensitive.

## 🚀 性能与可靠性 (Performance & Reliability)

- [ ] **负载均衡算法**: 实现加权轮询和一致性哈希等高级算法。
- [ ] **内存管理**: 优化大型路由表的内存使用效率。
- [ ] **上游连接管理**: 改进上游服务器的连接池管理策略。
- [ ] **响应缓存 (Caching)**: 增加响应缓存功能以提升性能。
- [ ] **熔断机制**: 实现上游服务熔断保护机制。
- [ ] **优雅关闭 (Graceful Shutdown)**: 完善服务关闭时的连接处理流程。
- [ ] **多协议支持**: 增加对 WebSocket 和 gRPC 的原生代理支持。
- [ ] **io_uring (Linux)**: 下沉事件驱动到 io_uring 提升吞吐。

## 📊 监控及运维 (Monitoring & Ops)

- [ ] **指标扩展 (Metrics)**: 增加更多运行时指标，对接 Prometheus。
- [ ] **日志系统**: 改进日志格式，增加结构化 (JSON) 日志输出。
- [ ] **告警集成**: 集成常见的告警和通知机制。
- [ ] **诊断工具**: 提供在线诊断和调试接口 (Admin UI/CLI)。
- [ ] **SIGHUP Reload Feedback**: 提供配置测试命令 (`pingclair validate`)，避免重载坏配置。

## 🐳 部署与分发 (Deployment & Distribution)

- [x] **Docker GLIBC Mismatch**: Fixed by switching to `debian:sid`.
- [ ] **CLI Ergonomics**: Support `--config` flag alongside positional argument.
- [ ] **Cross-Compilation (deploy.sh)**: Automate builds for different target architectures.
- [ ] **官方 Docker 镜像**: 提供官方多平台镜像支持。
- [ ] **迁移工具**: 提供从 Caddy 配置自动迁移的工具。

## 🧪 文档与测试 (Docs & Testing)

- [ ] **用户/开发者文档**: 编写完整的配置参考、开发者指南和贡献说明。
- [ ] **API 文档**: 补充代码中的 RustDoc 注释。
- [ ] **测试覆盖率**: 增加核心模块单元测试，编写端到端集成测试，建立性能基准。
- [ ] **代码审查与分析**: 引入更多静态分析工具，定期更新依赖修复漏洞。

