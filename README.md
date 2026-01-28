<div align="center">

# 🦀 Pingclair

**基于 Pingora 构建的现代高性能 Web 服务器与反向代理**  
*融合了 Cloudflare Pingora 的极致性能与 Caddy 的极简开发体验*

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.85%2B-orange.svg)](https://www.rust-lang.org/)
[![Status](https://img.shields.io/badge/status-active-green.svg)]()
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

</div>

---

## 📖 项目简介

**Pingclair** 是一个下一代 Web 服务器和反向代理工具。它的核心理念是将 **Cloudflare Pingora**（处理过万亿级请求的 Rust 代理框架）的强大能力，封装在一个类似于 **Caddy** 的易用外壳之下。

传统的 Nginx 配置往往晦涩难懂，而 Caddy 虽然易用但通常基于 Go。Pingclair 旨在填补这一空白：提供一个 **100% Rust 编写**、**内存安全**、**高性能** 且 **配置直观** 的解决方案。

无论你是需要一个简单的静态文件服务器，还是一个支持复杂负载均衡、自动 HTTPS 和 HTTP/3 的企业级网关，Pingclair 都能胜任。

## ✨ 核心特性

*   🚀 **基于 Pingora 内核**: 站在巨人的肩膀上，利用 Cloudflare 经过实战检验的基础设施，提供企业级的稳定性和吞吐量。
*   🔒 **内存安全**: 得益于 Rust 语言特性，彻底杜绝缓冲区溢出等常见的内存安全漏洞。
*   📝 **Caddyfile 兼容配置**: 极简的配置 DSL。支持**自动 HTTPS**、**多监听器**和**命名匹配器**，兼容主流 Caddyfile 语法。
*   ⚡ **HTTP/3 (QUIC) 原生支持**: 拥抱未来网络协议，在不稳定的网络环境下提供更低的延迟和更好的连接迁移能力。
*   🔄 **智能负载均衡**: 内置多种算法（轮询、最少连接等），支持健康检查和故障自动转移。
*   🔐 **全自动 HTTPS**: 集成 ACME 协议（如 Let's Encrypt），自动申请和续期 SSL/TLS 证书，零配置开启加密传输。
*   📁 **高性能静态文件服务**: 支持 Gzip/Brotli 压缩、Range 请求和高效的文件传输。
*   🔌 **模块化插件系统**: (开发中) 允许通过 Rust trait 扩展自定义功能，无需修改核心代码。
*   📊 **可观测性**: 开箱即用的 Prometheus 指标导出和 OpenTelemetry Tracing 支持。

## ⚡ 性能基准测试

我们在 Docker Bridge 内网（消除系统网络栈开销）对 Pingclair、Nginx 和 Caddy 进行了公平的压力测试。

**测试环境**:
*   硬件: MacBook Pro (M2 Chip), Docker Desktop
*   配置: 1KB 静态文件, 4 Threads, 100 Connections, 15s Duration
*   网络: Docker 容器直连 (Container-to-Container)

| 服务器 | RPS (请求/秒) | 平均延迟 | 备注 |
|--------|---------------|----------|------|
| **Nginx (Alpine)** | **~24,902** | **4.17ms** | ⭐️ 行业标杆，极致的 C/Epoll 优化 |
| **Pingclair (Debian)** | **~19,899** | **5.44ms** | 🚀 紧随其后，达到 Nginx 的 ~80% 性能 |
| **Caddy (Alpine)** | **~6,803** | **14.86ms** | 🐢 易用性优先，受限于 Go GC 开销 |

> **分析**:
> 虽然 Pingclair 是一个相对年轻的 Rust 项目，但得益于 Cloudflare Pingora 坚实的内核，即便在未经特定优化的 Docker 环境下，其性能也达到了成熟竞品 Nginx 的 80%，并达到了同类易用型服务器 Caddy 的 **3倍**。
> 
> *注意：基准测试仅供参考，实际生产环境性能取决于具体业务逻辑。*

## 📦 安装指南

### 前置要求

*   **Rust 工具链**: 需要安装 Rust 1.85 或更高版本。

### 源码编译安装

推荐从源码编译以获得针对你本机 CPU 优化的二进制文件：

```bash
# 1. 克隆仓库
git clone https://github.com/SinclairChao/pingclair.git
cd pingclair

# 2. 编译并安装 (release 模式)
cargo install --path ./pingclair
```

安装完成后，`pingclair` 命令将被添加到你的系统 PATH 中。

### Ubuntu/Debian 极简安装 (推荐)

如果你在 Ubuntu 或 Debian 系统上，可以使用一键安装脚本。该脚本会自动下载（或编译）二进制文件，配置 `systemd` 服务，并创建 `pingclair` 低权限用户（使用 `setcap` 绑定端口）。

```bash
# 运行安装脚本 (需要 sudo 权限)
curl -fsSL https://raw.githubusercontent.com/SinclairChao/pingclair/main/scripts/install.sh | sudo bash
```

安装完成后，你可以使用 `pc` (pingclair 的缩写) 命令来管理服务。

## 🏃 快速上手

Pingclair 提供了两种运行模式：**CLI 命令行模式**（适用于快速测试）和 **配置文件模式**（适用于生产环境）。

### 1. 命令行模式 (CLI)

**启动静态文件服务器**  
将当前目录下的文件通过 HTTP 8080 端口对外提供服务：
```bash
pingclair file-server --listen :8080 --root .
```

**启动反向代理**  
将本地 8080 端口的流量转发到后端的 3000 端口：
```bash
pingclair reverse-proxy --from :8080 --to localhost:3000
```

**管理系统服务 (Linux)**
安装后可以使用内置命令管理 `systemd` 服务：
```bash
pc service start    # 启动
pc service stop     # 停止
pc service status   # 状态查询
pc service reload   # 平滑重载配置 (SIGHUP)
pc service restart  # 重启
```

### 2. 配置文件模式 (推荐)

在项目根目录下创建一个名为 `Pingclairfile` 的文件，然后运行：

```bash
pingclair run Pingclairfile
```

## 🛠️ 配置详解 (Pingclairfile)

Pingclairfile 是一种结构化的配置语言。它看起来很像 Rust 代码，但专门用于描述服务器行为。

### 基础结构

一个最简单的配置包含一个或多个站点块：

```caddyfile
# 定义一个监听 localhost 的服务器
localhost:8080 {
    # 静态文件服务
    file_server ./public
}
```

### 路由与匹配 (Routing & Matching)

Pingclair 提供了强大的路由匹配能力。你可以根据路径、域名、Header 等条件分流请求。

```caddyfile
example.com {
    # 1. 使用命名匹配器匹配 API 路径
    @api {
        path /api/v1/*
    }
    
    # 针对 API 请求的逻辑
    handle @api {
        header {
            set Content-Type "application/json"
        }
        reverse_proxy localhost:3000
    }

    # 2. 匹配静态资源
    handle /assets/* {
        header {
            set Cache-Control "public, max-age=86400"
        }
        file_server ./assets
    }

    # 3. 默认回退（Fallback）
    handle {
        respond "Page Not Found" 404
    }
}
```

### 高级特性：宏 (Macros)

这是 Pingclair 最强大的特性之一。你可以定义“宏”来封装重复的配置片段，并在多个服务器或路由中复用，保持配置文件的整洁（DRY 原则）。

```rust
// 定义一个名为 security 的宏，用于添加安全头
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

// 定义通用的日志配置宏
macro standard_log!(path) {
    log {
        output: File(path);
        format: Json;
        level: Info;
    }
}

server "blog.example.com" {
    listen: "0.0.0.0:443";
    
    // 使用宏
    use security_headers!();
    use standard_log!("/var/log/pingclair/blog.log");

    route {
        _ => { file_server "./blog"; }
    }
}

server "shop.example.com" {
    listen: "0.0.0.0:443";
    
    // 复用相同的安全配置
    use security_headers!();
    use standard_log!("/var/log/pingclair/shop.log");

    route {
        _ => { proxy "http://shop-backend:8000"; }
    }
}
```

### 反向代理与负载均衡

```caddyfile
:80 :8080 {
    # 反向代理到多个后端
    reverse_proxy 10.0.0.1:8080 10.0.0.2:8080 {
        # 负载均衡策略: round_robin, random, least_conn
        lb_policy least_conn
        
        # 失败重试
        failover true
    }
}
```

## 🏗️ 架构概览

Pingclair 采用模块化的 Workspace 结构管理代码：

| Crate (模块) | 描述 |
|--------------|------|
| **`pingclair`** | **CLI 入口**。负责解析命令行参数，初始化日志，引导系统启动。 |
| **`pingclair-core`** | **核心运行时**。定义了核心的数据结构、Trait 和服务器生命周期管理。 |
| **`pingclair-config`** | **配置编译器**。负责解析 `Pingclairfile`，进行词法分析、语法分析和语义检查，生成运行时配置对象。 |
| **`pingclair-proxy`** | **代理实现**。基于 Pingora Proxy Trait 实现的 HTTP/TCP 代理逻辑，包含负载均衡器。 |
| **`pingclair-static`** | **静态文件服务**。实现了高效的文件读取、MIME 类型推断和流式传输。 |
| **`pingclair-tls`** | **TLS 管理**。处理证书加载、ACME 自动申请（Let's Encrypt）以及 QUIC 握手逻辑。 |
| **`pingclair-api`** | **Admin API**。提供 RESTful 接口，允许在运行时动态查看状态或热更新配置。 |
| **`pingclair-plugin`** | **插件系统**。定义了插件接口，允许第三方开发者扩展功能。 |

## 🤝 参与贡献

我们非常欢迎社区的贡献！无论你是想修复一个 Bug，增加一个新特性，还是仅仅改进文档。

### 开发流程

1.  **Fork** 本仓库。
2.  **创建分支**: `git checkout -b feature/my-cool-feature`
3.  **提交代码**: 遵循 Rust 代码风格。
4.  **运行测试**: 确保所有测试通过。
    ```bash
    cargo test --workspace
    ```
5.  **提交 PR**: 在 Pull Request 中描述你的改动。

## 📄 许可证

本项目采用 **Apache 2.0 许可证** 开源。详情请见 [LICENSE](LICENSE) 文件。

---

<div align="center">
  <sub>由 Pingclair 贡献者团队用 ❤️ 和 Rust 打造</sub>
</div>