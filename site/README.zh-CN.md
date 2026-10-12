# Pingclair 官方网站

[English](README.md) · [Français](README.fr.md) · **简体中文** · [繁體中文](README.zh-TW.md)

## 概述

官方网站：[https://pingclair.com](https://pingclair.com)

网站源代码位于独立的仓库
**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**。
本目录只保留生产环境的配置文件 [`Pingclairfile`](Pingclairfile)，作为使用 Pingclair
部署静态文档网站的实际示例：

- 自动 TLS 证书与 HTTP/3
- 基于主机名的三个虚拟主机
- 静态文件、自定义 404 页面与压缩
- 反向代理与响应缓存
- 在同一个 URL 上为 AI 代理提供 Markdown
- 永久重定向到规范域名
- JSON 访问日志与内置轮转

网站运行在一台 FreeBSD 服务器上。`pingclair.pingclair.com` 保留为测试用主机名，
`www.pingclair.com` 则永久重定向到主域名。配置文件是 Pingclairfile，即 Caddyfile
语法；以下摘录均取自该文件。

## 配置逐段说明

### 1. 全局选项

```caddyfile
{
    email team@pingclair.com
    storage file_system /var/db/pingclair
    admin 127.0.0.1:2019
}
```

`email` 是自动证书的 ACME 账户联系邮箱。`storage` 指定存放证书、账户密钥及相关状态的
目录。`admin` 仅在 loopback 上开放 Admin API，因此 `pingclair reload` 可以在不中断
连接的情况下应用修改后的配置文件。

### 2. 用 snippet 收纳重复的部分

重复出现的配置只定义一次，写成 snippet 后再 import：

| Snippet | 内容 |
| --- | --- |
| `(edge_headers)` | 安全相关的 header，以及 Cloudflare 部署时在 `_headers` 文件中声明、供代理程序发现的 `Link` header |
| `(installer)` | 从发布存储空间提供 `install.sh` 的代理 |
| `(worker)` | `/mcp` 与 `/a2a` 代理端点的代理 |
| `(access_log)` | 所有站点共用的访问日志 |
| `(docs)` | 整个文档网站，主域名与测试主机共用 |

### 3. 虚拟主机

```caddyfile
pingclair.com {
    import docs
}

pingclair.pingclair.com {
    import docs
}

www.pingclair.com {
    import access_log
    redir https://pingclair.com{uri} 308
}
```

带有主机名的站点地址会自动获得：443 端口的 HTTPS、UDP 443 端口的 HTTP/3，以及一个
80 端口的监听，负责重定向到 HTTPS 并响应 ACME 验证。

| 主机名 | 用途 |
| --- | --- |
| `pingclair.com` | 官方网站与代理端点 |
| `pingclair.pingclair.com` | 测试环境，提供同一个网站 |
| `www.pingclair.com` | 永久重定向到主域名 |

### 4. 路由顺序

```caddyfile
route {
    handle /install.sh {
        import installer
    }
    …
    handle {
        import edge_headers
        file_server
    }
}
```

在 `route` 中，各块按书写顺序执行，第一个匹配的 `handle` 负责响应。网站的顺序是：

1. 安装脚本：`/install.sh` 与 `/install`；
2. 代理端点：`/mcp` 与 `/a2a`；
3. 构建产物、搜索索引、Markdown 文件与 `/.well-known` 发现文档的边缘规则；
4. 向请求 Markdown 的客户端提供 Markdown；
5. 其余一律从磁盘提供。

### 5. 代理安装脚本并缓存

```caddyfile
(installer) {
    rewrite * /pingclair/install.sh
    reverse_proxy releases.pingclair.com:443 {
        header_up Host releases.pingclair.com
        header_down ?X-Installer-Source r2
        transport http {
            tls
            tls_server_name releases.pingclair.com
        }
        cache {
            ttl 5m
            max_size 16777216
        }
    }
}
```

网站本身不保存安装脚本的副本；每次发布都会把它上传到发布存储空间，网站再代理过去。
请求路径会被改写为存储空间中的路径，上游的 `Host` 与 TLS 服务器名称都显式指定，响应
缓存五分钟、上限 16 MiB，上游未设置时会补上 `X-Installer-Source: r2`。

显式指定 `Host` 在这里很重要：如果上游请求保留了 `pingclair.com`，Cloudflare 可能把它
路由回这台服务器，形成循环。

`/mcp` 与 `/a2a` 仍由 Cloudflare Worker 提供；`(worker)` snippet 以同样的方式代理它们，
但不缓存，因此网站迁移时这两个 URL 都无需更改。

### 6. 边缘规则

```caddyfile
handle /_astro/* {
    import edge_headers
    header Cache-Control "public, max-age=31536000, immutable"
    file_server
}
```

这些规则原本由 Cloudflare 在边缘应用，这里每一条都是一个 `handle` 块：构建产物使用
不可变缓存，搜索索引缓存一小时，直接获取的 Markdown 以 `text/plain` 响应，`/.well-known`
文档允许跨源访问，API 目录使用 RFC 9727 的媒体类型。

### 7. 面向 AI 代理的 Markdown

```caddyfile
@markdown header Accept *text/markdown*
handle @markdown {
    try_files {path}index.md {path}.md
    file_server
}
```

`Accept` header 中包含 `text/markdown` 的客户端，会在同一个 URL 上获得页面的 Markdown
版本：目录中的 `index.md`，或同名的 `<name>.md`。两者都不存在时，请求会以原始路径继续
处理，因此静态资源和没有 Markdown 版本的页面依然可以访问；浏览器得到的仍是 HTML。
`index.md` 副本在部署时生成。

这是基于 header 的判断，而非完整的 HTTP 内容协商。Pingclair 另外提供
`file_server { negotiate markdown }`，它按照 RFC 9110 的质量值判断并设置
`Vary: Accept`，网站之后可能改用它。

背景说明可参考 Cloudflare 的 [Agent Readiness](https://blog.cloudflare.com/agent-readiness/)。

### 8. 404 页面与压缩

```caddyfile
encode zstd gzip

handle_errors 404 {
    rewrite * /404.html
    file_server
}
```

`encode` 向支持的客户端提供 Zstandard 与 gzip。请求不存在的文件时，返回 Starlight
生成的 `404.html`，状态码保持为 404。

### 9. 访问日志

```caddyfile
(access_log) {
    log {
        output file /var/log/pingclair-access.log {
            roll_size 100MiB
            roll_keep 7
        }
        format json
        headers {
            request User-Agent
        }
    }
}
```

每个请求在 `/var/log/pingclair-access.log` 中记录为一行 JSON，并记录请求的
`User-Agent`。Pingclair 自行负责轮转：文件达到 100 MiB 时轮转，保留七个旧文件，并进行压缩。

## 参考资源

- **[官方文档](https://pingclair.com)**：配置参考与部署指南。
- **`pingclair validate`**：检查配置文件，并标出错误所在位置。
- **`pingclair fmt`**：格式化 Pingclairfile，保留注释。
- **[网站源代码](https://github.com/dorianverlaine/pingclair-docs)**：网站本身的仓库。
