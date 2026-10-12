# Pingclair 官方网站

[English](README.md) · [Français](README.fr.md) · **简体中文** · [繁體中文](README.zh-TW.md)

## 概述

官方网站：[https://pingclair.com](https://pingclair.com)

网站源代码位于独立的仓库
**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**。
本目录保留生产环境的配置文件 [`Pingclairfile`](Pingclairfile)，以及让网站文件保持
最新的脚本 [`sync-docs.sh`](sync-docs.sh)，作为使用 Pingclair 部署静态文档网站的实际示例：

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
handle /install.sh {
    import installer
}
…
handle {
    import edge_headers
    file_server {
        negotiate markdown
    }
}
```

`handle` 块彼此互斥：第一个匹配的负责响应。它们按路径的明确程度排序，因此精确路径与
前缀（安装脚本、代理端点、构建产物、搜索索引、Markdown 文件与 `/.well-known` 文档）排在
前面，没有条件的块排在最后。这些路径彼此没有重叠，所以这个顺序正是网站所需的顺序。

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
handle {
    import edge_headers
    file_server {
        negotiate markdown
    }
}
```

偏好 Markdown 的客户端，会在同一个 URL 上获得页面的 Markdown 版本。以 `/start/install/`
为例，响应的是构建生成的 `start/install.md`；目录中有 `index.md` 时（例如首页）则使用
它。部署时不再复制任何文件。没有 Markdown 版本的页面和静态资源照常提供。

偏好按 `Accept` 的质量值判断（RFC 9110）：

| `Accept` | 响应 |
| --- | --- |
| `text/markdown` | Markdown |
| `text/markdown, text/html`（编程代理发送的） | Markdown：客户端明确写出了它 |
| 浏览器的 `text/html,…,*/*;q=0.8` | HTML |
| `text/markdown;q=0, */*` | HTML：Markdown 被拒绝 |

每个页面响应都带 `Vary: Accept`，缓存会把两种版本分开存放。

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

## 让网站保持最新

服务器本身从不构建网站：Astro 构建的内存峰值接近 800 MB，而服务器的内存不到
1 GiB。网站仓库的 CI 会构建每一次推送到 `main` 的内容，把结果发布到固定的
`site-latest` release，内容是 `site.tar.gz`，以及记录 commit 与压缩包 sha256 的
`site.json`。

[`sync-docs.sh`](sync-docs.sh) 由 cron 每五分钟运行一次。`site.json` 中的 commit
与服务器正在提供的不同时，它会下载压缩包、检查 sha256 与几个关键页面，解压到
`/usr/local/www/pingclair-site/<commit>`，再把新的 symlink 重命名覆盖
`/usr/local/www/pingclair.pingclair.com`，也就是 Pingclairfile 提供的根目录。重命名是
原子操作，因此请求不会看到两个版本各一半的内容，Pingclair 也不需要重载。切换后如果
网站没有正常响应，链接会改回上一个版本。磁盘上保留最新的三个版本。

安装步骤（只需一次，以 root 运行）：

```sh
install -m 755 sync-docs.sh /usr/local/sbin/pingclair-site-sync
mkdir -p /usr/local/www/pingclair-site
mv /usr/local/www/pingclair.pingclair.com /usr/local/www/pingclair-site/initial
ln -s /usr/local/www/pingclair-site/initial /usr/local/www/pingclair.pingclair.com
echo '*/5 * * * * root /usr/local/sbin/pingclair-site-sync' > /etc/cron.d/pingclair-site-sync
```

每次切换都会以 `pingclair-site-sync` 为标签记录到 syslog。

## 参考资源

- **[官方文档](https://pingclair.com)**：配置参考与部署指南。
- **`pingclair validate`**：检查配置文件，并标出错误所在位置。
- **`pingclair fmt`**：格式化 Pingclairfile，保留注释。
- **[网站源代码](https://github.com/dorianverlaine/pingclair-docs)**：网站本身的仓库。
