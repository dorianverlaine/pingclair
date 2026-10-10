# Pingclair 官方网站

[English](README.md) · [Français](README.fr.md) · **简体中文** · [繁體中文](README.zh-TW.md)

## 概述

Pingclair 官方网站：[https://pingclair.com](https://pingclair.com)

官方网站的源代码已迁移至独立仓库：

**[dorianverlaine/pingclair-docs](https://github.com/dorianverlaine/pingclair-docs)**

迁移完成后，本目录不再维护网站源代码。原有的目录结构及用于保留空目录的 `.gitkeep` 占位文件均已移除。

本目录目前仅保留官方网站的生产环境配置，作为 Pingclair 原生配置语言的实际部署示例。

该配置展示了如何通过单个 `Pingclairfile` 部署静态文档网站，涵盖以下功能：

- 自动 TLS 证书管理及 HTTP/3 支持
- 基于主机名的虚拟主机配置
- 静态文件服务与自定义错误页面
- 上游反向代理及响应缓存
- 面向 AI Agent 的 Markdown 内容协商
- 永久重定向与规范域名管理
- 结构化访问日志及自动轮转

## 生产环境配置

以下为 `pingclair.com` 生产环境使用的 `Pingclairfile`。

网站由部署在巴黎的 FreeBSD 服务器上的 Pingclair 提供服务。`pingclair.pingclair.com` 保留为预发布环境域名，`www.pingclair.com` 则永久重定向至主域名。

配置中的英文注释保留原文，以便与实际部署文件进行对照。

```swift
// 🏝️ pingclair.com — the docs site, served by Pingclair from the
// FreeBSD node, with pingclair.pingclair.com kept as the staging alias and
// www redirected to the apex.

AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")

// 🧊 The one-line install address: `https://pingclair.com/install.sh`.
//
// The script lives in the server repository and is published to the release
// bucket by every release; proxying it here rather than keeping a copy is the
// same choice the Cloudflare Worker made — there is no second file to drift.
let installerHost = "releases.pingclair.com:443"

// 🤖 The agent endpoints still served by the documentation Worker; the
// Paris node proxies them so `pingclair.com/mcp` and `/a2a` keep the URL
// contract the Worker era established.
let cfWorker = "cf.pingclair.com:443"

HTTPListener(on: ":443") {
    Site(host: "pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/install")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 📄 Agents that ask for markdown get the twin on the same URL: the
        // directory's `index.md`, or the sibling `<name>.md`; a miss carries
        // on to the normal file server unchanged. The `index.md` copies are
        // made at deploy time.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback { ServeFiles(root: "/usr/local/www/pingclair.pingclair.com") }
    }
    // 🧾 Starlight ships a 404 page; unknown paths answer with it, the same
    // as the Cloudflare deployment's `not_found_handling`.
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)

    Site(host: "www.pingclair.com") {
        // ➡️ 308 to the apex, the same permanent move the Cloudflare zone
        // answered. The native language has no request-time placeholders yet,
        // so the path does not ride along; a `keepPath:` argument on Redirect
        // is the design idea on file for that.
        Fallback { Redirect(to: "https://pingclair.com", status: .permanentRedirect) }
    }

    Site(host: "pingclair.pingclair.com") {
        Route(when: .path(exact: "/install.sh")) {
            Rewrite(to: "/pingclair/install.sh")
            Proxy(
                to: installerHost,
                headersUp: [.set("Host", "releases.pingclair.com")],
                headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
            )
            .upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
            .cache(ttl: .minutes(5), maxSize: .mebibytes(16))
        }
        Route(when: .path(exact: "/mcp")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        Route(when: .path(exact: "/a2a")) {
            Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
            .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
        }
        // 📄 The same markdown negotiation as the apex site.
        Route(when: .header(name: "Accept", contains: "text/markdown")) {
            TryFiles(candidates: [.requestPath(appending: "index.md"), .requestPath(appending: ".md")], root: "/usr/local/www/pingclair.pingclair.com")
            ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
        }
        Fallback { ServeFiles(root: "/usr/local/www/pingclair.pingclair.com") }
    }
    .errorPage(for: [.status(404)], file: "/usr/local/www/pingclair.pingclair.com/404.html")
    .encode(.zstd, .gzip)
}
.tls(.automatic(email: "team@pingclair.com"))
// 📓 One JSON line per request, rotated by Pingclair itself.
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(size: .mebibytes(100), keep: 7, compress: true),
)
```

## 配置说明

### 1. 全局配置与上游定义

`AutomaticTLS` 和 `Storage` 用于定义服务级别的 TLS 管理及持久化存储行为。

```swift
AutomaticTLS(mode: .automatic, httpPort: 80, httpsPort: 443)
Storage(root: "/var/db/pingclair")
```

`AutomaticTLS` 启用自动证书管理，配置 HTTP 和 HTTPS 端口，以支持证书签发与续期流程。

`Storage` 指定持久化数据目录，用于保存 TLS 证书、ACME 账户密钥及相关状态信息。

此外，配置使用 `let` 声明两个上游地址：

```swift
let installerHost = "releases.pingclair.com:443"
let cfWorker = "cf.pingclair.com:443"
```

通过集中定义上游地址，可以减少重复配置，并确保同一上游在不同路由中的引用保持一致。

Pingclair 原生配置语言将字符串视为字面量，不支持在字符串内部进行运行时变量插值。上游地址通过显式绑定引用，相关配置在加载阶段即可完成解析和检查。

### 2. HTTP 监听器与虚拟主机

```swift
HTTPListener(on: ":443") {
    Site(host: "pingclair.com") { ... }
    Site(host: "www.pingclair.com") { ... }
    Site(host: "pingclair.pingclair.com") { ... }
}
```

`HTTPListener` 定义监听端点，`Site` 则根据请求的主机名配置虚拟主机。

多个 `Site` 可以共享同一个监听器，而无需分别创建网络监听端点。

当前部署包含三个虚拟主机：

| 主机名 | 用途 |
|---|---|
| `pingclair.com` | 官方网站及主要 API 入口 |
| `www.pingclair.com` | 永久重定向至主域名 |
| `pingclair.pingclair.com` | 预发布环境及兼容入口 |

这种组织方式将网络监听配置与站点级路由逻辑分离，便于集中管理 TLS、日志及其他监听器级功能。

### 3. 路由匹配与执行顺序

Pingclair 按声明顺序对站点中的 `Route` 进行匹配，首先匹配成功的路由负责处理请求。

当没有路由匹配时，请求由 `Fallback` 处理。

官方网站采用以下匹配优先级：

1. 安装脚本：`/install.sh` 与 `/install`
2. Agent 接口：`/mcp` 与 `/a2a`
3. 根据 `Accept` 请求头选择 Markdown 内容
4. 通过 `Fallback` 提供常规静态文件

精确路径匹配优先于通用请求头匹配，可避免静态文件服务或内容协商逻辑影响专用接口。

路由执行顺序直接体现在配置文件中，不依赖额外的优先级数值或隐式规则。

### 4. 上游代理与响应缓存

官方网站的安装脚本由独立发布服务维护，不在文档站点中保存副本。

`/install.sh` 和 `/install` 均通过反向代理访问 `releases.pingclair.com`：

```swift
Rewrite(to: "/pingclair/install.sh")
Proxy(
    to: installerHost,
    headersUp: [.set("Host", "releases.pingclair.com")],
    headersDown: [.setIfAbsent("X-Installer-Source", "r2")],
)
.upstreamTLS(.enabled(serverName: "releases.pingclair.com"))
.cache(ttl: .minutes(5), maxSize: .mebibytes(16))
```

该配置包含以下处理步骤：

1. **路径改写**：`Rewrite` 将请求路径转换为发布服务使用的资源路径。
2. **上游代理**：`Proxy` 将请求转发至指定的 HTTPS 上游。
3. **Host 头设置**：`headersUp` 显式设置上游请求的 `Host`。
4. **TLS 服务器名称**：`upstreamTLS` 指定上游 TLS 连接使用的服务器名称。
5. **响应缓存**：`cache` 设置五分钟的缓存有效期及 16 MiB 的大小限制。
6. **响应来源标识**：`headersDown` 在响应头不存在时添加 `X-Installer-Source: r2`。

显式设置上游 `Host` 和 TLS 服务器名称对于当前部署尤为重要。

如果请求继续使用原始主机名 `pingclair.com`，可能被 Cloudflare 路由回官方网站服务器，形成非预期的代理循环。因此，该配置明确区分客户端访问域名与上游服务域名。

安装脚本通过独立发布服务分发，也避免了网站部署与发行版本之间出现多个需要同步维护的副本。

#### Agent 接口代理

`/mcp` 和 `/a2a` 使用相同的反向代理机制，但不配置响应缓存。

```swift
Route(when: .path(exact: "/mcp")) {
    Proxy(to: cfWorker, headersUp: [.set("Host", "cf.pingclair.com")])
    .upstreamTLS(.enabled(serverName: "cf.pingclair.com"))
}
```

这些接口仍由 Cloudflare Worker 提供服务，官方网站服务器负责将请求转发至现有上游。

该部署方式保留了既有接口路径，使网站基础设施迁移不必同时改变客户端使用的 API 地址。

### 5. 面向 AI Agent 的 Markdown 内容协商

官方网站支持根据 HTTP `Accept` 请求头，在同一个 URL 下提供 HTML 或 Markdown 格式的内容。

```swift
Route(when: .header(name: "Accept", contains: "text/markdown")) {
    TryFiles(
        candidates: [
            .requestPath(appending: "index.md"),
            .requestPath(appending: ".md")
        ],
        root: "/usr/local/www/pingclair.pingclair.com"
    )
    ServeFiles(root: "/usr/local/www/pingclair.pingclair.com")
}
```

*以上代码仅为便于阅读而调整排版，处理逻辑与生产配置一致。*

当客户端发送包含 `text/markdown` 的 `Accept` 请求头时，Pingclair 尝试定位对应的 Markdown 文件。

`TryFiles` 按顺序检查候选路径：

1. 请求路径对应目录中的 `index.md`
2. 请求路径对应的 `.md` 文件

找到文件后，后续 `ServeFiles` 使用选定的路径提供内容。

如果两个候选路径均不存在，`TryFiles` 不会直接返回错误，而是继续使用原始请求路径进行处理。

这使得普通静态资源及没有 Markdown 版本的路径仍可由文件服务正常处理。

部署流程还会根据相应的 Markdown 源文件生成所需的 `index.md`，以支持目录形式的文档路径。

对于普通浏览器请求，网站继续提供 HTML 页面。Markdown 文件不在默认目录索引列表中，因此不会替代常规 HTML 索引页面。

需要注意的是，当前实现通过检查 `Accept` 请求头是否包含 `text/markdown` 来选择内容，属于基于请求头条件的格式选择，而非完整的 HTTP 内容协商算法。

该机制旨在使 AI Agent 能够直接获取文档的结构化文本版本，同时保持现有 URL 和浏览器访问行为不变。

有关网站面向 AI Agent 的整体可访问性与内容组织方式，可参考 Cloudflare 的相关文章：

[Agent Readiness](https://blog.cloudflare.com/agent-readiness/)

### 6. 规范域名与永久重定向

官方网站使用 `pingclair.com` 作为规范域名，并通过 HTTP 308 将 `www.pingclair.com` 的请求永久重定向至主域名。

```swift
Site(host: "www.pingclair.com") {
    Fallback {
        Redirect(
            to: "https://pingclair.com",
            status: .permanentRedirect
        )
    }
}
```

HTTP 308 表示永久重定向，并要求客户端在重定向过程中保留原始请求方法。

当前配置存在一项已知限制：**重定向不会保留原始请求路径。**

例如，访问 `https://www.pingclair.com/docs/example` 将被重定向至 `https://pingclair.com`，而不是相应的文档路径。

这是因为当前原生配置语言尚未提供用于构造动态重定向目标的请求路径引用机制。

相关改进方案正在 [Issue #330](https://github.com/dorianverlaine/pingclair/issues/330) 中跟踪，其中包括为 `Redirect` 引入 `keepPath` 参数的设计建议。

### 7. TLS 与 HTTP/3

```swift
.tls(.automatic(email: "team@pingclair.com"))
```

监听器通过自动 TLS 配置管理证书签发和续期。

`team@pingclair.com` 用作相关 ACME 账户的联系邮箱。

当前部署同时支持 HTTP/3，通过 UDP/443 提供基于 QUIC 的 HTTP 连接。

HTTP/3 与传统的 TLS-over-TCP 连接可以使用相同的端口号，但分别基于 UDP 和 TCP 传输。

### 8. 自定义错误页面与内容压缩

官方网站使用 Starlight 生成的 `404.html` 作为自定义错误页面。

```swift
.errorPage(
    for: [.status(404)],
    file: "/usr/local/www/pingclair.pingclair.com/404.html"
)
.encode(.zstd, .gzip)
```

`errorPage` 将 HTTP 404 状态关联至指定的静态错误页面，保持网站在资源不存在时的展示一致性。

`encode` 配置支持 Zstandard 和 Gzip 内容编码，使客户端能够根据支持的编码格式接收压缩后的响应。

### 9. 访问日志与文件轮转

```swift
.accessLog(
    output: .file("/var/log/pingclair-access.log"),
    format: .json,
    headers: [.request("User-Agent")],
    rotation: .roll(
        size: .mebibytes(100),
        keep: 7,
        compress: true
    ),
)
```

该配置启用 JSON 格式的访问日志，并将其写入：

`/var/log/pingclair-access.log`

每条访问日志采用独立的 JSON 记录，便于日志采集、查询及自动化分析。

日志额外包含请求的 `User-Agent` 头，并由 Pingclair 内置的轮转机制管理日志文件：

- 单个日志文件达到 100 MiB 时触发轮转
- 最多保留七个轮转文件
- 对轮转后的日志文件启用压缩

因此，该部署无需额外依赖外部日志轮转程序即可完成上述日志生命周期管理。

## 参考资料

有关 Pingclair 原生配置语言及其组件的完整说明，请参阅以下资源：

- **[官方文档](https://pingclair.com)**：配置语言、功能说明及部署指南
- **`pingclair describe`**：查看解析器支持的配置组件及其定义
- **`pingclair validate`**：校验配置文件，并报告语法或配置错误及其对应位置
- **[官方网站源代码](https://github.com/dorianverlaine/pingclair-docs)**：网站内容与文档维护仓库

本文所示配置用于说明 Pingclair 在实际生产环境中的部署方式。具体配置参数及功能支持情况请以对应版本的官方文档为准。