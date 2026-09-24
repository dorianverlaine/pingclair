<div align="center">

<a href="https://pingclair.com"><img src="assets/logo.png" alt="Pingclair" width="520"></a>

**A Rust web server and reverse proxy built on Cloudflare Pingora.**

[![Documentation](https://img.shields.io/badge/docs-pingclair.com-blue.svg)](https://pingclair.com)
[![Release](https://img.shields.io/github/v/release/dorianverlaine/pingclair?include_prereleases)](https://github.com/dorianverlaine/pingclair/releases/latest)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

</div>

---

## 📖 Overview

Pingclair serves static content and proxies HTTP applications through one
configuration model. It supports HTTP/1.1 and HTTP/2 over TCP, HTTP/3 over
QUIC, automatic HTTPS, health-aware load balancing, and configuration reloads.

The primary configuration format is the Pingclairfile, a deliberately bounded
implementation of commonly used Caddyfile syntax. Unsupported Caddy features
are rejected during configuration loading rather than accepted as no-ops.

Pingclair is currently distributed as a release candidate. Review the
[project status](https://pingclair.com/project/status/) before using it for a
production deployment.

## ✨ Highlights

- **HTTP/1.1, HTTP/2, and HTTP/3** — Serve all three protocols from one
  configuration, with QUIC provided by Cloudflare quiche.
- **Automatic HTTPS** — Obtain public certificates through ACME, operate a
  persistent internal certificate authority, or load certificates from files.
- **Reverse proxying** — Route to multiple upstreams with load-balancing
  policies, active health checks, retries, circuit breakers, and bounded
  overload queues.
- **Static files and FastCGI** — Serve files with conditional and range
  requests, apply gzip or Zstandard compression, and run PHP through FastCGI.
- **Fail-closed configuration** — Validate policy before publication and keep
  the last-known-good configuration when a reload cannot be applied safely.
- **Operational visibility** — Export Prometheus metrics and structured access
  logs without requiring an external module.

## 📦 Install

### Linux release package

The installer downloads the latest published release, verifies its SHA-256
checksum, creates an unprivileged service account, and installs the `pingclair`
and `pc` commands:

```bash
curl -fsSL https://pingclair.com/install.sh | sudo bash
```

The current release is `v0.2.0-rc.3`. It is a release candidate, not a stable
release. The `v0.1.x` line is unmaintained and should not be used for a new
deployment.

After installation, inspect the service before loading a configuration:

```bash
pc service status
pingclair version
```

The installer starts a systemd service with its configuration at
`/etc/Pingclair/Pingclairfile`. After replacing the placeholder configuration,
validate and reload it with:

```bash
sudo pingclair validate /etc/Pingclair/Pingclairfile
sudo pc service reload
```

See the [installation guide](https://pingclair.com/start/install/) for Docker,
service management, verification, removal, and troubleshooting.

### Build from source

Building the current branch requires the repository's pinned Rust toolchain:

```bash
git clone https://github.com/dorianverlaine/pingclair.git
cd pingclair
cargo +1.98.1 install --locked --path pingclair
```

The source build needs a C/C++ toolchain, CMake, Clang, and the development
headers used by BoringSSL and bindgen. The
[installation guide](https://pingclair.com/start/install/) lists the packages
for supported Linux distributions and documents the container image when a
host build is not appropriate.

Source builds describe the checked-out commit, which may contain changes not
present in the latest release. Consult the [changelog](CHANGELOG.md) before
upgrading a running deployment from a source build.

## 🚀 Quick start

Create a file named `Pingclairfile`:

```caddyfile
http://localhost:8080 {
    respond "Hello from Pingclair"
}
```

Validate it before starting the server:

```bash
pingclair validate Pingclairfile
```

Run Pingclair in the foreground:

```bash
pingclair run Pingclairfile
```

Verify the response from another terminal:

```bash
curl --noproxy '*' http://localhost:8080/
```

The response is:

```text
Hello from Pingclair
```

For a reverse proxy, replace `respond` with an upstream:

```caddyfile
http://localhost:8080 {
    reverse_proxy localhost:3000
}
```

For a public hostname, Pingclair can obtain and renew the certificate and
serve HTTP/1.1, HTTP/2, and HTTP/3:

```caddyfile
example.com {
    tls auto
    reverse_proxy localhost:3000
}
```

Public automatic HTTPS requires the hostname to resolve to the server and the
required TCP and UDP ports to be reachable. Follow the
[HTTPS guide](https://pingclair.com/start/https/) before enabling it on a live
host.

### Command-line modes

For temporary local use, Pingclair also provides direct commands that do not
require a Pingclairfile:

```bash
pingclair file-server --listen :8080 --root .
pingclair reverse-proxy --from :8080 --to localhost:3000
```

Configuration-file mode is recommended for services because it is reviewable,
validatable, and reloadable. A configuration can be inspected without starting
the server:

```bash
pingclair adapt --config Pingclairfile --pretty
```

The [quickstart](https://pingclair.com/start/quickstart/) covers validation,
adaptation, startup, verification, and migration into the system service.

## 📚 Documentation

The documentation site is the authoritative source for installation,
configuration, deployment behavior, compatibility boundaries, and performance
methodology.

| Topic | Description |
| --- | --- |
| [Install](https://pingclair.com/start/install/) | Release packages, Docker, source builds, verification, and removal. |
| [Quickstart](https://pingclair.com/start/quickstart/) | Write, validate, inspect, run, and verify a Pingclairfile. |
| [HTTPS](https://pingclair.com/start/https/) | Public ACME, DNS-01, internal certificates, and certificate files. |
| [Pingclairfile](https://pingclair.com/reference/pingclairfile/) | Addresses, matchers, route ordering, snippets, and imports. |
| [Directives](https://pingclair.com/reference/directives/) | Supported directives, syntax, defaults, and failure behavior. |
| [Command line](https://pingclair.com/reference/command-line/) | Commands, flags, service control, and configuration tools. |
| [Project status](https://pingclair.com/project/status/) | Release support, unsupported names, known limitations, and upcoming changes. |
| [Benchmarks](https://pingclair.com/project/benchmarks/) | Current results, test conditions, and interpretation limits. |

The repository [changelog](CHANGELOG.md) records upgrade-relevant changes on
`main` and between releases. It should be read before changing a deployed
version.

Documentation is published in English, Simplified Chinese, and Traditional
Chinese. The English pages define the terminology when translations differ;
all three editions describe the same commands and configuration surface.

## 📌 Release status

The latest published version is `v0.2.0-rc.3`. The source tree may contain
unreleased behavior, so release documentation and `main` must not be treated as
interchangeable.

Important boundaries include:

- Pingclair implements a practical subset of Caddyfile syntax; it is not a
  drop-in replacement for every Caddy configuration.
- Unsupported directives and options fail configuration loading explicitly.
  The complete current lists are maintained on the
  [project status page](https://pingclair.com/project/status/).
- Certificate and runtime state use a local file-backed store. Multiple
  instances do not share one distributed certificate store.
- Pingclair is an HTTP server and reverse proxy. It does not provide generic
  `CONNECT` tunnels or advertise extended CONNECT support.
- Request trailers are not forwarded to an upstream. Applications that depend
  on request trailers should not be placed behind this release.

Known defects, release-specific limitations, and differences between the
latest release and `main` are tracked on the
[project status page](https://pingclair.com/project/status/) and in the
[changelog](CHANGELOG.md). Performance results are published only with their
measurement conditions on the
[benchmarks page](https://pingclair.com/project/benchmarks/).

## 🤝 Contributing

Read [CONTRIBUTING.md](CONTRIBUTING.md) before opening a pull request. It
describes the development workflow, test requirements, commit conventions,
and architectural constraints.

Useful project resources:

- [Issue tracker](https://github.com/dorianverlaine/pingclair/issues) for
  confirmed defects and feature requests.
- [Discussions](https://github.com/dorianverlaine/pingclair/discussions) for
  design questions and general project conversation.
- [Changelog](CHANGELOG.md) for released and unreleased behavior changes.
- [CLA](CLA.md) for the one-time contributor agreement.

Security-sensitive reports should follow the repository's published security
policy when one is available. Do not include credentials, private keys, access
tokens, or private infrastructure details in a public issue.

## 📄 License

Pingclair is licensed under the [Apache License 2.0](LICENSE). See
[NOTICE](NOTICE) for attribution requirements and third-party notices.
