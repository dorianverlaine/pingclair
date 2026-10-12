# 📚 The example corpus

Every file here is a configuration this repository promises to understand. They
are documentation first — one topic per file, written the way a person would
write it — and a test corpus second, because that promise is only worth
something if a machine checks it.

## 🗂️ What the names mean

Every configuration here is a Pingclairfile: the upstream Caddyfile syntax,
plus the few words Pingclair adds for capabilities upstream has no word for.

| Path | What it shows |
| --- | --- |
| `Pingclairfile` | A deployment file: no extension, because that is the name `pingclair run` looks for in a working directory. |
| `Pingclairfile.example` | The file `scripts/install.sh` downloads to `/etc/Pingclair/Pingclairfile.example`. |
| `basic.pingclair` | The smallest useful site. |
| `reverse_proxy.pingclair` | A reverse proxy with upstream policy. |
| `full_featured.pingclair` | A tour of the directives this build implements. |
| `layer4.pingclair` | TCP routing by TLS ClientHello, in the global `layer4` block. |
| `extensions.pingclair` | The words Pingclair adds: `deny`, `send_timeout`, `keepalive_requests`, `negotiate markdown`. |
| `public/` | Static files the examples point at, fetched by `scripts/install.sh`. |

`.pingclair` is the extension a directory configuration is read from; a
`.caddyfile` file is read the same way, by the same parser.

## 🎯 The promise, and who keeps it

`pingclair-config/tests/documentation.rs` walks this directory and fails when:

- any example stops compiling (validation included);
- any example is not already formatted, so the corpus is also the style guide.

```bash
cargo +1.99.0 nextest run -p pingclair-config --test documentation
```

## ✍️ Adding an example

1. One topic per file, named after it: `layer4.pingclair`, `extensions.pingclair`.
2. Start with a comment saying what the file demonstrates, and what a reader
   should notice — an order, a default, a spelling that is easy to get wrong.
3. Prefer `tls internal` and high ports, so the file can be validated and run
   on a laptop without root and without certificates on disk.
4. Run `pingclair fmt --overwrite <file>`, then the test above. Comments are
   kept; only indentation and spacing change.
