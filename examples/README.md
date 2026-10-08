# 📚 The example corpus

Every file here is a configuration this repository promises to understand. They
are documentation first — one feature per file, written the way a person would
write it — and a test corpus second, because that promise is only worth
something if a machine checks it.

## 🗂️ What the names mean

| Path | Language | Why it is named that way |
| --- | --- | --- |
| `*.pingclair` | The native language | `.pingclair` is the extension the loader's directory mode reads (`configuration_paths`), and it is the extension a real deployment uses. |
| `Pingclairfile` | The native language | A deployment file: no extension, because that is the name `pingclair run` looks for in a working directory. |
| `caddyfile/*.caddyfile` | The Caddyfile dialect | The compatibility layer, kept for migration. `.caddyfile` says which language the file is in, which an extensionless name cannot. |
| `Pingclairfile.example` | The Caddyfile dialect | The file `scripts/install.sh` downloads to `/etc/Pingclair/Pingclairfile.example`. It moves to the native language when 0.3 is the released version and the installer is updated with it. |
| `public/` | — | Static files the examples point at, fetched by `scripts/install.sh`. |

The extension is the language. A file named `.pingclair` that holds a Caddyfile
is the one mistake this layout is designed to make impossible.

## ✅ The promise, and who keeps it

`pingclair-config/tests/documentation.rs` walks this directory and fails when:

- any example stops compiling (validation included);
- a top-level `.pingclair` file, or `Pingclairfile`, is not native syntax;
- a file under `caddyfile/` *is* native syntax — the two corpora stay honest
  about which language they are;
- any example is not already formatted, so the corpus is also the style guide.

```bash
cargo +1.99.0 nextest run -p pingclair-config --test documentation
```

## ✍️ Adding an example

1. One feature per file, named after the feature: `guards.pingclair`,
   `errors.pingclair`.
2. Start with a comment saying what the file demonstrates, and what a reader
   should notice — a component's order, a default, a spelling that is easy to
   get wrong.
3. Prefer `.tls(.internal)` and high ports, so the file can be validated and
   run on a laptop without root and without certificates on disk.
4. Run `pingclair fmt --overwrite <file>`, then the test above. The corpus is
   the language's own style reference, so it has to be in the formatter's
   canonical shape.

When a batch lands, `full_featured.pingclair` grows a line and the feature gets
its own file if it deserves one.
