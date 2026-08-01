# Caddy Official Documentation (local reference copy)

This directory is a snapshot of the official Caddy documentation source
(`src/docs` from https://github.com/caddyserver/website), copied on
2026-08-01 from the local checkout at
`/Users/sinclairverlaine/code/caddy-website` for offline reference during
Pingclair's Caddyfile compatibility work.

## Source

- Upstream repository: https://github.com/caddyserver/website
- Canonical rendered docs: https://caddyserver.com/docs
- The Caddy project is licensed under Apache-2.0; this copy is kept for
  reference and compatibility verification only, and is not part of the
  Pingclair shipped documentation.

## Usage

The Caddyfile compatibility audit documents in `../../docs/CADDYFILE_*.md`
cite these sources by file name (e.g. `caddyfile/concepts.md`,
`automatic-https.md`). Re-sync this snapshot with:

```bash
cp -R ~/code/caddy-website/src/docs/. vendor/caddy-docs/
```

⚠️ This is a snapshot for review; content may drift from upstream. Check the
canonical site before publishing user-facing claims.
