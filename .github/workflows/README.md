# Pingclair CI Workflow Overview

Pingclair's CI is split into two layers: a fast gate before merge and a full
verification pass after `main` changes. Each check has exactly one owning
workflow, so a red result never masks another.

## The two entry points

- `blocking-ci.yml`: the merge gate for `pull_request` and pushes to `main`.
  Every reusable workflow is called from here, and the `CI required` job
  collapses them into a single required status.
- `postmerge-ci.yml`: the full gate after pushes to `main`. It runs the
  nextest shards, release-profile Clippy, and the HTTP/3 suite, then
  collapses into `Postmerge CI results`. `dev.yml` waits for this gate before
  publishing development artifacts.

## Workflow responsibilities

| Workflow | Trigger | Responsibility |
| --- | --- | --- |
| `blocking-ci.yml` | PR, push `main` | Merge-gate parent; owns the `CI required` status |
| `postmerge-ci.yml` | push `main` | Full-gate parent; owns postmerge results |
| `rust-ci.yml` | workflow_call, dispatch | Path-aware fast gate; runs `just ci` on Rust changes |
| `rust-ci-full.yml` | workflow_call, dispatch, `**full-ci**` | Full orchestration: release Clippy, nextest shards |
| `rust-ci-full-nextest-platform.yml` | workflow_call | Nextest archive + 4 shards + JUnit for one platform |
| `docker.yml` | workflow_call | Builds the production image; boots it and validates a real Pingclairfile |
| `commit-checks.yml` | workflow_call | Whitespace, commit subjects, version ahead of the newest tag |
| `security-audit.yml` | workflow_call, nightly schedule | `cargo audit` plus a re-resolved audit of patched crates |
| `cargo-deny.yml` | workflow_call | License, ban, and duplicate-version policy |
| `repo-checks.yml` | workflow_call | Mechanical repository invariants and their unit tests |
| `codespell.yml` | workflow_call | Spelling check |
| `docs-lint.yml` | workflow_call | Markdown structure check via markdownlint-cli2 |
| `blob-size-policy.yml` | workflow_call | 512 KB blob budget with an explicit allowlist |
| `h3.yml` | workflow_call, dispatch | Full HTTP/3 functional matrix |
| `dev.yml` | workflow_run: postmerge-ci | Dev binaries, rolling release, and dev image |
| `release.yml` | push tag | Tag verification, native builds, checksums, multi-arch image |

## Rules for adding or changing checks

1. Add the command to the root `justfile` first; local development and CI
   share one source of truth.
2. Prefer a reusable workflow (`on: workflow_call`) and call it from
   `blocking-ci.yml` or `postmerge-ci.yml`.
3. Pin every third-party action to a commit SHA with a human-readable version
   comment (for example `# v7.0.1`); every checkout uses
   `persist-credentials: false`.
4. Any job that can generate files ends with `check-clean-worktree`, so
   formatting, codegen, or lockfile updates cannot silently stay uncommitted.
5. Grant elevated `permissions` only to jobs that need them; everything else
   stays at `contents: read`.
6. Matrices use `fail-fast: false` so every leg's failure stays visible.

## The local gate

Developers and CI run the same gate:

```bash
just ci
```

Use `just lint` or `just test` when only one half is needed.
