// 🏷️ Decides the version string the binary reports about itself.
//
// The default branch always carries version 0.0.0: a release is one commit
// off main that sets the real number, so no pull request ever conflicts on a
// version bump. A binary built from main must therefore not claim to be
// "0.0.0" — it says `0.0.0-dev+<short sha>`, which tells a bug reporter and
// a maintainer exactly which commit it came from. A release build reports its
// own version untouched.
//
// 📌 Only the leaf binary crate runs this script. Putting it in a library
// would rebuild the whole workspace after every commit, because the script
// has to rerun whenever HEAD moves.

use std::process::Command;

const DEV_VERSION: &str = "0.0.0";

fn main() {
    println!("cargo:rerun-if-changed=build.rs");
    let package = std::env::var("CARGO_PKG_VERSION").expect("cargo sets CARGO_PKG_VERSION");

    let version = if package == DEV_VERSION {
        watch_git_head();
        // 📦 A source tarball has no repository, so there is no sha to name;
        // the bare dev marker still says "not a release".
        match git(&["rev-parse", "--short=10", "HEAD"]) {
            Some(sha) => format!("{DEV_VERSION}-dev+{sha}"),
            None => format!("{DEV_VERSION}-dev"),
        }
    } else {
        package
    };
    println!("cargo:rustc-env=PINGCLAIR_VERSION={version}");
}

/// 🔁 Reruns this script when the checked-out commit changes, so the sha in
/// a dev build does not go stale across commits.
fn watch_git_head() {
    let Some(head) = git(&["rev-parse", "--git-path", "HEAD"]) else {
        return;
    };
    println!("cargo:rerun-if-changed={head}");
    // 🧭 HEAD usually names a branch, and a commit moves the branch's ref
    // file rather than HEAD itself. `packed-refs` covers refs git has packed.
    if let Some(branch) = git(&["symbolic-ref", "-q", "HEAD"])
        && let Some(path) = git(&["rev-parse", "--git-path", &branch])
    {
        println!("cargo:rerun-if-changed={path}");
    }
    if let Some(packed) = git(&["rev-parse", "--git-path", "packed-refs"]) {
        println!("cargo:rerun-if-changed={packed}");
    }
}

fn git(args: &[&str]) -> Option<String> {
    let output = Command::new("git").args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    let text = String::from_utf8(output.stdout).ok()?.trim().to_owned();
    (!text.is_empty()).then_some(text)
}
