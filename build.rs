//! Records the git commit pavise was built from (`PAVISE_GIT_COMMIT`), so a
//! report names the exact scanner build. Falls back to the `PAVISE_GIT_COMMIT`
//! environment variable (builds without `.git`, e.g. Docker), else empty.

use std::process::Command;

fn main() {
    println!("cargo:rerun-if-env-changed=PAVISE_GIT_COMMIT");
    // HEAD moves on checkout; the branch ref (or packed-refs) moves on commit.
    for path in [".git/HEAD", ".git/packed-refs"] {
        println!("cargo:rerun-if-changed={}", path);
    }
    if let Ok(head) = std::fs::read_to_string(".git/HEAD") {
        if let Some(r) = head.trim().strip_prefix("ref: ") {
            println!("cargo:rerun-if-changed=.git/{}", r);
        }
    }

    let commit = Command::new("git")
        .args(["rev-parse", "--short=7", "HEAD"])
        .output()
        .ok()
        .filter(|o| o.status.success())
        .and_then(|o| String::from_utf8(o.stdout).ok())
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .or_else(|| std::env::var("PAVISE_GIT_COMMIT").ok())
        .unwrap_or_default();
    println!("cargo:rustc-env=PAVISE_GIT_COMMIT={}", commit);
}
