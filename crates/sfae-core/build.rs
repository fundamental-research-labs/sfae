/// Load compile-time env vars from `.env.secrets` at the repo root.
/// This lets developers put secrets like `SFAE_GOOGLE_CLIENT_SECRET` in a
/// gitignored file that gets picked up by `option_env!()` in the crate source.
fn main() {
    // Walk up from CARGO_MANIFEST_DIR looking for .env.secrets.
    // We can't stop at the first .git because sfae-core lives in a git
    // submodule — its .git is a file, not the top-level repo root.
    let manifest_dir =
        std::path::PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let mut dir = manifest_dir.as_path();
    let secrets_path = loop {
        let candidate = dir.join(".env.secrets");
        if candidate.exists() {
            break candidate;
        }
        dir = match dir.parent() {
            Some(p) => p,
            None => {
                // Not found — skip silently (CI may set env vars directly).
                return;
            }
        };
    };
    println!("cargo:rerun-if-changed={}", secrets_path.display());

    let contents = match std::fs::read_to_string(&secrets_path) {
        Ok(c) => c,
        Err(_) => return, // File doesn't exist — that's fine.
    };

    for line in contents.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some((key, value)) = line.split_once('=') {
            let key = key.trim();
            let value = value.trim();
            println!("cargo:rustc-env={key}={value}");
        }
    }
}
