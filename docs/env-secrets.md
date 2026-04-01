# Compile-Time Secrets via `.env.secrets`

sfae-core's `build.rs` loads environment variables from a `.env.secrets` file at build time. This is the preferred way to provide compile-time secrets (like OAuth client secrets) when sfae is used as a submodule in a larger project.

## Setup

1. Create a `.env.secrets` file in your **project root** (not inside the sfae directory):

   ```
   # Compile-time secrets for sfae-core
   SFAE_GOOGLE_CLIENT_SECRET=your-secret-here
   ```

2. Make sure `.env.secrets` is gitignored. If your project's `.gitignore` already has `.env*`, you're covered.

3. Build as usual — `cargo build`, `cargo tauri dev`, etc. The secret is embedded into the binary at compile time via `option_env!()`.

## How it works

`sfae-core/build.rs` walks up the directory tree from its own `Cargo.toml` looking for a `.env.secrets` file. For each `KEY=VALUE` line it finds, it emits `cargo:rustc-env=KEY=VALUE`, which makes the value available to `option_env!("KEY")` in Rust source code.

The walk-up search means the file works regardless of which workspace triggers the build — the sfae workspace directly, a parent monorepo, or a Tauri app that depends on sfae-core as a path dependency.

## Variables

| Variable | Used by | Purpose |
|---|---|---|
| `SFAE_GOOGLE_CLIENT_SECRET` | `oauth.rs` → `get_provider_preset()` | Google OAuth client secret for the built-in `googleapis.com` preset |

## Alternatives

- **Inline env var**: `SFAE_GOOGLE_CLIENT_SECRET="..." cargo build` — works but must be repeated every build.
- **Shell profile**: Export the var in `.bashrc`/`.zshrc` — works but pollutes the global environment.
- **CI**: Set the variable in your CI environment — `build.rs` skips silently when the file is absent, so `option_env!()` falls back to the process environment as usual.

## Notes

- The file is re-read on every build only if it changes (`cargo:rerun-if-changed`).
- Lines starting with `#` and blank lines are ignored.
- If the file doesn't exist, the build succeeds silently — `option_env!()` returns `None` for any variables that aren't set in the process environment either.
