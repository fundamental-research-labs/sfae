#!/usr/bin/env bash
set -euo pipefail

readonly VET_REPO_URL="${VET_REPO_URL:-https://github.com/gdevillele/vet.git}"
readonly VET_REF="${VET_REF:-330f4ea75676d0706bab43b07d62d8dffce4662a}"

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
repo_root="$(cd "${script_dir}/.." && pwd)"
cache_root="${VET_CACHE_DIR:-${XDG_CACHE_HOME:-${HOME}/.cache}/sfae-vet}"
vet_dir="${cache_root}/repo"
cargo_bin="${CARGO:-cargo}"

if ! command -v "${cargo_bin}" >/dev/null 2>&1; then
  cargo_bin="$(rustup which cargo)"
fi
if ! command -v rustc >/dev/null 2>&1; then
  export RUSTC="${RUSTC:-$(rustup which rustc)}"
fi

if [[ ! -d "${vet_dir}/.git" ]]; then
  mkdir -p "${cache_root}"
  rm -rf "${vet_dir}"
  git clone --filter=blob:none --no-checkout "${VET_REPO_URL}" "${vet_dir}"
fi

if [[ "${VET_REF}" =~ ^[0-9a-f]{40}$ ]] \
  && git -C "${vet_dir}" cat-file -e "${VET_REF}^{commit}" >/dev/null 2>&1; then
  git -C "${vet_dir}" checkout --detach "${VET_REF}"
else
  git -C "${vet_dir}" fetch --depth 1 origin "${VET_REF}"
  git -C "${vet_dir}" checkout --detach FETCH_HEAD
fi

export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-${repo_root}/target/vet}"

cd "${repo_root}"
"${cargo_bin}" run \
  --quiet \
  --locked \
  --manifest-path "${vet_dir}/implementations/rust/Cargo.toml" \
  -- \
  --config "${repo_root}/vet.yaml" \
  "$@"
