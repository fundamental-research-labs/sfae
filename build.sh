#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$ROOT_DIR"

usage() {
  cat <<'USAGE'
Usage: ./build.sh [--cli | --oauth-broker]

Build targets:
  --cli           Build the SFAE CLI (default)
  --oauth-broker  Build the hosted OAuth broker
USAGE
}

target="cli"

case "${1:-}" in
  "" | "--cli")
    target="cli"
    ;;
  "--oauth-broker")
    target="oauth-broker"
    ;;
  "-h" | "--help")
    usage
    exit 0
    ;;
  *)
    usage >&2
    exit 2
    ;;
esac

if [[ $# -gt 1 ]]; then
  usage >&2
  exit 2
fi

case "$target" in
  "cli")
    cargo build --bin sfae --release
    built_binary="target/release/sfae"
    ;;
  "oauth-broker")
    cargo build -p sfae-oauth-server --bin sfae-oauth-server --release
    built_binary="target/release/sfae-oauth-server"
    ;;
esac

link_name="sfae"
tmp_link=".$link_name.tmp.$$"

cleanup() {
  rm -f "$tmp_link"
}
trap cleanup EXIT

if [[ ( -e "$link_name" || -L "$link_name" ) && ! -L "$link_name" ]]; then
  echo "error: ./$link_name exists and is not a symlink; refusing to overwrite it" >&2
  exit 1
fi

ln -s "$built_binary" "$tmp_link"
rm -f "$link_name"
mv "$tmp_link" "$link_name"
echo "Built $built_binary"
echo "Symlink: ./$link_name -> $built_binary"
