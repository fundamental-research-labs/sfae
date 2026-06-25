#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd "$(dirname "$0")/.." && pwd)"

usage() {
  echo "Usage: scripts/stamp-cargo-version.sh <version-or-tag>" >&2
  echo "Example: scripts/stamp-cargo-version.sh v1.2.3" >&2
}

if [[ "$#" -ne 1 ]]; then
  usage
  exit 1
fi

case "$1" in
  v*) version="${1#v}" ;;
  *) version="$1" ;;
esac

if [[ ! "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?(\+[0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid semver version: $version" >&2
  exit 1
fi

VERSION="$version" perl -0pi -e '
  my $version = $ENV{"VERSION"};
  my $count = s/(\[workspace\.package\]\s*(?:(?!\n\[).)*?\nversion\s*=\s*")[^"]+(")/$1$version$2/s;
  die "Could not find [workspace.package] version in Cargo.toml\n" unless $count == 1;
' "$script_dir/Cargo.toml"

echo "Stamped Cargo workspace version $version"
