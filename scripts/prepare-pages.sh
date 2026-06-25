#!/usr/bin/env bash
set -euo pipefail

script_dir="$(CDPATH= cd "$(dirname "$0")/.." && pwd)"

usage() {
  echo "Usage: scripts/prepare-pages.sh <version> <release-url>" >&2
}

if [[ "$#" -ne 2 ]]; then
  usage
  exit 1
fi

version="$1"
release_url="$2"
stage="$script_dir/dist/pages"

rm -rf "$stage"
mkdir -p "$stage"
cp -R "$script_dir/docs/." "$stage/"

cp "$script_dir/install.sh" "$stage/install.sh"
cp "$script_dir/install-skill.sh" "$stage/install-skill.sh"
mkdir -p "$stage/skill"
cp "$script_dir/skill/SKILL.md" "$stage/skill/SKILL.md"
cp "$script_dir/skill/install.sh" "$stage/skill/install.sh"

VERSION="$version" RELEASE_URL="$release_url" perl -0pi -e '
  s/__VERSION__/$ENV{"VERSION"}/g;
  s#__RELEASE_URL__#$ENV{"RELEASE_URL"}#g;
' "$stage/index.html"

if grep -R "__VERSION__\|__RELEASE_URL__" "$stage/index.html" >/dev/null; then
  echo "Unresolved page placeholders remain in $stage/index.html" >&2
  exit 1
fi

echo "Prepared Pages artifact at $stage"
