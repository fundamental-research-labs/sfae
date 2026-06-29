#!/usr/bin/env bash
set -euo pipefail
shopt -u patsub_replacement 2>/dev/null || true

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

if compgen -G "$script_dir/docs/pages/*.md" >/dev/null; then
  "$script_dir/scripts/render-markdown-pages.sh" \
    "$script_dir/docs/pages" \
    "$stage" \
    "$script_dir/docs/page-template.html"
  rm -rf "$stage/pages" "$stage/page-template.html"
fi

replace_placeholders() {
  local file="$1"
  local content
  content="$(<"$file")"
  content="${content//__VERSION__/$version}"
  content="${content//__RELEASE_URL__/$release_url}"
  printf '%s' "$content" > "$file"
}

while IFS= read -r -d '' html_file; do
  replace_placeholders "$html_file"
done < <(find "$stage" -name '*.html' -print0)

if grep -R "__VERSION__\|__RELEASE_URL__" "$stage" >/dev/null; then
  echo "Unresolved page placeholders remain in $stage" >&2
  exit 1
fi

echo "Prepared Pages artifact at $stage"
