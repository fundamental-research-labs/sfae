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
footer_path="$script_dir/docs/includes/footer.html"
footer_styles_path="$script_dir/docs/includes/footer.css"

rm -rf "$stage"
mkdir -p "$stage"
cp -R "$script_dir/docs/." "$stage/"

cp "$script_dir/install.sh" "$stage/install.sh"
cp "$script_dir/install-skill.sh" "$stage/install-skill.sh"
mkdir -p "$stage/skill"
cp "$script_dir/skill/SKILL.md" "$stage/skill/SKILL.md"
cp "$script_dir/skill/install.sh" "$stage/skill/install.sh"

inject_doc_partials() {
  local file="$1"
  local footer
  local footer_styles
  local footer_token
  local footer_styles_token
  local content

  footer="$(<"$footer_path")"
  footer_styles="$(<"$footer_styles_path")"
  footer_token="{{FOOTER}}"
  footer_styles_token="{{FOOTER_STYLES}}"
  content="$(<"$file")"
  content="${content//$footer_styles_token/$footer_styles}"
  content="${content//$footer_token/$footer}"
  printf '%s' "$content" > "$file"
}

while IFS= read -r -d '' html_file; do
  inject_doc_partials "$html_file"
done < <(find "$stage" -name '*.html' -print0)

if compgen -G "$script_dir/docs/pages/*.md" >/dev/null; then
  "$script_dir/scripts/render-markdown-pages.sh" \
    "$script_dir/docs/pages" \
    "$stage" \
    "$stage/page-template.html"
  rm -rf "$stage/pages" "$stage/page-template.html"
fi

rm -rf "$stage/includes"

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

if grep -R "{{FOOTER" "$stage" >/dev/null; then
  echo "Unresolved footer placeholders remain in $stage" >&2
  exit 1
fi

echo "Prepared Pages artifact at $stage"
