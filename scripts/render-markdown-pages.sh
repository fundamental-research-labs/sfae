#!/usr/bin/env bash
set -euo pipefail
shopt -u patsub_replacement 2>/dev/null || true

usage() {
  echo "Usage: scripts/render-markdown-pages.sh <source-dir> <output-dir> <template>" >&2
}

if [[ "$#" -ne 3 ]]; then
  usage
  exit 1
fi

source_dir="$1"
output_dir="$2"
template_path="$3"

escape_html() {
  local value="$1"
  value="${value//&/\&amp;}"
  value="${value//</\&lt;}"
  value="${value//>/\&gt;}"
  printf '%s' "$value"
}

escape_attr() {
  local value
  value="$(escape_html "$1")"
  value="${value//\"/\&quot;}"
  printf '%s' "$value"
}

linkify() {
  sed -E 's#\[([^]]+)\]\((https?://[^)]+)\)#<a href="\2">\1</a>#g'
}

inline_html() {
  local text="$1"
  local out=""
  local before=""
  local rest=""
  local code=""

  while [[ "$text" == *\`* ]]; do
    before="${text%%\`*}"
    rest="${text#*\`}"
    if [[ "$rest" != *\`* ]]; then
      out+="$(escape_html "$text" | linkify)"
      printf '%s' "$out"
      return
    fi
    code="${rest%%\`*}"
    text="${rest#*\`}"
    out+="$(escape_html "$before" | linkify)"
    out+="<code>$(escape_html "$code")</code>"
  done

  out+="$(escape_html "$text" | linkify)"
  printf '%s' "$out"
}

append_html() {
  html_output+="$1"$'\n'
}

flush_paragraph() {
  if [[ -n "$paragraph" ]]; then
    append_html "<p>$(inline_html "$paragraph")</p>"
    paragraph=""
  fi
}

close_list() {
  if [[ -n "$list_tag" ]]; then
    append_html "</$list_tag>"
    list_tag=""
  fi
}

open_list() {
  local tag="$1"
  if [[ -n "$list_tag" && "$list_tag" != "$tag" ]]; then
    close_list
  fi
  if [[ -z "$list_tag" ]]; then
    append_html "<$tag>"
    list_tag="$tag"
  fi
}

markdown_to_html() {
  local markdown_path="$1"
  local line
  local heading_marks
  local heading_text
  local heading_level
  local item_text
  html_output=""
  paragraph=""
  list_tag=""

  while IFS= read -r line || [[ -n "$line" ]]; do
    if [[ "$line" =~ ^[[:space:]]*$ ]]; then
      flush_paragraph
      close_list
      continue
    fi

    if [[ "$line" =~ ^(#{1,6})[[:space:]]+(.+)$ ]]; then
      flush_paragraph
      close_list
      heading_marks="${BASH_REMATCH[1]}"
      heading_text="${BASH_REMATCH[2]}"
      heading_level="${#heading_marks}"
      append_html "<h$heading_level>$(inline_html "$heading_text")</h$heading_level>"
      continue
    fi

    if [[ "$line" =~ ^-[[:space:]]+(.+)$ ]]; then
      flush_paragraph
      open_list "ul"
      item_text="${BASH_REMATCH[1]}"
      append_html "<li>$(inline_html "$item_text")</li>"
      continue
    fi

    if [[ "$line" =~ ^[0-9]+\.[[:space:]]+(.+)$ ]]; then
      flush_paragraph
      open_list "ol"
      item_text="${BASH_REMATCH[1]}"
      append_html "<li>$(inline_html "$item_text")</li>"
      continue
    fi

    close_list
    if [[ -n "$paragraph" ]]; then
      paragraph+=" $line"
    else
      paragraph="$line"
    fi
  done < "$markdown_path"

  flush_paragraph
  close_list
  printf '%s' "$html_output"
}

target_path() {
  local output_root="$1"
  local page_path="$2"
  local source="$3"
  local relative

  if [[ "$page_path" != /* ]]; then
    echo "$source frontmatter path must start with /" >&2
    exit 1
  fi
  if [[ "$page_path" == *..* ]]; then
    echo "$source frontmatter path must not contain .." >&2
    exit 1
  fi

  relative="${page_path#/}"
  if [[ "$relative" == *.html ]]; then
    printf '%s/%s' "$output_root" "$relative"
    return
  fi
  relative="${relative%/}"
  if [[ -z "$relative" ]]; then
    printf '%s/index.html' "$output_root"
  else
    printf '%s/%s/index.html' "$output_root" "$relative"
  fi
}

render_page() {
  local source="$1"
  local body_file
  local first_line
  local line
  local key
  local value
  local title
  local description
  local updated
  local page_path
  local content
  local html
  local output_file

  body_file="$(mktemp)"
  title=""
  description=""
  updated=""
  page_path=""

  exec 9< "$source"
  if ! IFS= read -r first_line <&9 || [[ "$first_line" != "---" ]]; then
    echo "$source is missing frontmatter" >&2
    exit 1
  fi

  while IFS= read -r line <&9; do
    if [[ "$line" == "---" ]]; then
      break
    fi
    [[ -z "$line" ]] && continue
    if [[ ! "$line" =~ ^([A-Za-z0-9_-]+):[[:space:]]*(.*)$ ]]; then
      echo "$source has invalid frontmatter line: $line" >&2
      exit 1
    fi
    key="${BASH_REMATCH[1]}"
    value="${BASH_REMATCH[2]}"
    value="${value%\"}"
    value="${value#\"}"
    case "$key" in
      title)
        title="$value"
        ;;
      description)
        description="$value"
        ;;
      updated)
        updated="$value"
        ;;
      path)
        page_path="$value"
        ;;
    esac
  done

  while IFS= read -r line <&9 || [[ -n "$line" ]]; do
    printf '%s\n' "$line" >> "$body_file"
  done
  exec 9<&-

  if [[ -z "$title" ]]; then
    echo "$source is missing required frontmatter key: title" >&2
    exit 1
  fi
  if [[ -z "$page_path" ]]; then
    echo "$source is missing required frontmatter key: path" >&2
    exit 1
  fi

  content="$(markdown_to_html "$body_file")"
  html="$(<"$template_path")"

  html="${html//\{\{TITLE\}\}/$(escape_html "$title")}"
  html="${html//\{\{DESCRIPTION\}\}/$(escape_attr "$description")}"
  html="${html//\{\{UPDATED\}\}/$(escape_html "$updated")}"
  html="${html//\{\{CONTENT\}\}/$content}"

  output_file="$(target_path "$output_dir" "$page_path" "$source")"
  mkdir -p "$(dirname "$output_file")"
  printf '%s' "$html" > "$output_file"
  rm -f "$body_file"
}

shopt -s nullglob
for source in "$source_dir"/*.md; do
  render_page "$source"
done
