#!/usr/bin/env bash
set -euo pipefail

script_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$script_dir"

usage() {
  cat >&2 <<'USAGE'
Usage: ./release.sh <version> [--build-only|--publish-only|--tap-only|--npm-only]
                    [--repo owner/name] [--tap-repo owner/name|--no-tap]
                    [--no-npm] [--force-tag] [--target rust-target]

Examples:
  ./release.sh 0.1.0
  ./release.sh 0.1.0 --build-only --target x86_64-unknown-linux-gnu
  ./release.sh 0.1.0 --publish-only
  ./release.sh 0.1.0 --tap-only
  ./release.sh 0.1.0 --npm-only

Prefer .github/workflows/release.yml for public releases. It builds all
platform assets, publishes the GitHub release, updates Homebrew, and handles npm
from GitHub Actions.
USAGE
}

die() {
  echo "$1" >&2
  exit 1
}

need_cmd() {
  if ! command -v "$1" >/dev/null 2>&1; then
    die "Missing required command: $1"
  fi
}

set_mode() {
  if [[ "$mode" != "all" && "$mode" != "$1" ]]; then
    die "Choose only one of --build-only, --publish-only, --tap-only, or --npm-only."
  fi
  mode="$1"
}

host_target() {
  rustc -vV | awk '/^host: / {print $2}'
}

workspace_version() {
  awk '
    /^\[workspace.package\]/ {in_workspace=1; next}
    /^\[/ {in_workspace=0}
    in_workspace && /^version =/ {gsub(/"/, "", $3); print $3; exit}
  ' Cargo.toml
}

asset_name_for_target() {
  case "$1" in
    x86_64-unknown-linux-gnu) echo "sfae-linux-x86_64.tar.gz" ;;
    aarch64-unknown-linux-gnu) echo "sfae-linux-arm64.tar.gz" ;;
    x86_64-apple-darwin) echo "sfae-macos-x86_64.tar.gz" ;;
    aarch64-apple-darwin) echo "sfae-macos-arm64.tar.gz" ;;
    *) die "Unsupported release target: $1" ;;
  esac
}

sha256_file() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  elif command -v shasum >/dev/null 2>&1; then
    shasum -a 256 "$1" | awk '{print $1}'
  else
    die "Missing sha256sum or shasum."
  fi
}

require_release_git_state() {
  need_cmd git
  if [[ -n "$(git status --porcelain --untracked-files=normal)" ]]; then
    git status --short >&2
    die "Worktree must be clean before releasing."
  fi
  branch="$(git rev-parse --abbrev-ref HEAD)"
  if [[ "$branch" == "HEAD" ]]; then
    die "Cannot release from a detached HEAD."
  fi
  if [[ "$branch" != "main" ]]; then
    die "Releases must be cut from main. Current branch: $branch"
  fi
}

verify_version() {
  current="$(workspace_version)"
  if [[ "$current" != "${tag#v}" ]]; then
    die "Cargo workspace version is $current, but release version is ${tag#v}. Update Cargo.toml first."
  fi
}

build_release() {
  need_cmd cargo
  need_cmd rustc
  need_cmd tar
  verify_version

  rm -rf "$dist"
  mkdir -p "$dist"

  for target in $targets; do
    asset_name="$(asset_name_for_target "$target")"
    echo "Building sfae for $target..."
    cargo build --release --bin sfae --target "$target"
    bin="target/$target/release/sfae"
    if [[ ! -x "$bin" ]]; then
      die "Build did not produce executable sfae at $bin"
    fi

    stage="$dist/$target"
    rm -rf "$stage"
    mkdir -p "$stage"
    cp "$bin" "$stage/sfae"
    strip "$stage/sfae" 2>/dev/null || true
    tar -C "$stage" -czf "$dist/$asset_name" sfae
    sha256_file "$dist/$asset_name" > "$dist/$asset_name.sha256"
    printf '  %s\n' "$asset_name"
  done

  echo "Built release assets in $dist"
}

ensure_tag() {
  head_sha="$(git rev-parse HEAD)"
  if [[ "$force_tag" == "1" ]]; then
    git tag -f -a "$tag" -m "$tag" "$head_sha"
    return
  fi
  if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    tag_sha="$(git rev-list -n 1 "$tag")"
    if [[ "$tag_sha" != "$head_sha" ]]; then
      die "Tag $tag already exists and does not point at HEAD."
    fi
    return
  fi
  if git ls-remote --exit-code --tags origin "refs/tags/$tag" >/dev/null 2>&1; then
    git fetch origin "refs/tags/$tag:refs/tags/$tag"
    tag_sha="$(git rev-list -n 1 "$tag")"
    if [[ "$tag_sha" != "$head_sha" ]]; then
      die "Remote tag $tag already exists and does not point at HEAD."
    fi
    return
  fi
  git tag -a "$tag" -m "$tag"
}

push_release_tag() {
  if [[ "$force_tag" == "1" ]]; then
    git push --force origin "refs/tags/$tag"
  else
    git push origin "refs/tags/$tag"
  fi
}

release_files() {
  local files=""
  for target in $targets; do
    asset="$dist/$(asset_name_for_target "$target")"
    checksum="$asset.sha256"
    [[ -f "$asset" ]] || die "Missing release asset: $asset"
    [[ -f "$checksum" ]] || die "Missing release checksum: $checksum"
    files="$files $asset $checksum"
  done
  echo "$files"
}

publish_release() {
  need_cmd gh
  verify_version
  git push origin main
  ensure_tag
  push_release_tag
  files="$(release_files)"
  if gh release view "$tag" --repo "$repo" >/dev/null 2>&1; then
    gh release upload "$tag" $files --repo "$repo" --clobber
  else
    gh release create "$tag" $files --repo "$repo" --title "$tag" --notes "Prebuilt sfae binaries for $tag" --verify-tag
  fi
  echo "Released $repo $tag"
}

checksum_for_asset() {
  local asset_name="$1"
  local checksum_file="$dist/$asset_name.sha256"
  if [[ -f "$checksum_file" ]]; then
    awk '{print $1}' "$checksum_file"
    return
  fi
  gh release download "$tag" --repo "$repo" --pattern "$asset_name.sha256" --dir "$dist/checksums" --clobber >/dev/null
  awk '{print $1}' "$dist/checksums/$asset_name.sha256"
}

formula_block() {
  local target="$1"
  local os_block="$2"
  local arch_block="$3"
  local asset_name
  asset_name="$(asset_name_for_target "$target")"
  local sha
  sha="$(checksum_for_asset "$asset_name" 2>/dev/null || true)"
  if [[ -z "$sha" ]]; then
    return
  fi
  cat <<FORMULA
  $os_block do
    $arch_block do
      url "https://github.com/$repo/releases/download/$tag/$asset_name"
      sha256 "$sha"
    end
  end

FORMULA
}

write_homebrew_formula() {
  local formula_path="$1"
  mkdir -p "$(dirname "$formula_path")"
  {
    cat <<FORMULA
class Sfae < Formula
  desc "Credential gateway for agents making authenticated API requests"
  homepage "https://sfae.io"
  version "${tag#v}"
  license "MIT"

FORMULA
    formula_block "aarch64-apple-darwin" "on_macos" "on_arm"
    formula_block "x86_64-apple-darwin" "on_macos" "on_intel"
    formula_block "aarch64-unknown-linux-gnu" "on_linux" "on_arm"
    formula_block "x86_64-unknown-linux-gnu" "on_linux" "on_intel"
    cat <<'FORMULA'
  def install
    bin.install "sfae"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/sfae --version")
  end
end
FORMULA
  } > "$formula_path"
  if ! grep -q 'url "' "$formula_path"; then
    die "No release assets/checksums available for the Homebrew formula."
  fi
}

update_homebrew_tap() {
  if [[ -z "$tap_repo" ]]; then
    echo "Skipping Homebrew tap update (--no-tap)."
    return
  fi
  need_cmd git
  need_cmd gh
  mkdir -p "$dist/checksums"
  tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/sfae-tap.XXXXXX")"
  trap 'rm -rf "$tmpdir"' EXIT INT HUP TERM
  tap_url="${SFAE_TAP_GIT_URL:-git@github.com:$tap_repo.git}"
  git clone "$tap_url" "$tmpdir/tap"
  write_homebrew_formula "$tmpdir/tap/Formula/sfae.rb"
  (
    cd "$tmpdir/tap"
    git add Formula/sfae.rb
    if git diff --cached --quiet; then
      echo "Homebrew formula already up to date."
      exit 0
    fi
    git commit -m "sfae $tag"
    git push
  )
}

publish_npm_package() {
  if [[ "$publish_npm" == "0" ]]; then
    echo "Skipping npm publish (--no-npm)."
    return
  fi
  need_cmd node
  need_cmd npm
  scripts/prepare-npm-package.sh "${tag#v}"
  npm_stage="$dist/npm"
  package_name="$(node -e "process.stdout.write(require(process.argv[1]).name)" "$npm_stage/package.json")"
  package_version="${tag#v}"
  npm pack --dry-run "$npm_stage" >/dev/null
  published_version="$(npm view "$package_name@$package_version" version 2>/dev/null || true)"
  if [[ "$published_version" == "$package_version" ]]; then
    echo "npm package $package_name@$package_version is already published"
    return
  fi
  npm publish "$npm_stage" --access public
  echo "Published npm package $package_name@$package_version"
}

mode="all"
repo="${SFAE_REPO:-fundamental-research-labs/sfae}"
tap_repo="${SFAE_TAP_REPO:-fundamental-research-labs/homebrew-tap}"
publish_npm="1"
force_tag="0"
input_version=""
targets=""

while [[ "$#" -gt 0 ]]; do
  case "$1" in
    -h|--help)
      usage
      exit 0
      ;;
    --build-only) set_mode "build" ;;
    --publish-only) set_mode "publish" ;;
    --tap-only) set_mode "tap" ;;
    --npm-only) set_mode "npm" ;;
    --repo)
      shift
      [[ "$#" -gt 0 ]] || die "--repo requires owner/name."
      repo="$1"
      ;;
    --repo=*) repo="${1#--repo=}" ;;
    --tap-repo)
      shift
      [[ "$#" -gt 0 ]] || die "--tap-repo requires owner/name."
      tap_repo="$1"
      ;;
    --tap-repo=*) tap_repo="${1#--tap-repo=}" ;;
    --no-tap) tap_repo="" ;;
    --no-npm) publish_npm="0" ;;
    --force-tag) force_tag="1" ;;
    --target)
      shift
      [[ "$#" -gt 0 ]] || die "--target requires a Rust target triple."
      targets="${targets}${targets:+ }$1"
      ;;
    --target=*) targets="${targets}${targets:+ }${1#--target=}" ;;
    --*) die "Unknown flag: $1" ;;
    *)
      if [[ -n "$input_version" ]]; then
        die "Unexpected argument: $1"
      fi
      input_version="$1"
      ;;
  esac
  shift
done

if [[ -z "$input_version" ]]; then
  usage
  exit 1
fi

case "$input_version" in
  v*) tag="$input_version" ;;
  *) tag="v$input_version" ;;
esac

[[ "$tag" != "v" ]] || die "Release version cannot be empty."
[[ "$mode" != "npm" || "$publish_npm" != "0" ]] || die "Cannot combine --npm-only with --no-npm."
case "$mode:$force_tag" in
  build:1|tap:1|npm:1) die "--force-tag can only be used when publishing the GitHub release." ;;
esac

if [[ -z "$targets" ]]; then
  need_cmd rustc
  targets="$(host_target)"
fi

dist="dist/$tag"

case "$mode" in
  all)
    require_release_git_state
    build_release
    publish_release
    update_homebrew_tap
    publish_npm_package
    ;;
  build)
    require_release_git_state
    build_release
    ;;
  publish)
    require_release_git_state
    publish_release
    update_homebrew_tap
    publish_npm_package
    ;;
  tap)
    require_release_git_state
    update_homebrew_tap
    ;;
  npm)
    publish_npm_package
    ;;
esac
