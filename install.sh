#!/usr/bin/env sh
set -eu

repo="${SFAE_REPO:-fundamental-research-labs/sfae}"
install_dir="${SFAE_INSTALL_DIR:-/usr/local/bin}"
version="${SFAE_VERSION:-latest}"

if [ -n "${SFAE_INSTALL_URL:-}" ]; then
  install_url="$SFAE_INSTALL_URL"
elif [ "$repo" = "fundamental-research-labs/sfae" ]; then
  install_url="https://sfae.io/install.sh"
else
  install_url="https://raw.githubusercontent.com/$repo/main/install.sh"
fi

case "$(uname -s)" in
  Darwin) os="macos" ;;
  Linux) os="linux" ;;
  *)
    echo "sfae direct installs currently support macOS and Linux." >&2
    exit 1
    ;;
esac

case "$(uname -m)" in
  arm64|aarch64) arch="arm64" ;;
  x86_64|amd64) arch="x86_64" ;;
  *)
    echo "Unsupported CPU architecture: $(uname -m)" >&2
    exit 1
    ;;
esac

for cmd in curl tar; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "Missing required command: $cmd" >&2
    exit 1
  fi
done

asset="sfae-$os-$arch.tar.gz"
if [ "$version" = "latest" ]; then
  base_url="https://github.com/$repo/releases/latest/download"
else
  case "$version" in
    v*) tag="$version" ;;
    *) tag="v$version" ;;
  esac
  base_url="https://github.com/$repo/releases/download/$tag"
fi

tmpdir="$(mktemp -d "${TMPDIR:-/tmp}/sfae-install.XXXXXX")"
cleanup() {
  rm -rf "$tmpdir"
}
trap cleanup EXIT INT HUP TERM

archive="$tmpdir/$asset"
checksum="$archive.sha256"

echo "Downloading $asset from $repo..."
curl -fL "$base_url/$asset" -o "$archive"
curl -fL "$base_url/$asset.sha256" -o "$checksum"

expected="$(awk '{print $1}' "$checksum")"
actual=""
if command -v sha256sum >/dev/null 2>&1; then
  actual="$(sha256sum "$archive" | awk '{print $1}')"
elif command -v shasum >/dev/null 2>&1; then
  actual="$(shasum -a 256 "$archive" | awk '{print $1}')"
else
  echo "Missing sha256sum or shasum for checksum verification." >&2
  exit 1
fi

if [ "$expected" != "$actual" ]; then
  echo "Checksum mismatch for $asset." >&2
  exit 1
fi

tar -xzf "$archive" -C "$tmpdir"
if [ ! -f "$tmpdir/sfae" ]; then
  echo "Release asset did not contain a sfae binary." >&2
  exit 1
fi

install_binary() {
  src="$1"
  dest="$2"
  if command -v install >/dev/null 2>&1; then
    install -m 0755 "$src" "$dest"
  else
    cp "$src" "$dest"
    chmod 0755 "$dest"
  fi
}

sudo_install_binary() {
  src="$1"
  dest="$2"
  if command -v install >/dev/null 2>&1; then
    sudo install -m 0755 "$src" "$dest"
  else
    sudo cp "$src" "$dest"
    sudo chmod 0755 "$dest"
  fi
}

print_permission_help() {
  echo "Could not write to $install_dir." >&2
  echo >&2
  if [ "$install_dir" = "/usr/local/bin" ]; then
    echo "To install to /usr/local/bin with admin permissions:" >&2
    echo "  curl -fsSL $install_url | sudo sh" >&2
    echo >&2
    echo "Or choose a user-writable install directory:" >&2
    echo "  curl -fsSL $install_url | env SFAE_INSTALL_DIR=\$HOME/.local/bin sh" >&2
  else
    echo "Choose a writable install directory with SFAE_INSTALL_DIR, for example:" >&2
    echo "  curl -fsSL $install_url | env SFAE_INSTALL_DIR=\$HOME/.local/bin sh" >&2
  fi
}

if ! mkdir -p "$install_dir" 2>/dev/null || ! install_binary "$tmpdir/sfae" "$install_dir/sfae" 2>/dev/null; then
  if [ "$install_dir" = "/usr/local/bin" ] && command -v sudo >/dev/null 2>&1 && [ -r /dev/tty ]; then
    printf "Installing to /usr/local/bin requires admin permissions. Use sudo? [y/N] " >/dev/tty
    IFS= read -r answer </dev/tty
    case "$answer" in
      y|Y|yes|YES) sudo_install_binary "$tmpdir/sfae" "$install_dir/sfae" ;;
      *)
        print_permission_help
        exit 1
        ;;
    esac
  else
    print_permission_help
    exit 1
  fi
fi

echo "Installed sfae to $install_dir/sfae"
if ! command -v sfae >/dev/null 2>&1; then
  echo "Make sure $install_dir is on PATH."
fi
