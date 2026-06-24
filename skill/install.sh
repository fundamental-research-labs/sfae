#!/usr/bin/env sh
set -eu

repo="${SFAE_REPO:-fundamental-research-labs/sfae}"
brew_formula="${SFAE_BREW_FORMULA:-fundamental-research-labs/tap/sfae}"
npm_package="${SFAE_NPM_PACKAGE:-@fundamental-research-labs/sfae}"
install_url="https://raw.githubusercontent.com/$repo/main/install.sh"

have() {
  command -v "$1" >/dev/null 2>&1
}

try_brew() {
  if ! have brew; then
    return 1
  fi
  echo "Installing sfae with Homebrew..."
  brew install "$brew_formula"
}

try_npm() {
  if ! have npm; then
    return 1
  fi
  echo "Installing sfae with npm..."
  npm install -g "$npm_package"
}

try_direct() {
  if ! have curl; then
    echo "Missing curl; cannot run direct installer." >&2
    return 1
  fi
  echo "Installing sfae with the direct installer..."
  curl -fsSL "$install_url" | sh
}

if have sfae && [ "${SFAE_FORCE_INSTALL:-0}" != "1" ]; then
  echo "sfae is already installed: $(command -v sfae)"
  exit 0
fi

if try_brew; then
  exit 0
fi

if try_npm; then
  exit 0
fi

try_direct
