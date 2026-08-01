#!/bin/sh
# tfforge installer — https://github.com/Mrg77/tfforge
# Works on Linux (Debian, Ubuntu, Alpine…) and macOS.
# Usage: curl -fsSL https://raw.githubusercontent.com/Mrg77/tfforge/master/install.sh | sh
set -eu

REPO="Mrg77/tfforge"
INSTALL_DIR="${TFFORGE_INSTALL_DIR:-$HOME/.local/bin}"

os=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$os" in
  darwin|linux) ;;
  *) echo "error: unsupported OS '$os' (darwin and linux only — use WSL on Windows)" >&2; exit 1 ;;
esac

arch=$(uname -m)
case "$arch" in
  x86_64|amd64) arch=amd64 ;;
  arm64|aarch64) arch=arm64 ;;
  *) echo "error: unsupported architecture '$arch'" >&2; exit 1 ;;
esac

version="${TFFORGE_VERSION:-}"
if [ -z "$version" ]; then
  version=$(curl -fsSL "https://api.github.com/repos/$REPO/releases/latest" \
    | grep '"tag_name"' | head -1 | cut -d '"' -f 4)
fi
[ -n "$version" ] || { echo "error: could not resolve latest release" >&2; exit 1; }

archive="tfforge_${version#v}_${os}_${arch}.tar.gz"
url="https://github.com/$REPO/releases/download/$version/$archive"

echo "Downloading tfforge $version ($os/$arch)..."
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
curl -fsSL "$url" -o "$tmp/$archive"
tar -xzf "$tmp/$archive" -C "$tmp" tfforge

mkdir -p "$INSTALL_DIR"
install -m 0755 "$tmp/tfforge" "$INSTALL_DIR/tfforge"
echo "Installed to $INSTALL_DIR/tfforge"

case ":$PATH:" in
  *":$INSTALL_DIR:"*) ;;
  *) echo "note: add $INSTALL_DIR to your PATH, e.g.:"
     echo "  echo 'export PATH=\"$INSTALL_DIR:\$PATH\"' >> ~/.bashrc" ;;
esac

echo
echo "Get started:"
echo "  tfforge scan ./infra --fail-on high     # deterministic security scan (no API key)"
echo "  export ANTHROPIC_API_KEY=...            # then run the agent:"
echo "  tfforge \"build a private, encrypted S3 bucket in ./out, scan it, fix findings\""
