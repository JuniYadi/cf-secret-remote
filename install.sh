#!/bin/sh
# Installs the cfs CLI from a GitHub release (Linux and macOS).
#   curl -fsSL https://raw.githubusercontent.com/JuniYadi/cf-secret-remote/main/install.sh | sh
#   curl -fsSL .../install.sh | sh -s -- v0.0.1      # a specific version
# Env: CFS_INSTALL_DIR (default ~/.local/bin), CFS_VERSION (same as the argument).
set -eu

REPO="JuniYadi/cf-secret-remote"
VERSION="${1:-${CFS_VERSION:-latest}}"
DIR="${CFS_INSTALL_DIR:-$HOME/.local/bin}"

die() { echo "cfs install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Linux) os=linux ;;
  Darwin) os=darwin ;;
  *) die "unsupported OS $(uname -s). On Windows use install.ps1." ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=x64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) die "unsupported CPU $(uname -m)" ;;
esac
asset="cfs-$os-$arch"

if [ "$VERSION" = latest ]; then
  base="https://github.com/$REPO/releases/latest/download"
else
  base="https://github.com/$REPO/releases/download/$VERSION"
fi

if command -v curl >/dev/null 2>&1; then
  fetch() { curl -fsSL "$1" -o "$2"; }
elif command -v wget >/dev/null 2>&1; then
  fetch() { wget -q "$1" -O "$2"; }
else
  die "curl or wget is required"
fi

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

echo "Downloading $asset ($VERSION)..."
fetch "$base/$asset" "$tmp/$asset" || die "download failed: $base/$asset"
fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS" || die "download failed: $base/SHA256SUMS"

want="$(awk -v a="$asset" '$2 == a || $2 == "*" a { print $1 }' "$tmp/SHA256SUMS")"
[ -n "$want" ] || die "SHA256SUMS has no entry for $asset. Nothing was installed."
if command -v sha256sum >/dev/null 2>&1; then
  got="$(sha256sum "$tmp/$asset" | awk '{ print $1 }')"
else
  got="$(shasum -a 256 "$tmp/$asset" | awk '{ print $1 }')"
fi
[ "$got" = "$want" ] || die "checksum mismatch for $asset. Nothing was installed."

mkdir -p "$DIR"
chmod +x "$tmp/$asset"
mv "$tmp/$asset" "$DIR/cfs"
echo "Installed $("$DIR/cfs" --version 2>/dev/null || echo cfs) to $DIR/cfs"

case ":$PATH:" in
  *":$DIR:"*) ;;
  *) echo "Add $DIR to your PATH, for example:  export PATH=\"$DIR:\$PATH\"" ;;
esac
echo "Next: cfs login --host https://your-vault.example.com"
