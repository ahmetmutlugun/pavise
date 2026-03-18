#!/bin/sh
set -e

REPO="ahmetmutlugun/pavise"
INSTALL_DIR="${PAVISE_INSTALL_DIR:-/usr/local/bin}"

# Detect platform
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case "${OS}-${ARCH}" in
  linux-x86_64)    TARGET="x86_64-unknown-linux-gnu" ;;
  darwin-arm64)    TARGET="aarch64-apple-darwin" ;;
  darwin-x86_64)   TARGET="x86_64-apple-darwin" ;;
  *)
    echo "Error: unsupported platform ${OS}-${ARCH}" >&2
    exit 1
    ;;
esac

# Get latest tag
TAG=$(curl -fsSL "https://api.github.com/repos/${REPO}/releases/latest" | grep '"tag_name"' | cut -d'"' -f4)
if [ -z "$TAG" ]; then
  echo "Error: could not determine latest release" >&2
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/pavise-${TAG}-${TARGET}.tar.gz"

echo "Downloading pavise ${TAG} for ${TARGET}..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "$URL" | tar xz -C "$TMPDIR"
install -m 755 "$TMPDIR"/pavise-*/pavise "${INSTALL_DIR}/pavise" 2>/dev/null \
  || install -m 755 "$TMPDIR"/pavise "${INSTALL_DIR}/pavise"

echo "Installed pavise ${TAG} to ${INSTALL_DIR}/pavise"
