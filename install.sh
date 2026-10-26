#!/bin/sh
set -e

REPO="ahmetmutlugun/pavise"
INSTALL_DIR="${PAVISE_INSTALL_DIR:-/usr/local/bin}"

# Detect platform
ARCH=$(uname -m)
OS=$(uname -s | tr '[:upper:]' '[:lower:]')

case "${OS}-${ARCH}" in
  linux-x86_64)    TARGET="x86_64-unknown-linux-gnu" ;;
  linux-aarch64)   TARGET="aarch64-unknown-linux-gnu" ;;
  darwin-arm64)    TARGET="aarch64-apple-darwin" ;;
  darwin-x86_64)   TARGET="x86_64-apple-darwin" ;;
  *)
    echo "Error: unsupported platform ${OS}-${ARCH}" >&2
    exit 1
    ;;
esac

# Latest tag from the /releases/latest redirect (the REST API allows only 60
# unauthenticated requests per hour per IP, which shared CI runners and office
# NATs exhaust). PAVISE_VERSION=v0.1.1 pins a release.
TAG="${PAVISE_VERSION:-$(curl -fsSI "https://github.com/${REPO}/releases/latest" \
  | tr -d '\r' | sed -n 's#^[Ll]ocation: .*/tag/##p')}"
if [ -z "$TAG" ]; then
  echo "Error: could not determine latest release" >&2
  exit 1
fi

URL="https://github.com/${REPO}/releases/download/${TAG}/pavise-${TAG}-${TARGET}.tar.gz"

echo "Downloading pavise ${TAG} for ${TARGET}..."
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

curl -fsSL "$URL" -o "$TMPDIR/pavise.tar.gz"
EXPECTED=$(curl -fsSL "${URL}.sha256" | cut -d' ' -f1)
if command -v sha256sum >/dev/null 2>&1; then
  ACTUAL=$(sha256sum "$TMPDIR/pavise.tar.gz" | cut -d' ' -f1)
else
  ACTUAL=$(shasum -a 256 "$TMPDIR/pavise.tar.gz" | cut -d' ' -f1)
fi
if [ -z "$EXPECTED" ] || [ "$EXPECTED" != "$ACTUAL" ]; then
  echo "Error: checksum mismatch for ${URL}" >&2
  exit 1
fi
tar xzf "$TMPDIR/pavise.tar.gz" -C "$TMPDIR"
install -m 755 "$TMPDIR"/pavise-*/pavise "${INSTALL_DIR}/pavise" 2>/dev/null \
  || install -m 755 "$TMPDIR"/pavise "${INSTALL_DIR}/pavise"

echo "Installed pavise ${TAG} to ${INSTALL_DIR}/pavise"
