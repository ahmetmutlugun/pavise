#!/bin/sh
# Print the Homebrew formula for a published release, using its .sha256 files.
# Usage: scripts/brew-formula.sh v0.1.0 > ../homebrew-tap/Formula/pavise.rb
set -eu

TAG="${1:?usage: $0 <tag>}"
BASE="https://github.com/ahmetmutlugun/pavise/releases/download/${TAG}"

sha() {
  curl -fsSL "${BASE}/pavise-${TAG}-$1.tar.gz.sha256" | cut -d' ' -f1
}

cat <<EOF
class Pavise < Formula
  desc "Fast static security analyzer for iOS IPA files"
  homepage "https://pavise.app"
  version "${TAG#v}"
  license "MPL-2.0"

  on_macos do
    on_arm do
      url "${BASE}/pavise-${TAG}-aarch64-apple-darwin.tar.gz"
      sha256 "$(sha aarch64-apple-darwin)"
    end
    on_intel do
      url "${BASE}/pavise-${TAG}-x86_64-apple-darwin.tar.gz"
      sha256 "$(sha x86_64-apple-darwin)"
    end
  end

  on_linux do
    on_arm do
      url "${BASE}/pavise-${TAG}-aarch64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha aarch64-unknown-linux-gnu)"
    end
    on_intel do
      url "${BASE}/pavise-${TAG}-x86_64-unknown-linux-gnu.tar.gz"
      sha256 "$(sha x86_64-unknown-linux-gnu)"
    end
  end

  def install
    bin.install "pavise"
  end

  test do
    assert_match version.to_s, shell_output("#{bin}/pavise --version")
  end
end
EOF
