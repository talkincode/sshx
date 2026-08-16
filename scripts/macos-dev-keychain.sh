#!/usr/bin/env bash
# macos-dev-keychain.sh — run the real-keyring E2E suite locally on macOS
# without Keychain authorization prompts.
#
# Mirrors the "Prepare isolated macOS keychain" step in .github/workflows/ci.yml:
# creates an ephemeral keychain, makes it the user default, sets the key
# partition list so command-line tools can read items without GUI prompts,
# runs the E2E suite with SSHX_E2E_REAL_KEYRING=1, and always restores the
# original keychain search list on exit.
#
# Usage:
#   scripts/macos-dev-keychain.sh            # run the full E2E suite
#   scripts/macos-dev-keychain.sh -run Name  # extra args are passed to go test

set -euo pipefail

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "error: this script only makes sense on macOS" >&2
  exit 1
fi

keychain_path="$(mktemp -d)/sshx-dev.keychain-db"
keychain_password="sshx-dev-local"

original_default="$(security default-keychain -d user | sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//')"
original_keychains=()
while IFS= read -r item; do
  item="$(echo "$item" | sed 's/^[[:space:]]*"//; s/"[[:space:]]*$//')"
  if [[ -n "$item" ]]; then original_keychains+=("$item"); fi
done < <(security list-keychains -d user)

cleanup() {
  security default-keychain -d user -s "$original_default" || true
  if [[ ${#original_keychains[@]} -gt 0 ]]; then
    security list-keychains -d user -s "${original_keychains[@]}" || true
  fi
  security delete-keychain "$keychain_path" 2>/dev/null || true
  rm -rf "$(dirname "$keychain_path")"
}
trap cleanup EXIT

echo "==> Creating ephemeral keychain: $keychain_path"
security create-keychain -p "$keychain_password" "$keychain_path"
security set-keychain-settings -lut 3600 "$keychain_path"
security unlock-keychain -p "$keychain_password" "$keychain_path"
security list-keychains -d user -s "$keychain_path" "${original_keychains[@]}"
security default-keychain -d user -s "$keychain_path"

# Allow command-line tools (go test binaries, the compiled sshx binary) to
# access items in this keychain without a GUI authorization prompt.
security set-key-partition-list -S "apple-tool:,apple:,codesign:" -s -k "$keychain_password" "$keychain_path" >/dev/null

echo "==> Running real-keyring E2E suite"
SSHX_E2E_REAL_KEYRING=1 go test -v ./tests/e2e "$@"

echo "==> Done (original keychain will be restored)"
