#!/usr/bin/env bash
#
# pull-synapse-fee.sh — vendor the pinned TypeScript FEE reference
# implementation and (re)generate + verify the FEE cross-implementation
# fixtures against it.
#
# The reference is github.com/FilOzone/synapse-sdk,
# packages/filecoin-encryption-envelope, pinned to a fixed commit (see REF_SHA
# below) for reproducibility. The vendored source is written under ts/vendor/
# (gitignored) and never committed; only this script, the ts/ driver, and the
# generated testdata/ fixtures are.
#
# Usage:
#   ./pull-synapse-fee.sh            # generate the TS fixtures + verify all
#   ./pull-synapse-fee.sh verify     # verify committed fixtures only
#   ./pull-synapse-fee.sh generate   # (re)generate the TS fixtures only
#
# Requires: Node 22.18 or later (it runs the TypeScript source directly), npm,
# and either git or curl for the source pull.
set -euo pipefail

REF_REPO="https://github.com/FilOzone/synapse-sdk"
REF_SHA="6883ba8d173e8576d59e74dd15928b4d0f144fbe"

PKG_SUBDIR="packages/filecoin-encryption-envelope"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TS_DIR="$SCRIPT_DIR/ts"
VENDOR="$TS_DIR/vendor/filecoin-encryption-envelope"

# Source files fetched by the raw fallback (the git path copies the whole
# src tree). This list is fixed for the pinned commit.
SRC_FILES=(
  src/index.ts src/aes-gcm.ts src/aes-gcm-stream.ts src/chunk-layout.ts
  src/constants.ts src/errors.ts src/nonce.ts src/public-constants.ts
  src/cose/constants.ts src/cose/decode.ts src/cose/enc-structure.ts
  src/cose/encode.ts src/cose/envelope-scanner.ts src/cose/headers.ts
  src/cose/index.ts
  src/internal/bytes.ts src/internal/chunk-framer.ts src/internal/keys.ts
  src/internal/web-crypto.ts
  src/range/decrypt.ts src/range/index.ts src/range/inspect.ts
  src/range/plan.ts src/range/source.ts
  src/recipients/a256kw.ts src/recipients/index.ts src/recipients/info.ts
  src/recipients/prepare.ts src/recipients/recover.ts src/recipients/types.ts
)

log() { printf '>> %s\n' "$*"; }

# fetch_via_git fetches only the pinned commit (the monorepo is large), then
# copies the package source into the vendor dir. Returns non-zero if git is
# unavailable or the fetch fails (e.g. behind a proxy that blocks git), so the
# caller can fall back to raw.
fetch_via_git() {
  command -v git >/dev/null 2>&1 || return 1
  local tmp
  tmp="$(mktemp -d)"
  if git -C "$tmp" init --quiet &&
    git -C "$tmp" fetch --quiet --depth 1 "$REF_REPO" "$REF_SHA" 2>/dev/null &&
    git -C "$tmp" -c advice.detachedHead=false checkout --quiet FETCH_HEAD 2>/dev/null; then
    rm -rf "$VENDOR"
    mkdir -p "$VENDOR"
    cp -R "$tmp/$PKG_SUBDIR/src" "$VENDOR/"
    rm -rf "$tmp"
    return 0
  fi
  rm -rf "$tmp"
  return 1
}

# fetch_via_raw pulls the individual pinned source files over HTTPS. This works
# in environments whose egress allows raw.githubusercontent.com but not git.
fetch_via_raw() {
  command -v curl >/dev/null 2>&1 || {
    echo "error: need git or curl to fetch the reference source" >&2
    exit 1
  }
  local base="https://raw.githubusercontent.com/FilOzone/synapse-sdk/$REF_SHA/$PKG_SUBDIR"
  rm -rf "$VENDOR"
  local f
  for f in "${SRC_FILES[@]}"; do
    mkdir -p "$VENDOR/$(dirname "$f")"
    curl -fsSL "$base/$f" -o "$VENDOR/$f"
  done
}

log "vendoring filecoin-encryption-envelope @ ${REF_SHA:0:12}"
if fetch_via_git; then
  log "source obtained via git"
else
  log "git fetch unavailable; falling back to raw file fetch"
  fetch_via_raw
  log "source obtained via raw.githubusercontent.com"
fi

command -v node >/dev/null 2>&1 || {
  echo "error: Node 22.18 or later is required to run the TS reference" >&2
  exit 1
}

log "installing the reference's dependencies (cborg, zod)"
(cd "$TS_DIR" && npm install --silent --no-package-lock --no-audit --no-fund)

log "running the filecoin-encryption-envelope driver"
(cd "$TS_DIR" && node driver.ts "${1:-all}")
