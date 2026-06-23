#!/usr/bin/env sh
set -eu

workflow=.github/workflows/verify.yml

if [ ! -f "$workflow" ]; then
  echo "missing $workflow"
  exit 1
fi

if ! grep -q 'mise run verify' "$workflow"; then
  echo "workflow does not run 'mise run verify'"
  exit 1
fi

if ! grep -q 'jdx/mise-action' "$workflow"; then
  echo "workflow does not install mise"
  exit 1
fi

if ! grep -q 'msys2/setup-msys2' "$workflow"; then
  echo "workflow does not install a MinGW linker surface"
  exit 1
fi

echo "ci parity ok: $workflow runs mise run verify with a MinGW linker surface"
