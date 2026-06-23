#!/usr/bin/env sh
set -eu

if [ "$#" -eq 0 ]; then
  exec mise run dev-check
fi

for path in "$@"; do
  case "$path" in
    .github/workflows/*|mise.toml)
      exec mise run verify
      ;;
    internal/*|ida/*|cmd/*|proto/*|scripts/*|go.mod|go.sum)
      exec mise run dev-check
      ;;
    python/*)
      exec mise run verify
      ;;
  esac
done

exec mise run dev-check
