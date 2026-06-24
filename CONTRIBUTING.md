# Contributing to IDA Pilot

Thanks for your interest. This is a Go server + Python worker that exposes IDA Pro
analysis over MCP. Most of the test suite runs **without** an IDA Pro license.

## Development setup

Toolchains are pinned with [mise](https://mise.jdx.dev/) (`mise.toml`):

```bash
mise install            # Go 1.25 + Python 3.12 (the CI-blessed versions)
pip install -r python/requirements.txt          # runtime deps
pip install -r python/requirements-test.txt     # test deps (no IDA needed)
go build -o bin/ida-pilot ./cmd/ida-pilot
```

Go 1.25+ and Python 3.10+ are the supported floor; CI pins 3.12 via mise. IDA Pro
9.0+ with idalib is only needed to actually open binaries at runtime — not to
build or to run the unit/mock suites.

## Build, test, and the local gates

The canonical developer suites live in `mise.toml`:

```bash
mise run dev-check    # fast loop: go test ./internal/... ./ida/...
mise run verify       # release gate: go vet + go test -count=1 + consistency.sh
mise run affected     # picks dev-check vs verify based on changed paths
```

Direct equivalents, if you prefer:

```bash
go vet ./...
go test ./internal/... ./ida/...                 # Go unit + transport tests (mock workers)
python -m pytest python/tests/ -v                # Python mock tests (no IDA)
bash ./scripts/consistency.sh                    # cross-file constant consistency (Git Bash/WSL on Windows)
```

`TestMCPToolGoldens` requires a real IDA worker surface and is skipped by the
local gates — don't worry if you can't run it.

## Before opening a PR

- Run `mise run verify` (or at least `go vet`, the Go tests, the Python tests, and
  `consistency.sh`) and make sure it's green.
- Keep `consistency.yaml`-tracked constants (port `17300`, timeout `240`, page
  limits `1000`/`10000`) in sync across `server.go`, `README.md`, and scripts.
- If you change `.github/workflows/verify.yml`, keep it passing `mise run ci-parity`
  (it must still run `mise run verify` with a MinGW surface and the mise action).
- Match the surrounding style. The architecture, handler signature, error
  protocol, and caching conventions are documented in
  [`CLAUDE.md`](CLAUDE.md) / [`AGENTS.md`](AGENTS.md) — read the "Key patterns"
  and "Conventions" sections before adding handlers.

## Protobuf changes

RPC contracts live in `proto/ida/worker/v1/service.proto`. After editing, run
`make proto` (requires `protoc`) to regenerate the Go stubs (`ida/worker/v1/`) and
Python stubs (`python/worker/gen/`). Commit the generated code with your change.

## Security-relevant changes

If your change touches the HTTP surface, path handling, `py_eval`, or the
allowlist, re-read the [Security model](README.md#%EF%B8%8F-security-model--read-before-exposing-the-port)
and keep the defaults safe (loopback bind, `py_eval` off, allowlist honored). For
reporting vulnerabilities, see [SECURITY.md](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
project's [MIT License](LICENSE).
