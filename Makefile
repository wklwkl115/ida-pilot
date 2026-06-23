.PHONY: proto proto-check clean build test run restart integration-test inspector setup setup-idalib install-tools install-python

# Protobuf generation
proto:
	@command -v protoc >/dev/null 2>&1 || { echo "Error: protoc not found. Install protobuf (brew install protobuf on macOS)"; exit 1; }
	PATH="$(shell go env GOPATH)/bin:$${PATH}" go generate ./proto/ida/worker/v1

proto-check:
	@command -v protoc >/dev/null 2>&1 || { echo "Error: protoc not found. Install protobuf (brew install protobuf on macOS)"; exit 1; }
	PATH="$(shell go env GOPATH)/bin:$${PATH}" go generate ./proto/ida/worker/v1
	git diff --exit-code proto ida python/worker/gen

# Build server binary (proto files are committed, no need to regenerate)
build:
	go build -o bin/ida-pilot ./cmd/ida-pilot

# Fast unit tests (no IDA required)
test:
	go test -v ./internal/... ./ida/...
	@./scripts/consistency.sh

# MCP transport integration tests (mock workers, no IDA required)
integration-test:
	go test ./internal/server -run TestStreamableHTTPTransportLifecycle -v
	go test ./internal/server -run TestSSETransportLifecycle -v

# Run server
run: build
	./bin/ida-pilot

# Restart server (kill existing, rebuild, start)
restart: build
	@pkill -f 'bin/ida-pilot' 2>/dev/null || true
	@pkill -f 'python3.*ida-pilot/python/worker/server.py' 2>/dev/null || true
	@sleep 1
	./bin/ida-pilot

# Clean generated files
clean:
	rm -rf ida/worker/v1/*.pb.go
	rm -rf bin/
	find python/worker -name "*.pyc" -delete
	find python/worker -name "__pycache__" -delete

# Install Go tools
install-tools:
	go install google.golang.org/protobuf/cmd/protoc-gen-go@latest
	go install connectrpc.com/connect/cmd/protoc-gen-connect-go@latest

# Install Python dependencies
install-python:
	pip3 install -r python/requirements.txt

# Setup idalib (macOS only — see scripts/setup_idalib.sh)
setup-idalib:
	@./scripts/setup_idalib.sh

# Full setup (macOS): idalib + python deps + build
setup: setup-idalib install-python build
	@echo "Setup complete. Run: ./bin/ida-pilot"

# Start MCP Inspector for testing
inspector:
	@./scripts/inspector.sh

.DEFAULT_GOAL := build
