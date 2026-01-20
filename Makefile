BIN_DIR := bin

# Version information
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

# Ldflags for version injection
LDFLAGS := -s -w \
	-X github.com/denisvmedia/go-mitmproxy/version.Version=$(VERSION) \
	-X github.com/denisvmedia/go-mitmproxy/version.Commit=$(COMMIT) \
	-X github.com/denisvmedia/go-mitmproxy/version.Date=$(DATE)

all: mitmproxy

.PHONY: mitmproxy
mitmproxy:
	mkdir -p $(BIN_DIR)
	go build -ldflags="$(LDFLAGS)" -o $(BIN_DIR)/go-mitmproxy cmd/go-mitmproxy/*.go

.PHONY: dummycert
dummycert:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/dummycert cmd/dummycert/main.go

.PHONY: clean
clean:
	rm -rf $(BIN_DIR)

# add -race to check data race
# add -count=1 to disable test cache
.PHONY: test
test:
	go test ./... -v

.PHONY: dev
dev:
	go run $(shell ls cmd/go-mitmproxy/*.go | grep -v _test.go)

.PHONY: lint-go
lint-go:
	golangci-lint run --timeout=30m ./...

.PHONY: lint-go-fix
lint-go-fix:
	golangci-lint run --fix --timeout=30m ./...
