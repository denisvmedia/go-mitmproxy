BIN_DIR := bin

all: mitmproxy

.PHONY: mitmproxy
mitmproxy:
	mkdir -p $(BIN_DIR)
	go build -o $(BIN_DIR)/go-mitmproxy cmd/go-mitmproxy/*.go

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
