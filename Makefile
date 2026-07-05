SHELL := /usr/bin/env bash
BIN := hpxnode
VERSION ?= dev
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build linux proto clean

# Build for the current host.
build:
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -o $(BIN) .

# Static Linux binaries (amd64 + arm64) for release.
linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags "$(LDFLAGS)" -o $(BIN)-linux-amd64 .
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags "$(LDFLAGS)" -o $(BIN)-linux-arm64 .
	@echo "built $(BIN)-linux-amd64 + $(BIN)-linux-arm64"

# Regenerate gRPC code (needs protoc + protoc-gen-go[-grpc]).
proto:
	protoc -I proto --go_out=paths=source_relative:pb --go-grpc_out=paths=source_relative:pb proto/node.proto

clean:
	rm -f $(BIN) $(BIN)-linux-*
