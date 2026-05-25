# longsocks Makefile

BINARY := longsocks
BINDIR := bin
PREFIX ?= /usr/local
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X github.com/cloudygreybeard/longsocks/cmd.Version=$(VERSION) \
	-X github.com/cloudygreybeard/longsocks/cmd.Commit=$(COMMIT) \
	-X github.com/cloudygreybeard/longsocks/cmd.Date=$(DATE)

.PHONY: all build test lint clean install snapshot image help

## all: Build the binary (default target)
all: build

## build: Build the binary into bin/
build:
	@mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(BINARY) .

## test: Run tests
test:
	go test -v -race ./...

## lint: Run linter
lint:
	golangci-lint run

## clean: Remove build artifacts
clean:
	rm -rf $(BINDIR)/
	rm -rf dist/

## install: Install to PREFIX/bin
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 755 $(BINDIR)/$(BINARY) $(DESTDIR)$(PREFIX)/bin/$(BINARY)

## image: Build a container image with podman
image: build
	podman build -f Containerfile -t ghcr.io/cloudygreybeard/longsocks:dev .

## snapshot: Build a snapshot release (no publish)
snapshot:
	goreleaser release --snapshot --clean

## deps: Download dependencies
deps:
	go mod download
	go mod tidy

## help: Show this help
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@sed -n 's/^## //p' $(MAKEFILE_LIST) | column -t -s ':'
