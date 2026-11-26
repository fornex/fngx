PKG      := github.com/fornex/fngx
CMD      := $(notdir $(wildcard cmd/*))
VERSION  ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT   ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
LDFLAGS  := -s -w -X $(PKG)/internal/product.Version=$(VERSION) -X $(PKG)/internal/product.Commit=$(COMMIT)

.PHONY: all build build-linux test lint fmt clean

all: lint test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(CMD) ./cmd/$(CMD)

# Target servers are x86_64 Linux.
build-linux:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(CMD)-linux-amd64 ./cmd/$(CMD)

test:
	go test -race -count=1 ./...

lint:
	go vet ./...
	golangci-lint run

fmt:
	gofmt -w .

clean:
	rm -rf bin
