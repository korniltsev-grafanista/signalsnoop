.PHONY: all run clean deps setup-headers bpftrace docker docker-push docker-run

IMAGE_PREFIX ?= korniltsev/
IMAGE_TAG ?= $(shell git rev-parse --short HEAD)

CILIUM_EBPF_VERSION := v0.12.3
LIBBPF_VERSION := v1.2.0
TETRAGON_VERSION := main
HEADERS_URL := https://raw.githubusercontent.com/cilium/ebpf/$(CILIUM_EBPF_VERSION)/examples/headers
LIBBPF_URL := https://raw.githubusercontent.com/libbpf/libbpf/$(LIBBPF_VERSION)/src
TETRAGON_URL := https://raw.githubusercontent.com/cilium/tetragon/$(TETRAGON_VERSION)/bpf/include

# Source files
BPF_SOURCE := bpf/signalsnoop.c
GO_SOURCES := $(wildcard *.go)
BPF_HEADERS := $(wildcard bpf/headers/*.h)

# Generated files
GEN_X86_GO := signalsnoop_bpfel_x86.go
GEN_X86_O := signalsnoop_bpfel_x86.o
GEN_ARM64_GO := signalsnoop_bpfel_arm64.go
GEN_ARM64_O := signalsnoop_bpfel_arm64.o

# Binary outputs
BIN_AMD64 := signalsnoop-amd64
BIN_ARM64 := signalsnoop-arm64

# Default target - build static binaries for both architectures
all: $(BIN_AMD64) $(BIN_ARM64)

# Generate eBPF code using bpf2go - rebuilds if C source or headers change
$(GEN_X86_GO) $(GEN_X86_O) $(GEN_ARM64_GO) $(GEN_ARM64_O): $(BPF_SOURCE) $(BPF_HEADERS) | setup-headers
	go generate ./...

# Build static binary for amd64 - rebuilds if Go sources or generated files change
$(BIN_AMD64): $(GO_SOURCES) $(GEN_X86_GO) $(GEN_X86_O)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags='-s -w' -o $@ .

# Build static binary for arm64 - rebuilds if Go sources or generated files change
$(BIN_ARM64): $(GO_SOURCES) $(GEN_ARM64_GO) $(GEN_ARM64_O)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags='-s -w' -o $@ .

# Convenience targets
generate: $(GEN_X86_GO) $(GEN_ARM64_GO)

build: $(BIN_AMD64) $(BIN_ARM64)

build-amd64: $(BIN_AMD64)

build-arm64: $(BIN_ARM64)

# Build and run with sudo (uses native architecture)
ARCH := $(shell uname -m)
ifeq ($(ARCH),x86_64)
    BINARY := $(BIN_AMD64)
else ifeq ($(ARCH),aarch64)
    BINARY := $(BIN_ARM64)
else
    BINARY := $(BIN_AMD64)
endif

run: $(BINARY)
	sudo ./$(BINARY)

# Run the original bpftrace script for comparison
bpftrace:
	sudo bpftrace get_signal.bt

# Clean build artifacts
clean:
	rm -f signalsnoop signalsnoop-amd64 signalsnoop-arm64
	rm -f signalsnoop_bpfel.go signalsnoop_bpfel.o
	rm -f signalsnoop_bpfeb.go signalsnoop_bpfeb.o
	rm -f signalsnoop_bpfel_x86.go signalsnoop_bpfel_x86.o
	rm -f signalsnoop_bpfel_arm64.go signalsnoop_bpfel_arm64.o

# Install Go dependencies
deps:
	go mod tidy
	go install github.com/cilium/ebpf/cmd/bpf2go@latest

# Download BPF headers from cilium/ebpf, libbpf, and tetragon
setup-headers:
	@mkdir -p bpf/headers
	@if [ ! -f bpf/headers/common.h ]; then \
		echo "Downloading BPF headers from cilium/ebpf $(CILIUM_EBPF_VERSION)..."; \
		curl -sL $(HEADERS_URL)/common.h -o bpf/headers/common.h; \
		curl -sL $(HEADERS_URL)/bpf_helpers.h -o bpf/headers/bpf_helpers.h; \
		curl -sL $(HEADERS_URL)/bpf_helper_defs.h -o bpf/headers/bpf_helper_defs.h; \
		curl -sL $(HEADERS_URL)/bpf_tracing.h -o bpf/headers/bpf_tracing.h; \
		curl -sL $(HEADERS_URL)/bpf_endian.h -o bpf/headers/bpf_endian.h; \
		echo "Downloading bpf_core_read.h from libbpf $(LIBBPF_VERSION)..."; \
		curl -sL $(LIBBPF_URL)/bpf_core_read.h -o bpf/headers/bpf_core_read.h; \
		echo "Downloading vmlinux headers from tetragon $(TETRAGON_VERSION)..."; \
		curl -sL $(TETRAGON_URL)/vmlinux.h -o bpf/headers/vmlinux.h; \
		curl -sL $(TETRAGON_URL)/vmlinux_generated_x86.h -o bpf/headers/vmlinux_generated_x86.h; \
		curl -sL $(TETRAGON_URL)/vmlinux_generated_arm64.h -o bpf/headers/vmlinux_generated_arm64.h; \
		echo "Headers downloaded."; \
	fi

# Docker build for amd64 and arm64 (push to registry)
docker-push:
	docker buildx build --platform linux/amd64,linux/arm64 --push -t $(IMAGE_PREFIX)signalsnoop:$(IMAGE_TAG) -t $(IMAGE_PREFIX)signalsnoop:latest .

# Docker build for local use (current platform only, --load doesn't support multi-platform)
docker:
	docker buildx build --load -t $(IMAGE_PREFIX)signalsnoop:$(IMAGE_TAG) -t $(IMAGE_PREFIX)signalsnoop:latest .

# Build and run docker image
docker-run: docker
	docker run --rm -it --privileged $(IMAGE_PREFIX)signalsnoop:$(IMAGE_TAG)
