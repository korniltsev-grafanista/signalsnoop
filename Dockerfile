# syntax=docker/dockerfile:1

# Build stage - runs on build host platform for native speed
FROM --platform=$BUILDPLATFORM golang:1.21-bookworm AS builder

# Install clang for eBPF compilation
RUN apt-get update && apt-get install -y --no-install-recommends \
    clang \
    llvm \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download

# Copy only required source files
COPY main.go ./
COPY bpf/ ./bpf/

# Generate eBPF code (runs on build host, generates for all architectures)
RUN go generate ./...

# Target architecture from docker buildx
ARG TARGETARCH=amd64

# Build static binary for target architecture
RUN CGO_ENABLED=0 GOARCH=${TARGETARCH} go build -ldflags='-s -w' -o signalsnoop .

# Final stage - minimal image
FROM scratch

COPY --from=builder /build/signalsnoop /signalsnoop

ENTRYPOINT ["/signalsnoop"]
