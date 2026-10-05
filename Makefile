BINARY := ebpfproxy
GO ?= go
CLANG ?= clang
BPFTOOL ?= bpftool

export CGO_ENABLED := 0
export GOFLAGS := -mod=mod

.PHONY: all build generate vmlinux clean install run

all: build

# build compiles the ebpfproxy binary. The generated eBPF bindings
# (internal/bpf/proxy_x86_bpfel.{go,o}) are committed, so a plain `make build`
# only needs Go.
build:
	$(GO) build -trimpath -ldflags "-s -w" -o $(BINARY) ./cmd/ebpfproxy

# generate regenerates the Go bindings after changing bpf/proxy.bpf.c.
# Requires clang and bpf/vmlinux.h (see the vmlinux target).
generate: bpf/vmlinux.h
	$(GO) generate ./internal/bpf

# vmlinux regenerates bpf/vmlinux.h from the running kernel BTF.
bpf/vmlinux.h:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@

clean:
	rm -f $(BINARY)
	rm -f internal/bpf/proxy_x86_bpfel.o internal/bpf/proxy_x86_bpfel.go

install: build
	install -m 0755 $(BINARY) /usr/local/bin/$(BINARY)

run: build
	./$(BINARY)
