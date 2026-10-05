// Package bpf wraps the compiled eBPF object and exposes a small, typed API
// for the rest of the application.
package bpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -target amd64 -cflags "-O2 -g -Wall -target bpf -D__TARGET_ARCH_x86 -I ../../bpf" proxy ../../bpf/proxy.bpf.c
