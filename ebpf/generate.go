// ============================================================
// ebpf/generate.go
// Tells `go generate` how to compile sentinel.bpf.c into a Go
// file using bpf2go (cilium's code generator).
//
// Prerequisites:
//   go install github.com/cilium/ebpf/cmd/bpf2go@latest
//   sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)
//   bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
//
// Run:
//   cd ebpf && go generate
//
// This produces sentinel_bpf_{x86,arm64,...}.go + sentinel_bpf_{...}.o
// which are embedded into the Go binary at compile time.
// ============================================================

package ebpf

//go:generate go run github.com/cilium/ebpf/cmd/bpf2go -cc clang -cflags "-O2 -g -Wall -D__TARGET_ARCH_x86" sentinel sentinel.bpf.c -- -I/usr/include/bpf -I.
