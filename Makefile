# ============================================================
# Makefile — SentinelGo build system
#
# Targets:
#   make all        — build everything (eBPF + Go binary)
#   make ebpf       — compile eBPF C → .o object only
#   make go         — build Go binary (requires ebpf step first)
#   make run-stub   — run in stub mode (no kernel required)
#   make ml         — install Python deps + start FastAPI server
#   make test       — run all mini-task programs
#   make clean      — remove build artifacts
# ============================================================

KERNEL_HEADERS := /usr/include/bpf
KERNEL_VERSION := $(shell uname -r)
ARCH           := x86
BPF_TARGET     := bpf
BPF_SRC        := ebpf/sentinel.bpf.c
BPF_OBJ        := ebpf/sentinel.bpf.o
BINARY         := sentinel

CLANG_FLAGS := \
	-O2 -g -Wall \
	-target $(BPF_TARGET) \
	-D__TARGET_ARCH_$(ARCH) \
	-I$(KERNEL_HEADERS) \
	-I/usr/include

.PHONY: all ebpf go run-stub ml test clean fmt vmlinux

# ── Build everything ─────────────────────────────────────────
all: ebpf go

# ── Generate vmlinux.h for your running kernel ───────────────
vmlinux:
	@echo "Generating ebpf/vmlinux.h for kernel $(KERNEL_VERSION)..."
	bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h
	@echo "Done: ebpf/vmlinux.h"

# ── Compile eBPF C → BPF bytecode object ─────────────────────
ebpf: $(BPF_OBJ)

$(BPF_OBJ): $(BPF_SRC) ebpf/vmlinux.h
	@echo "Compiling eBPF program..."
	clang $(CLANG_FLAGS) -c $(BPF_SRC) -o $(BPF_OBJ)
	@echo "✅ $(BPF_OBJ)"

# ── Build Go binary ───────────────────────────────────────────
go:
	@echo "Building Go binary..."
	go build -o $(BINARY) ./cmd/sentinel
	@echo "✅ ./$(BINARY)"

# ── Run in stub mode (no eBPF or root required) ───────────────
run-stub:
	go run ./cmd/sentinel --stub --api=http://localhost:8000

# ── Run with real eBPF (requires root + kernel 5.8+) ─────────
run:
	sudo ./$(BINARY) --ebpf-obj=$(BPF_OBJ)

# ── Python ML server ─────────────────────────────────────────
ml-install:
	pip install -r ml/requirements.txt

ml-server:
	python ml/server.py

# ── Run all mini-tasks (verifies each topic) ─────────────────
test:
	@echo "\n=== Topic 1: Go Basics ==="
	go run topic1_basics/main.go

	@echo "\n=== Topic 2: Goroutines & Channels ==="
	go run topic2_concurrency/main.go

	@echo "\n=== Topic 5: Feature Extraction ==="
	go run topic5_features/main.go

	@echo "\n=== Topic 6: Isolation Forest (Python) ==="
	python ml/topic6_isolation_forest.py

	@echo "\nAll mini-tasks passed ✅"

# ── Format Go code ───────────────────────────────────────────
fmt:
	gofmt -w .

# ── Tidy Go modules ──────────────────────────────────────────
tidy:
	go mod tidy

# ── Clean build artifacts ────────────────────────────────────
clean:
	rm -f $(BPF_OBJ) $(BINARY)
	find . -name "sentinel_bpf_*.go" -delete
	find . -name "*.o" -not -path "./.git/*" -delete
	@echo "Clean."

# ── Attack simulation ─────────────────────────────────────────
attack:
	@echo "Running attack simulation (watch SentinelGo terminal for alerts)..."
	bash scripts/simulate_attack.sh
