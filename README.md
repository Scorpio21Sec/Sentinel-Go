# SentinelGo 🛡️

**OS-Level AI Security System** — eBPF + Go + Python Isolation Forest

> Built as a research project targeting IIT Madras Centre for Cybersecurity Trust and Reliability.

---

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Linux Kernel                         │
│                                                         │
│  execve ──┐                                             │
│  openat ──┤── eBPF tracepoints ──► Ring Buffer          │
│  connect ─┤      (C/BPF)                                │
│  clone  ──┘                                             │
└─────────────────────┬───────────────────────────────────┘
                      │ BpfEvent (binary)
                      ▼
┌─────────────────────────────────────────────────────────┐
│                   Go Pipeline                           │
│                                                         │
│  Collector ──► channel ──► Extractor ──► channel        │
│  (ring buf        (buf=512)   (5s window)    (buf=20)   │
│   reader)                                               │
│                                          FeatureVector  │
│                                               │         │
│                                    HTTP POST ▼         │
└────────────────────────────────────────────────────────┘
                                               │
                                               ▼
┌─────────────────────────────────────────────────────────┐
│                  Python FastAPI                         │
│                                                         │
│  POST /predict ──► IsolationForest.predict()            │
│                         │                               │
│                         ▼                               │
│              {"anomaly_score": -0.35,                   │
│               "is_anomaly": true}                       │
└─────────────────────────────────────────────────────────┘
                          │
                          ▼
                    🚨 ALERT printed to terminal
```

## Repository Structure

```
sentinelgo/
├── cmd/sentinel/         # Main Go binary entry point
├── internal/
│   ├── collector/        # eBPF loader + ring buffer reader
│   ├── extractor/        # Feature extraction (5s windows)
│   └── sender/           # HTTP client + alert display
├── ebpf/
│   └── sentinel.bpf.c    # eBPF C program (syscall hooks)
├── ml/
│   ├── server.py         # FastAPI + Isolation Forest server
│   ├── topic6_isolation_forest.py  # standalone ML demo
│   └── requirements.txt
├── netsentry/
│   └── netsentry.py      # Network-level anomaly detector (Scapy)
├── scripts/
│   └── simulate_attack.sh  # Demo attack simulator
├── topic1_basics/        # Topic 1 mini-task
├── topic2_concurrency/   # Topic 2 mini-task
├── topic5_features/      # Topic 5 mini-task
├── topic7_http/          # Topic 7 mini-task
└── go.mod
```

## Quick Start

### 1. Python ML Server

```bash
cd ml
pip install -r requirements.txt
python server.py
# Server running on http://localhost:8000
# Auto-trains on synthetic normal data at startup
```

### 2. Go Pipeline (stub mode — no kernel required)

```bash
go build ./cmd/sentinel
sudo ./sentinel --stub --api=http://localhost:8000
```

### 3. Real eBPF Mode (Linux kernel 5.8+)

```bash
# Install build deps (Ubuntu 22.04)
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r) linux-tools-common

# Generate vmlinux.h for your kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# Compile eBPF object
clang -O2 -g -Wall -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/bpf \
  -c ebpf/sentinel.bpf.c -o ebpf/sentinel.bpf.o

# Run
go build ./cmd/sentinel
sudo ./sentinel --ebpf-obj=./ebpf/sentinel.bpf.o
```

### 4. Trigger an Alert (Demo)

In a second terminal while SentinelGo is running:

```bash
bash scripts/simulate_attack.sh
```

You should see a red alert box in the SentinelGo terminal.

## Features Extracted

| Feature | Description | Malware Signal |
|---|---|---|
| `exec_count` | New processes per window | Process injection, malware spawning |
| `fork_rate` | clone/fork calls | Fork bombs, rapid replication |
| `unique_procs` | Distinct process names | Unusual binaries executing |
| `unique_files_opened` | Distinct files accessed | Ransomware file enumeration |
| `sensitive_file_hits` | Accesses to `/etc/`, `/root/`, `.ssh/` | Credential harvesting |
| `total_open_calls` | Raw openat count | Bulk file scanning |
| `new_connections` | Outbound connect() calls | C2 callback, exfiltration |

## Running Mini-Tasks

```bash
# Topic 1 — Go basics
go run topic1_basics/main.go

# Topic 2 — Goroutines + channels
go run topic2_concurrency/main.go

# Topic 5 — Feature extraction
go run topic5_features/main.go

# Topic 6 — Isolation Forest standalone (Python)
python ml/topic6_isolation_forest.py

# Topic 7 — Go HTTP → Python test (server must be running)
go run topic7_http/main.go

# Topic 8 — NetSentry (stub mode)
python netsentry/netsentry.py --stub
```

## Why eBPF?

- Runs in kernel space — cannot be evaded by userspace rootkits
- Microsecond precision — catches short-lived malicious processes
- No kernel module required — safe, verified by kernel verifier
- Zero overhead for non-matching events

## Why Isolation Forest?

- **Unsupervised** — no labelled malware samples needed
- Learns normal behaviour, flags deviations
- Handles high-dimensional feature vectors efficiently
- Interpretable: each feature contribution can be examined
- Fast: O(n log n) training, O(log n) inference

## Interview Quick Reference

**"Explain your project in 30 seconds"**
> SentinelGo hooks into Linux kernel syscalls via eBPF to capture every process execution, file access, and network connection. A Go pipeline aggregates these into behavioural feature vectors every 5 seconds and ships them to a Python server running Isolation Forest. The model learns what normal looks like and alerts on deviations — in real time, at the kernel level, with no labelled training data required.

**"Why not just poll /proc?"**
> eBPF catches every event in microseconds. Polling /proc misses short-lived processes, introduces latency, and can be fooled by processes that hide themselves from the /proc filesystem.

## License

MIT
