# SentinelGo

**OS-level behavioural anomaly detector** — eBPF + Go + Python Isolation Forest

> Built as a research project targeting IIT Madras Centre for Cybersecurity Trust and Reliability.

---

## What it does

SentinelGo hooks into Linux kernel syscalls via eBPF tracepoints to watch every process execution, file open, and network connection on the host.  A Go pipeline aggregates those raw events into 5-second behavioural windows and ships the resulting feature vector to a small Python server running an Isolation Forest model.  When the model sees activity that deviates from the learned baseline it prints a colour-coded alert to the terminal.

The design goal is **zero labelled data required**: the model learns what *normal* looks like on the target machine and flags deviations, rather than matching against a signature database.

## Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Linux Kernel                         │
│                                                         │
│  execve ──┐                                             │
│  openat ──┤── eBPF tracepoints ──► Ring Buffer          │
│  connect ─┤      (C / BPF)                              │
│  clone  ──┘                                             │
└─────────────────────┬───────────────────────────────────┘
                      │ BpfEvent (binary, little-endian)
                      ▼
┌─────────────────────────────────────────────────────────┐
│                   Go Pipeline                           │
│                                                         │
│  Collector ──► chan(512) ──► Extractor ──► chan(20)      │
│  (ring-buf                  (5 s window)  FeatureVector │
│   reader)                                     │         │
│                                      HTTP POST ▼        │
└─────────────────────────────────────────────────────────┘
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
├── cmd/sentinel/         # main binary
├── internal/
│   ├── collector/        # eBPF loader + ring-buffer reader + stub
│   ├── extractor/        # 5-second window feature aggregation
│   └── sender/           # HTTP client + alert renderer
├── ebpf/
│   └── sentinel.bpf.c    # eBPF C program (syscall hooks)
├── ml/
│   ├── server.py                    # FastAPI + Isolation Forest
│   ├── collect_baseline.py          # baseline retraining helper
│   ├── topic6_isolation_forest.py   # standalone ML demo
│   └── requirements.txt
├── netsentry/
│   └── netsentry.py      # network-level anomaly detector (Scapy)
├── scripts/
│   └── simulate_attack.sh  # demo attack simulator
├── tests/
│   └── integration_test.go # end-to-end pipeline tests (no kernel needed)
├── topic1_basics/        # Go basics demo
├── topic2_concurrency/   # goroutine pipeline demo
├── topic5_features/      # feature extraction demo
├── topic7_http/          # Go ↔ Python HTTP demo
└── go.mod
```

## Quick Start

### 1. Start the Python ML server

```bash
cd ml
pip install -r requirements.txt
python server.py
# Trains on synthetic normal data at startup; ready in ~2 s
```

### 2. Run the Go pipeline (stub mode — no kernel required)

```bash
go build ./cmd/sentinel
./sentinel --stub --api=http://localhost:8000
```

### 3. Real eBPF mode (Linux kernel 5.8+, requires root)

```bash
# Install build deps (Ubuntu 22.04)
sudo apt install clang llvm libbpf-dev linux-headers-$(uname -r)

# Generate vmlinux.h for your running kernel
bpftool btf dump file /sys/kernel/btf/vmlinux format c > ebpf/vmlinux.h

# Compile the eBPF object
clang -O2 -g -Wall -target bpf \
  -D__TARGET_ARCH_x86 \
  -I/usr/include/bpf \
  -c ebpf/sentinel.bpf.c -o ebpf/sentinel.bpf.o

# Run (needs CAP_BPF / root)
go build ./cmd/sentinel
sudo ./sentinel --ebpf-obj=./ebpf/sentinel.bpf.o
```

### 4. Trigger a demo alert

In a second terminal while SentinelGo is running:

```bash
bash scripts/simulate_attack.sh
```

### 5. Run tests (no kernel, no Python needed)

```bash
go test ./tests/ -v -timeout 30s
```

## Features extracted per window

| Feature | What it counts | Malware signal |
|---|---|---|
| `exec_count` | execve calls | process injection, malware spawning |
| `fork_rate` | clone/fork calls | fork bombs, rapid replication |
| `unique_procs` | distinct process names | unusual binaries running |
| `unique_files_opened` | distinct file paths opened | ransomware file enumeration |
| `sensitive_file_hits` | opens of `/etc/`, `/root/`, `.ssh/`, `/proc/`, `/sys/` | credential harvesting |
| `total_open_calls` | raw openat count | bulk file scanning |
| `new_connections` | connect() calls | C2 callback, data exfiltration |

## Running the mini-task demos

```bash
go run topic1_basics/main.go       # event struct + JSON
go run topic2_concurrency/main.go  # goroutine producer/consumer
go run topic5_features/main.go     # feature extraction
go run topic7_http/main.go         # Go → Python HTTP call

python ml/topic6_isolation_forest.py  # standalone Isolation Forest demo
python netsentry/netsentry.py --stub  # NetSentry network monitor (stub)
```

## Why eBPF?

- Runs in kernel space — cannot be evaded by user-space rootkits
- Microsecond precision — catches short-lived malicious processes that polling `/proc` would miss
- No kernel module required — safe, verified by the kernel verifier
- Negligible overhead for non-matching events

## Why Isolation Forest?

- **Unsupervised** — no labelled malware samples required; learns a normal baseline
- Handles high-dimensional feature vectors without per-feature thresholds
- Fast: O(n log n) training, O(log n) inference
- Decision scores are interpretable: a score of −0.3 means "moderately anomalous"

## Design trade-offs and limitations

- **Synthetic training data**: the ML server trains on generated normal-behaviour data by default.  On a real deployment you should run `ml/collect_baseline.py` for 10–30 minutes on a quiet system and retrain via `POST /retrain`, otherwise the false-positive rate will be higher.
- **Fixed window size**: the 5-second window is a reasonable default for interactive workloads but may be too coarse for very short attack bursts (< 1 s).  The `--window` flag lets you tune this.
- **Feature set**: only four syscall families are hooked (`execve`, `openat`, `connect`, `clone`).  Encrypted exfiltration over an existing connection, for example, will not raise `new_connections > threshold`.
- **Single host**: there is no aggregation layer; each host runs its own model with its own baseline.
- **Python dependency**: the anomaly scoring requires the FastAPI server to be reachable.  If the server is down, events are still collected locally but no alerts fire.
- **Root / CAP_BPF required**: real eBPF mode needs elevated privileges.  The `--stub` flag works without root for development and CI.

## Next steps

- [ ] Persist collected feature vectors to disk so the model can be retrained across restarts
- [ ] Add eBPF hook for `write` to catch in-memory exfiltration
- [ ] Structured JSON log output (instead of plain `log.Printf`) for SIEM integration
- [ ] Prometheus metrics endpoint for `total_predictions`, `anomaly_rate`, etc.
- [ ] Multi-host aggregation / central alert collector

## License

MIT

