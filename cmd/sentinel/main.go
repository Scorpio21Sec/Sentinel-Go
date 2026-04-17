// ============================================================
// cmd/sentinel/main.go
// SentinelGo — OS-level AI security system
// Wires: eBPF collector → feature extractor → ML sender
//
// Usage:
//   sudo ./sentinel                          # real eBPF mode
//   sudo ./sentinel --stub                   # stub mode (no kernel needed)
//   sudo ./sentinel --ebpf-obj=./sentinel.bpf.o
// ============================================================
package main

import (
	"flag"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"sentinelgo/internal/collector"
	"sentinelgo/internal/extractor"
	"sentinelgo/internal/sender"
)

func main() {
	// ── CLI flags ─────────────────────────────────────────────
	stubMode   := flag.Bool("stub", false, "Use synthetic events (no real eBPF required)")
	ebpfObj    := flag.String("ebpf-obj", "./ebpf/sentinel.bpf.o", "Path to compiled eBPF object file")
	apiURL     := flag.String("api", "http://localhost:8000", "Python FastAPI base URL")
	windowSec  := flag.Int("window", 5, "Feature extraction window in seconds")
	threshold  := flag.Float64("threshold", -0.1, "Anomaly score threshold (more negative = stricter)")
	flag.Parse()

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	printBanner()

	// ── Shared stop channel ───────────────────────────────────
	stopCh := make(chan struct{})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("Shutting down…")
		close(stopCh)
	}()

	// ── Stage 1: Collector ────────────────────────────────────
	coll := collector.NewCollector(512)

	if *stubMode {
		log.Println("⚙️  Mode: STUB (synthetic events)")
		go coll.RunStubEvents()
	} else {
		log.Printf("⚙️  Mode: eBPF — loading %s", *ebpfObj)
		go func() {
			if err := coll.Run(*ebpfObj); err != nil {
				log.Fatalf("eBPF collector error: %v", err)
			}
		}()
	}

	// ── Stage 2: Feature Extractor ────────────────────────────
	window := time.Duration(*windowSec) * time.Second
	ext := extractor.NewExtractor(coll.EventCh, window)
	go ext.Run(stopCh)

	// ── Stage 3: ML Sender ────────────────────────────────────
	snd := sender.NewSender(*apiURL, *threshold)
	go snd.Run(ext.FeatureCh, stopCh)

	log.Printf("🔍 Pipeline running — window=%ds  api=%s", *windowSec, *apiURL)
	log.Println("Press Ctrl+C to stop.")

	<-stopCh
	coll.Stop()
	log.Println("Goodbye.")
}

func printBanner() {
	log.Println(`
 ___            _   _            _  ____
/ __| ___ _ __ | |_(_)_ _  ___ | |/ ___| ___
\__ \/ -_) '  \|  _| | ' \/ -_)| | |  _ / _ \
|___/\___|_|_|_|\__|_|_||_\___||_|\____|\___/

  OS-Level AI Security System
  eBPF + Go + Python Isolation Forest
`)
}
