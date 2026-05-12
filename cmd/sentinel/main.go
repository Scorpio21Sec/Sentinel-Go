// ============================================================
// cmd/sentinel/main.go
// Wires the eBPF collector → feature extractor → ML sender pipeline.
//
// Usage:
//
//	sudo ./sentinel                         # real eBPF mode
//	sudo ./sentinel --stub                  # no kernel required
//	sudo ./sentinel --ebpf-obj=./sentinel.bpf.o
//
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
	stubMode := flag.Bool("stub", false, "use synthetic events (no real eBPF required)")
	ebpfObj := flag.String("ebpf-obj", "./ebpf/sentinel.bpf.o", "path to compiled eBPF object file")
	apiURL := flag.String("api", "http://localhost:8000", "Python FastAPI base URL")
	windowSec := flag.Int("window", 5, "feature extraction window in seconds")
	threshold := flag.Float64("threshold", -0.1, "anomaly score threshold (more negative = stricter)")
	flag.Parse()

	if *windowSec < 1 {
		log.Fatalf("--window must be >= 1, got %d", *windowSec)
	}

	log.SetFlags(log.Ltime | log.Lmicroseconds)
	printBanner()

	stopCh := make(chan struct{})

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sig
		log.Println("shutting down…")
		close(stopCh)
	}()

	coll := collector.NewCollector(512)

	if *stubMode {
		log.Println("mode: stub (synthetic events)")
		go coll.RunStubEvents()
	} else {
		log.Printf("mode: eBPF — loading %s", *ebpfObj)
		go func() {
			if err := coll.Run(*ebpfObj); err != nil {
				log.Fatalf("eBPF collector: %v", err)
			}
		}()
	}

	window := time.Duration(*windowSec) * time.Second
	ext := extractor.NewExtractor(coll.EventCh, window)
	go ext.Run(stopCh)

	snd, err := sender.NewSender(*apiURL, *threshold)
	if err != nil {
		log.Fatalf("invalid --api flag: %v", err)
	}
	go snd.Run(ext.FeatureCh, stopCh)

	log.Printf("pipeline running — window=%ds  api=%s", *windowSec, *apiURL)
	log.Println("press Ctrl+C to stop")

	<-stopCh
	coll.Stop()
	log.Println("goodbye")
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
