// ============================================================
// TOPIC 2 MINI-TASK — Go Concurrency: Goroutines & Channels
// Mini-pipeline: producer goroutine → channel → consumer goroutine
// Run: go run topic2_concurrency/main.go
// ============================================================
package main

import (
	"fmt"
	"sync"
	"time"
)

type Event struct {
	ProcessName string
	Syscall     string
	Timestamp   int64
}

func main() {
	// Buffered channel — holds up to 50 events without blocking the producer.
	eventCh := make(chan Event, 50)

	var wg sync.WaitGroup

	// ── Goroutine 1: Producer ────────────────────────────────
	// Simulates eBPF emitting kernel events every 500ms.
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(eventCh) // signal consumer that we're done

		syscalls := []string{"execve", "open", "connect", "write", "read"}
		procs := []string{"bash", "curl", "python3", "ssh", "cat"}

		for i := 0; i < 10; i++ {
			e := Event{
				ProcessName: procs[i%len(procs)],
				Syscall:     syscalls[i%len(syscalls)],
				Timestamp:   time.Now().UnixNano(),
			}
			eventCh <- e
			fmt.Printf("  [producer] sent: %-8s → %s\n", e.ProcessName, e.Syscall)
			time.Sleep(500 * time.Millisecond)
		}
		fmt.Println("  [producer] done — channel closed")
	}()

	// ── Goroutine 2: Consumer ────────────────────────────────
	// Reads from the channel and processes each event.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for e := range eventCh { // range on channel exits when channel is closed
			tag := ""
			if e.Syscall == "execve" {
				tag = " ⚠️  EXEC"
			} else if e.Syscall == "connect" {
				tag = " 🌐 NET"
			}
			fmt.Printf("  [consumer] received: %-8s %-10s%s\n", e.ProcessName, e.Syscall, tag)
		}
		fmt.Println("  [consumer] channel drained — exiting")
	}()

	// ── Main: wait for both goroutines ───────────────────────
	fmt.Println("=== SentinelGo — Topic 2: Goroutine Pipeline ===")
	wg.Wait()
	fmt.Println("Pipeline complete.")
}
