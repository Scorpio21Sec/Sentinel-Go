// ============================================================
// TOPIC 1 MINI-TASK — Go Language Basics
// Defines an Event struct, creates a slice, loops, and flags
// suspicious syscalls.
// Run: go run topic1_basics/main.go
// ============================================================
package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// Event represents a single kernel-level event captured by eBPF.
type Event struct {
	ProcessName string `json:"process_name"`
	Syscall     string `json:"syscall"`
	Timestamp   int64  `json:"timestamp"`
}

func main() {
	now := time.Now().UnixNano()

	// Create 3 sample events (in real SentinelGo these come from eBPF).
	events := []Event{
		{ProcessName: "bash", Syscall: "execve", Timestamp: now},
		{ProcessName: "sshd", Syscall: "read", Timestamp: now + 1000},
		{ProcessName: "curl", Syscall: "connect", Timestamp: now + 2000},
	}

	fmt.Println("=== SentinelGo — Topic 1: Event Dump ===")
	for i, e := range events {
		b, _ := json.Marshal(e)
		fmt.Printf("[%d] %s", i+1, string(b))
		if e.Syscall == "execve" {
			fmt.Print("  ⚠️  suspicious!")
		}
		fmt.Println()
	}
}
