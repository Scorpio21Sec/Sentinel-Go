// ============================================================
// topic5_features/main.go
// TOPIC 5 MINI-TASK — Feature Extraction in Go
//
// Accepts fake events, computes a FeatureVector, and prints JSON.
// Run: go run topic5_features/main.go
// ============================================================
package main

import (
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

type Event struct {
	ProcessName string
	Syscall     string
	Timestamp   int64
}

type FeatureVector struct {
	ExecCount     int `json:"exec_count"`
	UniqueProcs   int `json:"unique_procs"`
	OpenCount     int `json:"open_count"`
	ConnectCount  int `json:"connect_count"`
	SensitiveHits int `json:"sensitive_file_hits"`
}

var sensitivePaths = []string{"/etc/passwd", "/etc/shadow", "/root/", "/home/", "/.ssh/"}

func isSensitive(filename string) bool {
	for _, p := range sensitivePaths {
		if strings.HasPrefix(filename, p) {
			return true
		}
	}
	return false
}

// extract computes a FeatureVector from a slice of events.
func extract(events []Event) FeatureVector {
	procs := make(map[string]struct{})
	fv := FeatureVector{}

	for _, e := range events {
		procs[e.ProcessName] = struct{}{}
		switch e.Syscall {
		case "execve":
			fv.ExecCount++
		case "openat":
			fv.OpenCount++
			// For demo: if process name looks like a sensitive read, count it
			if isSensitive("/etc/passwd") {
				fv.SensitiveHits++ // in real code this comes from e.Filename
			}
		case "connect":
			fv.ConnectCount++
		}
	}

	fv.UniqueProcs = len(procs)
	return fv
}

func main() {
	now := time.Now().UnixNano()

	// Fake events — in real SentinelGo these come from eBPF
	events := []Event{
		{"bash", "execve", now},
		{"bash", "execve", now + 100},
		{"curl", "connect", now + 200},
		{"python3", "execve", now + 300},
		{"cat", "openat", now + 400},
		{"bash", "execve", now + 500},
		{"nmap", "connect", now + 600},
		{"wget", "connect", now + 700},
	}

	fv := extract(events)

	b, _ := json.MarshalIndent(fv, "", "  ")
	fmt.Println("=== Feature Vector ===")
	fmt.Println(string(b))
}
