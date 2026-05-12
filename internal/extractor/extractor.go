// Package extractor aggregates raw BpfEvents into fixed-time-window
// FeatureVectors that the ML model can consume.
package extractor

import (
	"log"
	"math"
	"strings"
	"time"

	"sentinelgo/internal/collector"
)

// FeatureVector is the numerical summary of system activity over one time
// window. Field order must match FeatureVector.ToSlice() and the Python
// server's FEATURE_NAMES list.
type FeatureVector struct {
	ExecCount         int `json:"exec_count"`          // execve calls (new processes)
	ForkRate          int `json:"fork_rate"`           // clone/fork calls
	UniqueProcs       int `json:"unique_procs"`        // distinct process names seen
	UniqueFilesOpened int `json:"unique_files_opened"` // distinct file paths opened
	SensitiveFileHits int `json:"sensitive_file_hits"` // opens hitting /etc/, /root/, .ssh/, etc.
	TotalOpenCalls    int `json:"total_open_calls"`    // raw openat count
	NewConnections    int `json:"new_connections"`     // connect() calls

	WindowStart time.Time `json:"window_start"`
	WindowEnd   time.Time `json:"window_end"`
}

// ToSlice converts the feature vector to a float64 slice for scikit-learn.
func (f *FeatureVector) ToSlice() []float64 {
	return []float64{
		float64(f.ExecCount),
		float64(f.ForkRate),
		float64(f.UniqueProcs),
		float64(f.UniqueFilesOpened),
		float64(f.SensitiveFileHits),
		float64(f.TotalOpenCalls),
		float64(f.NewConnections),
	}
}

// AnomalyScore is the normalised "weirdness" score for quick display.
// (computed locally before sending to Python for a sanity check)
func (f *FeatureVector) LocalHeuristicScore() float64 {
	score := 0.0
	if f.ExecCount > 20 {
		score += math.Min(float64(f.ExecCount)/20.0, 3.0)
	}
	if f.SensitiveFileHits > 5 {
		score += math.Min(float64(f.SensitiveFileHits)/5.0, 3.0)
	}
	if f.NewConnections > 10 {
		score += math.Min(float64(f.NewConnections)/10.0, 3.0)
	}
	if f.ForkRate > 15 {
		score += math.Min(float64(f.ForkRate)/15.0, 3.0)
	}
	return score
}

// Extractor aggregates events into feature windows.
type Extractor struct {
	WindowDuration time.Duration
	FeatureCh      chan FeatureVector
	inputCh        <-chan collector.BpfEvent
}

// NewExtractor wires the extractor to the collector's event channel.
func NewExtractor(input <-chan collector.BpfEvent, window time.Duration) *Extractor {
	return &Extractor{
		WindowDuration: window,
		FeatureCh:      make(chan FeatureVector, 20),
		inputCh:        input,
	}
}

// Run starts the extraction loop. Call in a separate goroutine.
// It closes FeatureCh when it returns, so downstream consumers
// can use a range loop and detect shutdown naturally.
func (ex *Extractor) Run(stopCh <-chan struct{}) {
	ticker := time.NewTicker(ex.WindowDuration)
	defer ticker.Stop()
	defer close(ex.FeatureCh)

	var (
		execCount     int
		forkRate      int
		openCount     int
		connectCount  int
		sensitiveHits int
		uniqueProcs   = make(map[string]struct{})
		uniqueFiles   = make(map[string]struct{})
		windowStart   = time.Now()
	)

	flush := func() {
		fv := FeatureVector{
			ExecCount:         execCount,
			ForkRate:          forkRate,
			UniqueProcs:       len(uniqueProcs),
			UniqueFilesOpened: len(uniqueFiles),
			SensitiveFileHits: sensitiveHits,
			TotalOpenCalls:    openCount,
			NewConnections:    connectCount,
			WindowStart:       windowStart,
			WindowEnd:         time.Now(),
		}
		log.Printf("[extractor] window %s → exec=%d fork=%d files=%d sensitive=%d net=%d",
			fv.WindowEnd.Format("15:04:05"),
			fv.ExecCount, fv.ForkRate, fv.UniqueFilesOpened,
			fv.SensitiveFileHits, fv.NewConnections)
		select {
		case ex.FeatureCh <- fv:
		default:
			log.Println("[extractor] feature channel full — dropping window")
		}
	}

	reset := func() {
		execCount = 0
		forkRate = 0
		openCount = 0
		connectCount = 0
		sensitiveHits = 0
		uniqueProcs = make(map[string]struct{})
		uniqueFiles = make(map[string]struct{})
		windowStart = time.Now()
	}

	for {
		select {
		case <-stopCh:
			return

		case evt, ok := <-ex.inputCh:
			if !ok {
				// Input closed — flush whatever we have before returning so
				// callers don't lose the last partial window.
				flush()
				return
			}
			proc := evt.ProcessName()
			file := evt.FilePath()
			uniqueProcs[proc] = struct{}{}

			switch evt.SyscallID {
			case collector.SyscallExecve:
				execCount++
			case collector.SyscallOpenat:
				openCount++
				if file != "" {
					uniqueFiles[file] = struct{}{}
					if isSensitive(file) {
						sensitiveHits++
					}
				}
			case collector.SyscallConnect:
				connectCount++
			case collector.SyscallClone:
				forkRate++
			}

		case <-ticker.C:
			flush()
			reset()
		}
	}
}

// isSensitive reports whether the path touches a high-value target
// (credential files, home dirs, kernel interfaces).
func isSensitive(path string) bool {
	for _, prefix := range collector.SensitivePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
