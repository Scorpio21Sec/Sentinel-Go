// ============================================================
// internal/extractor/extractor.go
// TOPIC 5 — Feature Extraction
//
// Reads BpfEvents from the collector channel, aggregates them
// over a configurable time window (default 5 seconds), and
// emits a FeatureVector for the ML model.
// ============================================================
package extractor

import (
	"log"
	"math"
	"strings"
	"time"

	"sentinelgo/internal/collector"
)

// FeatureVector is the numerical representation of system behaviour
// over one time window. This is what the Isolation Forest receives.
type FeatureVector struct {
	// --- Process activity ---
	ExecCount   int `json:"exec_count"`   // # of execve calls
	ForkRate    int `json:"fork_rate"`    // # of clone/fork calls
	UniqueProcs int `json:"unique_procs"` // # of distinct process names

	// --- File activity ---
	UniqueFilesOpened   int `json:"unique_files_opened"`   // # of distinct files opened
	SensitiveFileHits   int `json:"sensitive_file_hits"`   // opens of /etc/, /root/, etc.
	TotalOpenCalls      int `json:"total_open_calls"`      // raw count of openat calls

	// --- Network activity ---
	NewConnections int `json:"new_connections"` // # of connect() calls

	// --- Metadata ---
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
func (ex *Extractor) Run(stopCh <-chan struct{}) {
	ticker := time.NewTicker(ex.WindowDuration)
	defer ticker.Stop()
	defer close(ex.FeatureCh)

	// Per-window accumulators
	var (
		execCount         int
		forkRate          int
		openCount         int
		connectCount      int
		sensitiveHits     int
		uniqueProcs       = make(map[string]struct{})
		uniqueFiles       = make(map[string]struct{})
		windowStart       = time.Now()
	)

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
				return // input channel closed
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
			// Emit feature vector for the completed window
			fv := FeatureVector{
				ExecCount:           execCount,
				ForkRate:            forkRate,
				UniqueProcs:         len(uniqueProcs),
				UniqueFilesOpened:   len(uniqueFiles),
				SensitiveFileHits:   sensitiveHits,
				TotalOpenCalls:      openCount,
				NewConnections:      connectCount,
				WindowStart:         windowStart,
				WindowEnd:           time.Now(),
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

			reset()
		}
	}
}

// isSensitive returns true if the file path matches a known sensitive prefix.
func isSensitive(path string) bool {
	for _, prefix := range collector.SensitivePrefixes {
		if strings.HasPrefix(path, prefix) {
			return true
		}
	}
	return false
}
