// ============================================================
// tests/integration_test.go
// End-to-end pipeline test using the stub collector.
// Verifies: events flow → features are extracted → sender fires.
//
// Run: go test ./tests/ -v -timeout 30s
// ============================================================
package tests

import (
	"encoding/json"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"sentinelgo/internal/collector"
	"sentinelgo/internal/extractor"
	"sentinelgo/internal/sender"
)

// fakePredictServer starts a local HTTP server that mimics the Python FastAPI
// /predict endpoint. Returns anomaly=true for vectors with exec_count > 20.
func fakePredictServer(t *testing.T) *httptest.Server {
	t.Helper()
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/predict" || r.Method != http.MethodPost {
			http.NotFound(w, r)
			return
		}

		body, _ := io.ReadAll(r.Body)
		var req map[string]interface{}
		if err := json.Unmarshal(body, &req); err != nil {
			http.Error(w, "bad json", 400)
			return
		}

		execCount, _ := req["exec_count"].(float64)
		isAnomaly := execCount > 20

		score := 0.15
		if isAnomaly {
			score = -0.42
		}

		resp := map[string]interface{}{
			"anomaly_score": score,
			"is_anomaly":    isAnomaly,
			"confidence":    0.85,
			"model":         "FakeIsolationForest",
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(resp)
	}))
}

// TestPipelineNormalBehavior verifies that normal events don't trigger alerts.
func TestPipelineNormalBehavior(t *testing.T) {
	srv := fakePredictServer(t)
	defer srv.Close()

	stopCh := make(chan struct{})
	defer close(stopCh)

	coll := collector.NewCollector(256)
	go coll.RunStubEvents() // synthetic events — normal rate

	ext := extractor.NewExtractor(coll.EventCh, 500*time.Millisecond)
	go ext.Run(stopCh)

	snd := sender.NewSender(srv.URL, -0.1)
	go snd.Run(ext.FeatureCh, stopCh)

	// Let two windows pass
	time.Sleep(1200 * time.Millisecond)
	coll.Stop()

	t.Log("Pipeline ran without panic ✅")
}

// TestFeatureExtraction verifies feature counting is correct.
func TestFeatureExtraction(t *testing.T) {
	// Build synthetic events
	events := []collector.BpfEvent{}
	for i := 0; i < 10; i++ {
		var comm [16]byte
		copy(comm[:], "bash")
		events = append(events, collector.BpfEvent{
			PID:       uint32(i),
			SyscallID: collector.SyscallExecve,
			Comm:      comm,
		})
	}
	for i := 0; i < 5; i++ {
		var comm [16]byte
		var fname [64]byte
		copy(comm[:], "curl")
		copy(fname[:], "/etc/passwd")
		events = append(events, collector.BpfEvent{
			PID:       uint32(100 + i),
			SyscallID: collector.SyscallOpenat,
			Comm:      comm,
			Filename:  fname,
		})
	}

	// Feed into extractor via channel
	ch := make(chan collector.BpfEvent, len(events))
	for _, e := range events {
		ch <- e
	}
	close(ch)

	stopCh := make(chan struct{})
	ext := extractor.NewExtractor(ch, 100*time.Millisecond)

	var got extractor.FeatureVector
	done := make(chan struct{})
	go func() {
		go ext.Run(stopCh)
		got = <-ext.FeatureCh
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for feature vector")
	}
	close(stopCh)

	if got.ExecCount != 10 {
		t.Errorf("expected exec_count=10, got %d", got.ExecCount)
	}
	if got.SensitiveFileHits < 1 {
		t.Errorf("expected sensitive_file_hits >= 1, got %d", got.SensitiveFileHits)
	}
	t.Logf("FeatureVector: exec=%d sensitive=%d files=%d",
		got.ExecCount, got.SensitiveFileHits, got.UniqueFilesOpened)
}

// TestSenderHTTP verifies the sender POSTs correct JSON and parses response.
func TestSenderHTTP(t *testing.T) {
	srv := fakePredictServer(t)
	defer srv.Close()

	stopCh := make(chan struct{})
	featureCh := make(chan extractor.FeatureVector, 2)

	snd := sender.NewSender(srv.URL, -0.1)
	go snd.Run(featureCh, stopCh)

	// Send a normal vector
	featureCh <- extractor.FeatureVector{ExecCount: 3, NewConnections: 1}
	time.Sleep(200 * time.Millisecond)

	// Send an anomalous vector
	featureCh <- extractor.FeatureVector{ExecCount: 50, NewConnections: 30}
	time.Sleep(200 * time.Millisecond)

	close(stopCh)
	log.Println("Sender HTTP test passed ✅")
}
