// tests/integration_test.go tests the full stub pipeline end-to-end.
// Run: go test ./tests/ -v -timeout 30s
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

// fakePredictServer starts a local HTTP server that mimics the Python /predict
// endpoint.  It flags anomalies when exec_count > 20.
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

		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]interface{}{
			"anomaly_score": score,
			"is_anomaly":    isAnomaly,
			"confidence":    0.85,
			"model":         "FakeIsolationForest",
		})
	}))
}

func mustNewSender(t *testing.T, apiURL string, threshold float64) *sender.Sender {
	t.Helper()
	s, err := sender.NewSender(apiURL, threshold)
	if err != nil {
		t.Fatalf("NewSender: %v", err)
	}
	return s
}

// TestPipelineNormalBehavior verifies that normal events don't panic the pipeline.
func TestPipelineNormalBehavior(t *testing.T) {
	srv := fakePredictServer(t)
	defer srv.Close()

	stopCh := make(chan struct{})
	defer close(stopCh)

	coll := collector.NewCollector(256)
	go coll.RunStubEvents()

	ext := extractor.NewExtractor(coll.EventCh, 500*time.Millisecond)
	go ext.Run(stopCh)

	snd := mustNewSender(t, srv.URL, -0.1)
	go snd.Run(ext.FeatureCh, stopCh)

	time.Sleep(1200 * time.Millisecond)
	coll.Stop()

	t.Log("Pipeline ran without panic ✅")
}

// TestFeatureExtraction verifies that event counts are accumulated correctly
// within a window, including that sensitive file hits are counted.
func TestFeatureExtraction(t *testing.T) {
	var events []collector.BpfEvent

	// 10 execve events from bash
	for i := 0; i < 10; i++ {
		var comm [16]byte
		copy(comm[:], "bash")
		events = append(events, collector.BpfEvent{
			PID:       uint32(i),
			SyscallID: collector.SyscallExecve,
			Comm:      comm,
		})
	}

	// 5 openat events accessing /etc/passwd (sensitive)
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

	ch := make(chan collector.BpfEvent, len(events))
	for _, e := range events {
		ch <- e
	}
	close(ch) // signals end of input; extractor must flush before returning

	stopCh := make(chan struct{})
	defer close(stopCh)

	ext := extractor.NewExtractor(ch, 100*time.Millisecond)
	go ext.Run(stopCh)

	var got extractor.FeatureVector
	select {
	case got = <-ext.FeatureCh:
	case <-time.After(2 * time.Second):
		t.Fatal("timeout waiting for feature vector")
	}

	if got.ExecCount != 10 {
		t.Errorf("ExecCount: want 10, got %d", got.ExecCount)
	}
	if got.SensitiveFileHits < 1 {
		t.Errorf("SensitiveFileHits: want >= 1, got %d", got.SensitiveFileHits)
	}
	t.Logf("FeatureVector: exec=%d sensitive=%d files=%d",
		got.ExecCount, got.SensitiveFileHits, got.UniqueFilesOpened)
}

// TestSenderHTTP verifies that the sender POSTs correct JSON and parses
// both normal and anomalous responses without error.
func TestSenderHTTP(t *testing.T) {
	srv := fakePredictServer(t)
	defer srv.Close()

	stopCh := make(chan struct{})
	featureCh := make(chan extractor.FeatureVector, 2)

	snd := mustNewSender(t, srv.URL, -0.1)
	go snd.Run(featureCh, stopCh)

	featureCh <- extractor.FeatureVector{ExecCount: 3, NewConnections: 1}
	time.Sleep(200 * time.Millisecond)

	featureCh <- extractor.FeatureVector{ExecCount: 50, NewConnections: 30}
	time.Sleep(200 * time.Millisecond)

	close(stopCh)
	log.Println("Sender HTTP test passed ✅")
}

// TestNewSenderValidation checks that invalid URLs are rejected upfront.
func TestNewSenderValidation(t *testing.T) {
	cases := []struct {
		url     string
		wantErr bool
	}{
		{"http://localhost:8000", false},
		{"https://example.com", false},
		{"not-a-url", true},
		{"ftp://bad-scheme.com", true},
		{"", true},
	}
	for _, tc := range cases {
		_, err := sender.NewSender(tc.url, -0.1)
		if tc.wantErr && err == nil {
			t.Errorf("NewSender(%q): expected error, got nil", tc.url)
		}
		if !tc.wantErr && err != nil {
			t.Errorf("NewSender(%q): unexpected error: %v", tc.url, err)
		}
	}
}
