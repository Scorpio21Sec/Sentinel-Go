// ============================================================
// topic7_http/main.go
// TOPIC 7 MINI-TASK — Go HTTP client calling FastAPI
//
// Start the Python server first:
//   cd ml && python server.py
// Then run:
//   go run topic7_http/main.go
// ============================================================
package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"
)

type FeatureVector struct {
	ExecCount         int     `json:"exec_count"`
	ForkRate          int     `json:"fork_rate"`
	UniqueProcs       int     `json:"unique_procs"`
	UniqueFilesOpened int     `json:"unique_files_opened"`
	SensitiveFileHits int     `json:"sensitive_file_hits"`
	TotalOpenCalls    int     `json:"total_open_calls"`
	NewConnections    int     `json:"new_connections"`
}

type PredictResponse struct {
	AnomalyScore float64 `json:"anomaly_score"`
	IsAnomaly    bool    `json:"is_anomaly"`
	Confidence   float64 `json:"confidence"`
	Model        string  `json:"model"`
}

func predict(apiURL string, fv FeatureVector) (*PredictResponse, error) {
	body, err := json.Marshal(fv)
	if err != nil {
		return nil, err
	}

	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Post(apiURL+"/predict", "application/json", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("POST failed: %w", err)
	}
	defer resp.Body.Close()

	raw, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("server returned %d: %s", resp.StatusCode, raw)
	}

	var pr PredictResponse
	if err := json.Unmarshal(raw, &pr); err != nil {
		return nil, fmt.Errorf("decode response: %w", err)
	}
	return &pr, nil
}

func main() {
	apiURL := "http://localhost:8000"

	// Test vectors
	tests := []struct {
		label string
		fv    FeatureVector
	}{
		{
			"normal workstation",
			FeatureVector{2, 1, 2, 8, 0, 12, 1},
		},
		{
			"suspicious — many execs + connections",
			FeatureVector{50, 40, 20, 150, 20, 300, 35},
		},
		{
			"ransomware-like — many file opens + sensitive hits",
			FeatureVector{5, 2, 3, 300, 50, 600, 1},
		},
	}

	fmt.Println("=== Topic 7: Go ↔ Python FastAPI Bridge Test ===\n")

	for _, t := range tests {
		pr, err := predict(apiURL, t.fv)
		if err != nil {
			log.Printf("  %-40s  ERROR: %v", t.label, err)
			continue
		}

		flag := "✅ OK    "
		if pr.IsAnomaly {
			flag = "🚨 ALERT "
		}
		fmt.Printf("  %s  %-40s  score=%+.4f  conf=%.2f\n",
			flag, t.label, pr.AnomalyScore, pr.Confidence)
	}
}
