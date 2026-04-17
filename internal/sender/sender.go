// ============================================================
// internal/sender/sender.go
// TOPIC 7 — Go ↔ Python FastAPI Bridge
//
// Reads FeatureVectors from the extractor channel and POSTs
// them to the Python FastAPI server. Handles alerts.
// ============================================================
package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"time"

	"sentinelgo/internal/extractor"
)

// PredictRequest matches the Pydantic model on the Python side.
type PredictRequest struct {
	ExecCount         int     `json:"exec_count"`
	ForkRate          int     `json:"fork_rate"`
	UniqueProcs       int     `json:"unique_procs"`
	UniqueFilesOpened int     `json:"unique_files_opened"`
	SensitiveFileHits int     `json:"sensitive_file_hits"`
	TotalOpenCalls    int     `json:"total_open_calls"`
	NewConnections    int     `json:"new_connections"`
}

// PredictResponse is what the Python server returns.
type PredictResponse struct {
	AnomalyScore    float64 `json:"anomaly_score"`
	IsAnomaly       bool    `json:"is_anomaly"`
	Confidence      float64 `json:"confidence"`
	Model           string  `json:"model"`
}

// Sender ships feature vectors to the ML server.
type Sender struct {
	APIURL    string
	Threshold float64 // anomaly_score below this triggers alert
	client    *http.Client
}

// NewSender creates a Sender pointed at the given FastAPI base URL.
func NewSender(apiURL string, threshold float64) *Sender {
	return &Sender{
		APIURL:    apiURL,
		Threshold: threshold,
		client: &http.Client{
			Timeout: 3 * time.Second,
		},
	}
}

// Run reads from featureCh and sends each vector to the API.
func (s *Sender) Run(featureCh <-chan extractor.FeatureVector, stopCh <-chan struct{}) {
	log.Printf("[sender] sending to %s/predict", s.APIURL)

	for {
		select {
		case <-stopCh:
			return
		case fv, ok := <-featureCh:
			if !ok {
				return
			}
			if err := s.send(fv); err != nil {
				log.Printf("[sender] ERROR: %v", err)
			}
		}
	}
}

// send serialises the feature vector, POSTs it, and handles the response.
func (s *Sender) send(fv extractor.FeatureVector) error {
	req := PredictRequest{
		ExecCount:         fv.ExecCount,
		ForkRate:          fv.ForkRate,
		UniqueProcs:       fv.UniqueProcs,
		UniqueFilesOpened: fv.UniqueFilesOpened,
		SensitiveFileHits: fv.SensitiveFileHits,
		TotalOpenCalls:    fv.TotalOpenCalls,
		NewConnections:    fv.NewConnections,
	}

	body, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("marshal feature vector: %w", err)
	}

	resp, err := s.client.Post(
		s.APIURL+"/predict",
		"application/json",
		bytes.NewReader(body),
	)
	if err != nil {
		return fmt.Errorf("POST /predict: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("API returned %d: %s", resp.StatusCode, string(b))
	}

	var pr PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return fmt.Errorf("decode response: %w", err)
	}

	// ── Alert logic ───────────────────────────────────────────
	if pr.IsAnomaly {
		printAlert(fv, pr)
	} else {
		log.Printf("[OK]     score=%.4f  exec=%d  fork=%d  files=%d  net=%d",
			pr.AnomalyScore, fv.ExecCount, fv.ForkRate,
			fv.UniqueFilesOpened, fv.NewConnections)
	}

	return nil
}

func printAlert(fv extractor.FeatureVector, pr PredictResponse) {
	// Bold red terminal output
	fmt.Println()
	fmt.Println("\033[1;31m╔══════════════════════════════════════════════════════╗")
	fmt.Println("║         🚨  ANOMALY DETECTED  🚨                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Printf( "║  Anomaly Score : %-35.4f ║\n", pr.AnomalyScore)
	fmt.Printf( "║  Confidence    : %-35.2f ║\n", pr.Confidence)
	fmt.Printf( "║  Window        : %-35s ║\n", fv.WindowEnd.Format("15:04:05"))
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Printf( "║  exec_count    : %-35d ║\n", fv.ExecCount)
	fmt.Printf( "║  fork_rate     : %-35d ║\n", fv.ForkRate)
	fmt.Printf( "║  unique_files  : %-35d ║\n", fv.UniqueFilesOpened)
	fmt.Printf( "║  sensitive_hits: %-35d ║\n", fv.SensitiveFileHits)
	fmt.Printf( "║  connections   : %-35d ║\n", fv.NewConnections)
	fmt.Println("╚══════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()
}
