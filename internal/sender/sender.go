// Package sender ships FeatureVectors to the Python ML server and
// renders alerts when the model flags an anomaly.
package sender

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"time"

	"sentinelgo/internal/extractor"
)

// PredictRequest matches the Pydantic model expected by the Python server.
type PredictRequest struct {
	ExecCount         int `json:"exec_count"`
	ForkRate          int `json:"fork_rate"`
	UniqueProcs       int `json:"unique_procs"`
	UniqueFilesOpened int `json:"unique_files_opened"`
	SensitiveFileHits int `json:"sensitive_file_hits"`
	TotalOpenCalls    int `json:"total_open_calls"`
	NewConnections    int `json:"new_connections"`
}

// PredictResponse is the JSON body returned by POST /predict.
type PredictResponse struct {
	AnomalyScore float64 `json:"anomaly_score"`
	IsAnomaly    bool    `json:"is_anomaly"`
	Confidence   float64 `json:"confidence"`
	Model        string  `json:"model"`
}

// Sender ships feature vectors to the ML server and handles responses.
type Sender struct {
	apiURL    string
	threshold float64 // score below this triggers a local alert (backup to server flag)
	client    *http.Client
}

// NewSender creates a Sender targeting the given FastAPI base URL.
// Returns an error if apiURL is not a valid http/https URL.
func NewSender(apiURL string, threshold float64) (*Sender, error) {
	u, err := url.ParseRequestURI(apiURL)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, fmt.Errorf("invalid API URL %q: must be http or https", apiURL)
	}
	return &Sender{
		apiURL:    apiURL,
		threshold: threshold,
		client:    &http.Client{Timeout: 3 * time.Second},
	}, nil
}

// Run reads from featureCh and sends each vector to the ML server.
func (s *Sender) Run(featureCh <-chan extractor.FeatureVector, stopCh <-chan struct{}) {
	log.Printf("[sender] posting to %s/predict", s.apiURL)

	for {
		select {
		case <-stopCh:
			return
		case fv, ok := <-featureCh:
			if !ok {
				return
			}
			if err := s.postFeatureVector(fv); err != nil {
				log.Printf("[sender] %v", err)
			}
		}
	}
}

// postFeatureVector serialises fv, POSTs it to /predict, and handles the result.
func (s *Sender) postFeatureVector(fv extractor.FeatureVector) error {
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

	resp, err := s.client.Post(s.apiURL+"/predict", "application/json", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("POST /predict: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("server returned %d: %s", resp.StatusCode, string(b))
	}

	var pr PredictResponse
	if err := json.NewDecoder(resp.Body).Decode(&pr); err != nil {
		return fmt.Errorf("decode predict response: %w", err)
	}

	if pr.IsAnomaly {
		renderAnomalyAlert(fv, pr)
	} else {
		log.Printf("[OK]  score=%+.4f  exec=%d  fork=%d  files=%d  net=%d",
			pr.AnomalyScore, fv.ExecCount, fv.ForkRate,
			fv.UniqueFilesOpened, fv.NewConnections)
	}

	return nil
}

// renderAnomalyAlert prints a formatted alert box to stdout.
func renderAnomalyAlert(fv extractor.FeatureVector, pr PredictResponse) {
	fmt.Println()
	fmt.Println("\033[1;31m╔══════════════════════════════════════════════════════╗")
	fmt.Println("║         🚨  ANOMALY DETECTED  🚨                      ║")
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Printf("║  Anomaly Score : %-35.4f ║\n", pr.AnomalyScore)
	fmt.Printf("║  Confidence    : %-35.2f ║\n", pr.Confidence)
	fmt.Printf("║  Window        : %-35s ║\n", fv.WindowEnd.Format("15:04:05"))
	fmt.Println("╠══════════════════════════════════════════════════════╣")
	fmt.Printf("║  exec_count    : %-35d ║\n", fv.ExecCount)
	fmt.Printf("║  fork_rate     : %-35d ║\n", fv.ForkRate)
	fmt.Printf("║  unique_files  : %-35d ║\n", fv.UniqueFilesOpened)
	fmt.Printf("║  sensitive_hits: %-35d ║\n", fv.SensitiveFileHits)
	fmt.Printf("║  connections   : %-35d ║\n", fv.NewConnections)
	fmt.Println("╚══════════════════════════════════════════════════════╝\033[0m")
	fmt.Println()
}
