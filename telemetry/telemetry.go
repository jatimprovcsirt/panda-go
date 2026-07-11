package telemetry

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"log"
	"net/http"
	"os"
	"time"
)

const (
	DemoToken    = "panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2"
	TelemetryURL = "https://portal.panda.gov.id/api/telemetry"
)

// TelemetryClient handles fail-silent ongoing telemetry reporting (FR-14, FR-16).
//
// IMPORTANT: This client handles ONGOING telemetry only — it is opt-out via
// PANDA_TELEMETRY_DISABLED=1, and always fails silently without blocking
// encrypt/decrypt operations.
//
// The init-time token gate (FR-28/FR-29) is a SEPARATE mechanism implemented
// in ValidateToken and the CLI init command. It is mandatory, fail-closed, and
// NOT affected by the PANDA_TELEMETRY_DISABLED flag. See Technical PRD
// Section 14 (comparison table) for the deliberate separation.
type TelemetryClient struct {
	disabled bool
}

func NewTelemetryClient() *TelemetryClient {
	// This opt-out flag governs ONLY this ongoing telemetry client.
	// It has NO effect on the mandatory init-time token gate (FR-28).
	disabled := os.Getenv("PANDA_TELEMETRY_DISABLED") == "1" || os.Getenv("PANDA_TELEMETRY_DISABLED") == "true"
	return &TelemetryClient{
		disabled: disabled,
	}
}

type payload struct {
	Token          string `json:"token"`
	KeyFingerprint string `json:"keyFingerprint"`
	SDKVersion     string `json:"sdkVersion"`
	Language       string `json:"language"`
}

func (c *TelemetryClient) Report(token string, keyBytes []byte, sdkVersion string) {
	if c.disabled {
		return
	}

	if token == DemoToken {
		isLocal := os.Getenv("NODE_ENV") != "production" && os.Getenv("APP_ENV") != "production"
		// If running locally, don't flood warnings. Otherwise print warning.
		if !isLocal {
			log.Println("⚠️ PANDA WARNING: The static DEMO TOKEN is being used outside a local development environment. Please register your agency to get a live token!")
		}
	}

	// Run fail-silently (asynchronously or inside a deferred block with recover)
	go func() {
		defer func() {
			if r := recover(); r != nil {
				// Prevent crashes from panic
			}
		}()

		h := sha256.New()
		h.Write(keyBytes)
		fingerprint := hex.EncodeToString(h.Sum(nil))

		p := payload{
			Token:          token,
			KeyFingerprint: fingerprint,
			SDKVersion:     sdkVersion,
			Language:       "go",
		}

		bodyBytes, err := json.Marshal(p)
		if err != nil {
			return
		}

		client := &http.Client{
			Timeout: 2 * time.Second, // Hard 2-second timeout
		}

		resp, err := client.Post(TelemetryURL, "application/json", bytes.NewBuffer(bodyBytes))
		if err != nil {
			return
		}
		defer resp.Body.Close()
	}()
}
