package crypto

import (
	"encoding/json"
	"fmt"
)

type Envelope struct {
	V          int    `json:"v"`
	Alg        string `json:"alg"`
	Kid        string `json:"kid"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

func ParseEnvelope(jsonStr string) (Envelope, error) {
	var env Envelope
	if err := json.Unmarshal([]byte(jsonStr), &env); err != nil {
		return env, fmt.Errorf("%w: invalid JSON envelope", ErrMalformedEnvelope)
	}

	if env.V == 0 || env.Alg == "" || env.Kid == "" || env.Nonce == "" || env.Ciphertext == "" {
		return env, fmt.Errorf("%w: missing required envelope fields", ErrMalformedEnvelope)
	}

	return env, nil
}

func (e Envelope) ToJSON() (string, error) {
	// Simple struct marshalling maps to standard JSON formatting
	bytes, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(bytes), nil
}
