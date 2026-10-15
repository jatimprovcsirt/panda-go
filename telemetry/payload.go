package telemetry

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// The telemetry payloads, as pinned in panda-spec/telemetry-format.md.
//
// Separate from the client that sends them, and pure, so the format can be
// checked without a portal. `verify_interop.js` section 11 gives every SDK the
// same counters and asserts they produce the same fields.
//
// It is separate for a second reason, which is the defect it exists to
// prevent: the SDK and the portal disagreed about the field names — the SDK
// sent `keyFingerprint`/`sdkVersion`/`language` and the portal read
// `eventType`/`metadata` — and nothing noticed, because the endpoint was never
// reached. A payload built in one typed place, against a written contract, is
// a payload someone can compare against the receiver.

// Language is what this SDK calls itself in the payload.
const Language = "go"

// PortalBaseURL is the one definition every portal endpoint is derived from.
//
// This package used to carry its own literal — `https://portal.panda.gov.id`,
// a hostname that does not exist — while the token gate next door had the
// right one. Two definitions of one host is how they came apart.
const PortalBaseURL = "https://csirt.jatimprov.go.id/panda/api/v1"

// TelemetryURL is derived, never written out again.
const TelemetryURL = PortalBaseURL + "/telemetry"

// Counters are the counts since the installation's last successful report.
type Counters struct {
	Encrypts    uint64 `json:"encrypts"`
	Decrypts    uint64 `json:"decrypts"`
	DecryptsRaw uint64 `json:"decryptsRaw"`
}

// UsageInput is the vector shape as well as the argument shape, so the
// interop runner can hand a vector straight to BuildUsagePayload and the check
// tests the format rather than a translation of it.
type UsageInput struct {
	Token         string   `json:"token"`
	SDKVersion    string   `json:"sdkVersion"`
	WindowSeconds int      `json:"windowSeconds"`
	Counters      Counters `json:"counters"`
}

// usagePayload is the wire shape. Distinct from UsageInput so that a field
// added to one is not silently added to the other.
type usagePayload struct {
	EventType     string   `json:"eventType"`
	Token         string   `json:"token"`
	SDKVersion    string   `json:"sdkVersion"`
	Language      string   `json:"language"`
	WindowSeconds int      `json:"windowSeconds"`
	Counters      Counters `json:"counters"`
}

type keyPayload struct {
	EventType      string `json:"eventType"`
	Token          string `json:"token"`
	SDKVersion     string `json:"sdkVersion"`
	Language       string `json:"language"`
	KeyFingerprint string `json:"keyFingerprint"`
}

// BuildUsagePayload renders a usage report.
//
// Every counter is written, including the ones at zero. Omitting an unmoved
// counter would be indistinguishable, at the receiver, from an older SDK that
// never sent the field — and an idle installation has to be tellable from an
// out-of-date one.
func BuildUsagePayload(in UsageInput) (string, error) {
	body, err := json.Marshal(usagePayload{
		EventType:     "usage",
		Token:         in.Token,
		SDKVersion:    in.SDKVersion,
		Language:      Language,
		WindowSeconds: in.WindowSeconds,
		Counters:      in.Counters,
	})
	if err != nil {
		return "", fmt.Errorf("telemetry: build usage payload: %w", err)
	}
	return string(body), nil
}

// BuildKeyPayload renders a key report, sent once when a key is generated.
func BuildKeyPayload(token, sdkVersion string, key []byte) (string, error) {
	body, err := json.Marshal(keyPayload{
		EventType:      "key",
		Token:          token,
		SDKVersion:     sdkVersion,
		Language:       Language,
		KeyFingerprint: KeyFingerprint(key),
	})
	if err != nil {
		return "", fmt.Errorf("telemetry: build key payload: %w", err)
	}
	return string(body), nil
}

// KeyFingerprint is base64(SHA-256(key bytes)) — the bytes, not their base64
// text.
//
// Hashing the encoded form is the mistake that survives every round-trip test,
// because the implementation agrees with itself and only disagrees with the
// other three. A vector in vectors.json hashes a key whose base64 encoding is
// itself, so the two readings differ.
func KeyFingerprint(key []byte) string {
	sum := sha256.Sum256(key)
	return base64.StdEncoding.EncodeToString(sum[:])
}
