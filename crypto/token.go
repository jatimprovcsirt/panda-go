package crypto

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"time"
)

// TOKEN_PATTERN is the regex pattern for a valid PANDA access token.
// Format: panda_(demo|live)_<48 or 64 hex characters>
const TOKEN_PATTERN = `^panda_(demo|live)_([a-f0-9]{48}|[a-f0-9]{64})$`

// DEMO_TOKEN is the static demo token shipped in .env.example and documentation.
const DEMO_TOKEN = "panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2"

// DEFAULT_VALIDATION_URL is the production portal validation endpoint.
const DEFAULT_VALIDATION_URL = "https://csirt.jatimprov.go.id/panda/api/v1/tokens/validate"

var tokenRegexp = regexp.MustCompile(TOKEN_PATTERN)

// ValidateTokenRequest is the request payload for token validation.
type ValidateTokenRequest struct {
	Token string `json:"token"`
}

// ValidateTokenResponse is the response from the portal validation endpoint.
type ValidateTokenResponse struct {
	Valid           bool   `json:"valid"`
	ApplicationID   string `json:"applicationId,omitempty"`
	OrganizationID  string `json:"organizationId,omitempty"`
	Reason          string `json:"reason,omitempty"`
}

// getValidationURL returns the validation URL from environment or default.
func getValidationURL() string {
	if url := os.Getenv("PANDA_VALIDATION_URL"); url != "" {
		return url
	}
	return DEFAULT_VALIDATION_URL
}

// skipOnlineValidation returns true if online validation should be skipped (test mode).
func skipOnlineValidation() bool {
	return os.Getenv("PANDA_SKIP_ONLINE_VALIDATION") == "1"
}

// validateTokenOnline performs a synchronous HTTPS call to validate the token
// against the PANDA portal. This is blocking and fail-closed.
func validateTokenOnline(token string) error {
	req := ValidateTokenRequest{Token: token}
	bodyBytes, err := json.Marshal(req)
	if err != nil {
		return fmt.Errorf("failed to encode validation request: %w", err)
	}

	client := &http.Client{
		Timeout: 5 * time.Second,
	}

	resp, err := client.Post(getValidationURL(), "application/json", bytes.NewBuffer(bodyBytes))
	if err != nil {
		return fmt.Errorf("%w: Unable to reach the PANDA portal for token validation. Please check your network connection and try again.", ErrInvalidToken)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: PANDA portal returned unexpected status code %d. Please try again later.", ErrInvalidToken, resp.StatusCode)
	}

	var result ValidateTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return fmt.Errorf("%w: Failed to parse portal response. Please try again later.", ErrInvalidToken)
	}

	if !result.Valid {
		switch result.Reason {
		case "revoked":
			return fmt.Errorf("%w: The provided token has been revoked by the portal administrator.", ErrInvalidToken)
		case "already_activated":
			return fmt.Errorf("%w: The provided token has already been used. Each token can only be activated once.", ErrInvalidToken)
		default:
			return fmt.Errorf("%w: The provided token is invalid or not recognized by the PANDA portal.", ErrInvalidToken)
		}
	}

	return nil
}

// ValidateToken checks if the given access token meets the required format
// and validates it against the PANDA portal (except for the demo token).
//
// The demo token skips online validation entirely. All other tokens require
// a successful portal validation check before key generation is allowed.
func ValidateToken(token string) error {
	if token == "" {
		return fmt.Errorf("%w: A valid PANDA access token is required to initialize a new application.\n"+
			"Provide it via --token <value> or the PANDA_ACCESS_TOKEN environment variable.\n"+
			"Register your application at the PANDA portal to obtain a token,\n"+
			"or use the demo token for local development (see .env.example).", ErrInvalidToken)
	}

	if !tokenRegexp.MatchString(token) {
		gotText := token
		if len(gotText) > 20 {
			gotText = gotText[:20] + "..."
		}
		return fmt.Errorf("%w: The provided token does not match the expected format.\n"+
			"Expected: panda_(demo|live)_<48 or 64 hex characters>\n"+
			"Got: %s", ErrInvalidToken, gotText)
	}

	// Demo token skips all online validation - no HTTP call is ever made.
	if IsDemoToken(token) {
		return nil
	}

	// Test mode: skip online validation when PANDA_SKIP_ONLINE_VALIDATION=1
	if skipOnlineValidation() {
		return nil
	}

	// For non-demo tokens, perform online validation.
	// This is blocking and fail-closed — if it fails, init refuses to generate a key.
	if err := validateTokenOnline(token); err != nil {
		return err
	}

	return nil
}

// ValidateTokenFormat reports whether the token is well-formed.
//
// Distinct from ValidateToken: that one consults the portal and returns an
// error. This one answers a question about the string — the CLI wizard needs
// that answer to decide whether to warn about what the user typed.
//
// It exists because the wizard compiled its own regexp with the pattern
// written out again, and that copy accepted 48 hex characters where this
// package accepts 48 or 64. A token the rest of the tool considers valid was
// rejected in exactly one place.
func ValidateTokenFormat(token string) bool {
	return tokenRegexp.MatchString(token)
}

// IsDemoToken checks if the given token is the static demo token.
func IsDemoToken(token string) bool {
	return token == DEMO_TOKEN
}

// IsLocalEnvironment checks whether the current environment appears to be a local/dev environment.
// Used to determine whether to warn about demo token usage.
func IsLocalEnvironment() bool {
	env := os.Getenv("APP_ENV")
	nodeEnv := os.Getenv("NODE_ENV")
	if env == "production" || nodeEnv == "production" {
		return false
	}
	return true
}
