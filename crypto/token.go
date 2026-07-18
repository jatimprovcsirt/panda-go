package crypto

import (
	"fmt"
	"os"
	"regexp"
)

// TOKEN_PATTERN is the regex pattern for a valid PANDA access token.
// Format: panda_(demo|live)_<48 or 64 hex characters>
const TOKEN_PATTERN = `^panda_(demo|live)_([a-f0-9]{48}|[a-f0-9]{64})$`

// DEMO_TOKEN is the static demo token shipped in .env.example and documentation.
const DEMO_TOKEN = "panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2"

var tokenRegexp = regexp.MustCompile(TOKEN_PATTERN)

// ValidateToken checks if the given access token meets the required format.
//
// Pre-portal: performs a local format check only.
// Post-portal: will additionally call the portal validation endpoint.
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

	// Pre-portal phase: format check is sufficient (Technical PRD Section 14.2).
	// Post-portal phase (Phase 6+): add live HTTPS validation call here.
	// The call would be blocking and fail-closed — if it fails, init refuses
	// to generate a key. This is the one exception to the SDK's fail-silent
	// portal interaction policy.
	return nil
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
