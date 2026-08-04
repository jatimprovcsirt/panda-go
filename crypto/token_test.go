package crypto

import (
	"errors"
	"os"
	"testing"
)

func TestTokenValidator(t *testing.T) {
	// Set test mode to skip online validation during unit tests
	os.Setenv("PANDA_SKIP_ONLINE_VALIDATION", "1")
	defer os.Unsetenv("PANDA_SKIP_ONLINE_VALIDATION")
	t.Run("DemoToken", func(t *testing.T) {
		if !IsDemoToken(DEMO_TOKEN) {
			t.Errorf("Expected IsDemoToken(%q) to be true", DEMO_TOKEN)
		}
		if err := ValidateToken(DEMO_TOKEN); err != nil {
			t.Errorf("Expected DEMO_TOKEN to be valid, got: %v", err)
		}
	})

	t.Run("LiveToken", func(t *testing.T) {
		liveToken := "panda_live_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2"
		if IsDemoToken(liveToken) {
			t.Errorf("Expected IsDemoToken(%q) to be false", liveToken)
		}
		if err := ValidateToken(liveToken); err != nil {
			t.Errorf("Expected liveToken to be valid, got: %v", err)
		}
	})

	t.Run("LiveToken64Chars", func(t *testing.T) {
		liveToken64 := "panda_live_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be276d08573d453cdbd"
		if IsDemoToken(liveToken64) {
			t.Errorf("Expected IsDemoToken(%q) to be false", liveToken64)
		}
		if err := ValidateToken(liveToken64); err != nil {
			t.Errorf("Expected 64-char liveToken to be valid, got: %v", err)
		}
	})

	t.Run("EmptyToken", func(t *testing.T) {
		err := ValidateToken("")
		if err == nil {
			t.Error("Expected empty token validation to fail")
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Expected error to wrap ErrInvalidToken, got: %v", err)
		}
	})

	t.Run("MalformedToken", func(t *testing.T) {
		err := ValidateToken("invalid_token_123")
		if err == nil {
			t.Error("Expected malformed token validation to fail")
		}
		if !errors.Is(err, ErrInvalidToken) {
			t.Errorf("Expected error to wrap ErrInvalidToken, got: %v", err)
		}
	})

	t.Run("InvalidHexToken", func(t *testing.T) {
		err := ValidateToken("panda_live_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4beG")
		if err == nil {
			t.Error("Expected token with non-hex char to fail validation")
		}
	})
}
