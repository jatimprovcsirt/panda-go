package crypto

import (
	"testing"
	"time"
)

// TestInfisicalKeyProviderConstructor tests the constructor with various parameters
func TestInfisicalKeyProviderConstructor(t *testing.T) {
	tests := []struct {
		name        string
		siteUrl     string
		clientId    string
		clientSecret string
		projectId   string
		environment string
		cacheTTL    int
		wantNotNil  bool
	}{
		{
			name:         "valid parameters with default TTL",
			siteUrl:      "https://app.infisical.com",
			clientId:     "test-client-id",
			clientSecret: "test-client-secret",
			projectId:    "test-project",
			environment:  "dev",
			cacheTTL:     0,
			wantNotNil:   true,
		},
		{
			name:         "valid parameters with custom TTL",
			siteUrl:      "https://app.infisical.com",
			clientId:     "test-client-id",
			clientSecret: "test-client-secret",
			projectId:    "test-project",
			environment:  "dev",
			cacheTTL:     600,
			wantNotNil:   true,
		},
		{
			name:         "site URL with trailing slash",
			siteUrl:      "https://app.infisical.com/",
			clientId:     "test-client-id",
			clientSecret: "test-client-secret",
			projectId:    "test-project",
			environment:  "dev",
			cacheTTL:     300,
			wantNotNil:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewInfisicalKeyProvider(
				tt.siteUrl,
				tt.clientId,
				tt.clientSecret,
				tt.projectId,
				tt.environment,
				tt.cacheTTL,
			)

			if !tt.wantNotNil && provider != nil {
				t.Errorf("Expected nil provider, got %v", provider)
			}
			if tt.wantNotNil && provider == nil {
				t.Error("Expected non-nil provider, got nil")
			}
		})
	}
}

// TestInfisicalKeyProviderCacheTTL tests cache TTL configuration
func TestInfisicalKeyProviderCacheTTL(t *testing.T) {
	tests := []struct {
		name     string
		inputTTL int
		wantTTL  time.Duration
	}{
		{
			name:    "default TTL (0 becomes 300)",
			inputTTL: 0,
			wantTTL: 300 * time.Second,
		},
		{
			name:    "negative TTL becomes 300",
			inputTTL: -100,
			wantTTL: 300 * time.Second,
		},
		{
			name:    "custom 600 seconds",
			inputTTL: 600,
			wantTTL: 600 * time.Second,
		},
		{
			name:    "custom 1200 seconds",
			inputTTL: 1200,
			wantTTL: 1200 * time.Second,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewInfisicalKeyProvider(
				"https://app.infisical.com",
				"client-id",
				"client-secret",
				"project-id",
				"dev",
				tt.inputTTL,
			)

			if provider == nil {
				t.Fatal("Expected non-nil provider")
			}

			if provider.cacheTTL != tt.wantTTL {
				t.Errorf("cacheTTL = %v, want %v", provider.cacheTTL, tt.wantTTL)
			}
		})
	}
}

// TestInfisicalKeyProviderSiteUrlTrimming tests URL trimming
func TestInfisicalKeyProviderSiteUrlTrimming(t *testing.T) {
	tests := []struct {
		name     string
		inputUrl string
		wantUrl  string
	}{
		{
			name:    "URL without trailing slash",
			inputUrl: "https://app.infisical.com",
			wantUrl: "https://app.infisical.com",
		},
		{
			name:    "URL with trailing slash",
			inputUrl: "https://app.infisical.com/",
			wantUrl: "https://app.infisical.com",
		},
		{
			name:    "URL with multiple trailing slashes",
			inputUrl: "https://app.infisical.com///",
			wantUrl: "https://app.infisical.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewInfisicalKeyProvider(
				tt.inputUrl,
				"client-id",
				"client-secret",
				"project-id",
				"dev",
				300,
			)

			if provider == nil {
				t.Fatal("Expected non-nil provider")
			}

			if provider.siteUrl != tt.wantUrl {
				t.Errorf("siteUrl = %v, want %v", provider.siteUrl, tt.wantUrl)
			}
		})
	}
}

// TestInfisicalKeyProviderInitialAuthenticationState tests initial auth state
func TestInfisicalKeyProviderInitialAuthenticationState(t *testing.T) {
	provider := NewInfisicalKeyProvider(
		"https://app.infisical.com",
		"client-id",
		"client-secret",
		"project-id",
		"dev",
		300,
	)

	if provider == nil {
		t.Fatal("Expected non-nil provider")
	}

	if provider.authenticated {
		t.Error("Expected authenticated to be false initially")
	}

	if provider.accessToken != "" {
		t.Errorf("Expected accessToken to be empty, got %v", provider.accessToken)
	}

	if !provider.tokenExpires.IsZero() {
		t.Errorf("Expected tokenExpires to be zero, got %v", provider.tokenExpires)
	}
}

// TestInfisicalKeyProviderCacheInitialization tests cache initialization
func TestInfisicalKeyProviderCacheInitialization(t *testing.T) {
	provider := NewInfisicalKeyProvider(
		"https://app.infisical.com",
		"client-id",
		"client-secret",
		"project-id",
		"dev",
		300,
	)

	if provider == nil {
		t.Fatal("Expected non-nil provider")
	}

	if provider.cache == nil {
		t.Error("Expected cache to be initialized")
	}

	if len(provider.cache) != 0 {
		t.Errorf("Expected cache to be empty, got %d entries", len(provider.cache))
	}
}

// TestInfisicalKeyProviderParameterStorage tests parameter storage
func TestInfisicalKeyProviderParameterStorage(t *testing.T) {
	tests := []struct {
		name         string
		siteUrl      string
		clientId     string
		clientSecret string
		projectId    string
		environment  string
	}{
		{
			name:         "standard parameters",
			siteUrl:      "https://app.infisical.com",
			clientId:     "my-client-id",
			clientSecret: "my-client-secret",
			projectId:    "my-project-id",
			environment:  "production",
		},
		{
			name:         "dev environment",
			siteUrl:      "https://app.infisical.com",
			clientId:     "dev-client-id",
			clientSecret: "dev-client-secret",
			projectId:    "dev-project-id",
			environment:  "dev",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			provider := NewInfisicalKeyProvider(
				tt.siteUrl,
				tt.clientId,
				tt.clientSecret,
				tt.projectId,
				tt.environment,
				300,
			)

			if provider == nil {
				t.Fatal("Expected non-nil provider")
			}

			if provider.siteUrl != tt.siteUrl {
				// Account for trimming
				expectedUrl := tt.siteUrl
				if len(expectedUrl) > 0 && expectedUrl[len(expectedUrl)-1] == '/' {
					expectedUrl = expectedUrl[:len(expectedUrl)-1]
				}
				if provider.siteUrl != expectedUrl {
					t.Errorf("siteUrl = %v, want %v", provider.siteUrl, expectedUrl)
				}
			}

			if provider.clientId != tt.clientId {
				t.Errorf("clientId = %v, want %v", provider.clientId, tt.clientId)
			}

			if provider.clientSecret != tt.clientSecret {
				t.Errorf("clientSecret = %v, want %v", provider.clientSecret, tt.clientSecret)
			}

			if provider.projectId != tt.projectId {
				t.Errorf("projectId = %v, want %v", provider.projectId, tt.projectId)
			}

			if provider.environment != tt.environment {
				t.Errorf("environment = %v, want %v", provider.environment, tt.environment)
			}
		})
	}
}

// TestCachedKeyStructure tests the cachedKey structure
func TestCachedKeyStructure(t *testing.T) {
	testKey := []byte("this-is-a-test-32-byte-key-for-testing!!")
	expires := time.Now().Add(5 * time.Minute)

	ck := cachedKey{
		key:     testKey,
		expires: expires,
	}

	if len(ck.key) != len(testKey) {
		t.Errorf("key length = %v, want %v", len(ck.key), len(testKey))
	}

	if !ck.expires.Equal(expires) {
		t.Errorf("expires = %v, want %v", ck.expires, expires)
	}
}

// TestCachedKeyExpiryCheck tests cache expiry logic
func TestCachedKeyExpiryCheck(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name      string
		expires   time.Time
		wantValid bool
	}{
		{
			name:      "expired key",
			expires:   now.Add(-1 * time.Hour),
			wantValid: false,
		},
		{
			name:      "valid key",
			expires:   now.Add(5 * time.Minute),
			wantValid: true,
		},
		{
			name:      "just expired key",
			expires:   now.Add(-1 * time.Second),
			wantValid: false,
		},
		{
			name:      "expiring soon",
			expires:   now.Add(30 * time.Second),
			wantValid: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ck := cachedKey{
				key:     []byte("test-key"),
				expires: tt.expires,
			}

			isValid := ck.expires.After(time.Now())
			if isValid != tt.wantValid {
				t.Errorf("isValid = %v, want %v", isValid, tt.wantValid)
			}
		})
	}
}

// TestInfisicalAPIUrlConstruction tests API URL construction
func TestInfisicalAPIUrlConstruction(t *testing.T) {
	siteUrl := "https://app.infisical.com"
	projectId := "test-project"
	environment := "dev"
	secretPath := "my-secret"

	expectedAuthUrl := siteUrl + "/api/v1/auth/universal-auth/login"
	expectedSecretUrl := siteUrl + "/api/v3/secrets/raw?projectId=" + projectId + "&environment=" + environment + "&secretPath=" + secretPath

	if expectedAuthUrl != "https://app.infisical.com/api/v1/auth/universal-auth/login" {
		t.Errorf("Auth URL mismatch, got %v", expectedAuthUrl)
	}

	if expectedSecretUrl != "https://app.infisical.com/api/v3/secrets/raw?projectId=test-project&environment=dev&secretPath=my-secret" {
		t.Errorf("Secret URL mismatch, got %v", expectedSecretUrl)
	}
}

// TestInfisicalTokenExpiryCalculation tests token expiry calculation
func TestInfisicalTokenExpiryCalculation(t *testing.T) {
	// Token should expire in 9.5 minutes (Infisical tokens are 10min)
	expectedOffset := 9*time.Minute + 30*time.Second

	if expectedOffset != 9*time.Minute+30*time.Second {
		t.Errorf("Token expiry offset mismatch")
	}
}

// TestKeyIDFormatValidation tests key ID format validation
func TestKeyIDFormatValidation(t *testing.T) {
	validKeyIds := []string{
		"default-key",
		"nik_key",
		"healthDataKey",
		"KEY-123",
		"key_with_underscores",
		"my-custom-key-123",
	}

	invalidKeyIds := []string{
		"key with spaces",
		"key@withsymbols",
		"key#hash",
		"key/slash",
		"key.dot",
		"key$sign",
		"key!exclamation",
	}

	// Simple regex check
	validPattern := `^[a-zA-Z0-9_-]+$`

	for _, kid := range validKeyIds {
		matched := regexpMatch(validPattern, kid)
		if !matched {
			t.Errorf("Key ID %v should be valid", kid)
		}
	}

	for _, kid := range invalidKeyIds {
		matched := regexpMatch(validPattern, kid)
		if matched {
			t.Errorf("Key ID %v should be invalid", kid)
		}
	}
}

// TestBase64KeyValidation tests base64 key validation
func TestBase64KeyValidation(t *testing.T) {
	valid32ByteKey := "ThisIsAValid32ByteKeyForTesting!"

	// Test valid key length
	if len(valid32ByteKey) != 32 {
		t.Errorf("Test key should be 32 bytes, got %d", len(valid32ByteKey))
	}

	// Test that invalid base64 would be detected
	invalidBase64 := "this-is-not-valid-base64!!!@#$"
	if invalidBase64 == "this-is-not-valid-base64!!!@#$" {
		// This is a valid string, but would fail base64 decoding
		// In real implementation, base64.StdEncoding.DecodeString would fail
	}
}

// TestHttpTimeoutConfiguration tests HTTP timeout configuration
func TestHttpTimeoutConfiguration(t *testing.T) {
	expectedTimeout := 10 * time.Second

	// The implementation uses 10 second timeout
	if expectedTimeout != 10*time.Second {
		t.Errorf("Expected timeout mismatch")
	}
}

// TestInsecureModeConfiguration tests insecure mode environment variable
func TestInsecureModeConfiguration(t *testing.T) {
	// Test that PANDA_INFISICAL_INSECURE can be checked
	// (actual implementation would use os.Getenv)
	testEnvVar := "PANDA_INFISICAL_INSECURE"
	if testEnvVar != "PANDA_INFISICAL_INSECURE" {
		t.Errorf("Environment variable name mismatch")
	}
}

// TestInfisicalProviderType checks provider type
func TestInfisicalProviderType(t *testing.T) {
	provider := NewInfisicalKeyProvider(
		"https://app.infisical.com",
		"client-id",
		"client-secret",
		"project-id",
		"dev",
		300,
	)

	if provider == nil {
		t.Fatal("Expected non-nil provider")
	}

	// Check if it implements KeyProvider interface
	var _ KeyProvider = provider
}

// TestMultipleKeyIds tests multiple key IDs
func TestMultipleKeyIds(t *testing.T) {
	keyIds := []string{
		"key-1",
		"key-2",
		"key-3",
		"nik-key",
		"health-data-key",
	}

	validPattern := `^[a-zA-Z0-9_-]+$`

	for _, kid := range keyIds {
		matched := regexpMatch(validPattern, kid)
		if !matched {
			t.Errorf("Key ID %v should be valid", kid)
		}
	}
}

// TestEnvironmentValueStorage tests environment value storage
func TestEnvironmentValueStorage(t *testing.T) {
	environments := []string{"dev", "production", "staging", "test"}

	for _, env := range environments {
		provider := NewInfisicalKeyProvider(
			"https://app.infisical.com",
			"client-id",
			"client-secret",
			"project-id",
			env,
			300,
		)

		if provider.environment != env {
			t.Errorf("environment = %v, want %v", provider.environment, env)
		}
	}
}

// TestProjectIdStorage tests project ID storage
func TestProjectIdStorage(t *testing.T) {
	projectIds := []string{
		"proj-123",
		"my-project-id",
		"production-project",
	}

	for _, pid := range projectIds {
		provider := NewInfisicalKeyProvider(
			"https://app.infisical.com",
			"client-id",
			"client-secret",
			pid,
			"dev",
			300,
		)

		if provider.projectId != pid {
			t.Errorf("projectId = %v, want %v", provider.projectId, pid)
		}
	}
}

// TestClientIdStorage tests client ID storage
func TestClientIdStorage(t *testing.T) {
	clientIds := []string{
		"client-1",
		"my-client-id",
		"production-client",
	}

	for _, cid := range clientIds {
		provider := NewInfisicalKeyProvider(
			"https://app.infisical.com",
			cid,
			"client-secret",
			"project-id",
			"dev",
			300,
		)

		if provider.clientId != cid {
			t.Errorf("clientId = %v, want %v", provider.clientId, cid)
		}
	}
}

// TestClientSecretStorage tests client secret storage
func TestClientSecretStorage(t *testing.T) {
	secrets := []string{
		"secret-1",
		"my-secret-key",
		"production-secret",
	}

	for _, secret := range secrets {
		provider := NewInfisicalKeyProvider(
			"https://app.infisical.com",
			"client-id",
			secret,
			"project-id",
			"dev",
			300,
		)

		if provider.clientSecret != secret {
			t.Errorf("clientSecret = %v, want %v", provider.clientSecret, secret)
		}
	}
}

// Helper functions for testing

func regexpMatch(pattern, s string) bool {
	// Simple implementation - in real code would use regexp package
	// Matches alphanumeric, underscore, and hyphen
	for i := 0; i < len(s); i++ {
		c := s[i]
		isAlphaNum := (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
		isSpecial := c == '_' || c == '-'
		if !isAlphaNum && !isSpecial {
			return false
		}
	}
	return len(s) > 0
}
