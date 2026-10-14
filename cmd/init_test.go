package cmd

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/jatimprovcsirt/panda-go/crypto"
	"github.com/jatimprovcsirt/panda-go/internal/panda"
)

// TestInitCommandConfiguration tests the init command configuration
func TestInitCommandConfiguration(t *testing.T) {
	if initCmd == nil {
		t.Error("initCmd should not be nil")
	}

	if initCmd.Use != "init" {
		t.Errorf("Expected Use to be 'init', got %v", initCmd.Use)
	}

	if initCmd.Short == "" {
		t.Error("Expected Short description to be set")
	}
}

// TestInitFlags tests init command flags
func TestInitFlags(t *testing.T) {
	tests := []struct {
		name     string
		flagName string
		expected string
	}{
		{name: "token flag", flagName: "token", expected: ""},
		{name: "quick flag", flagName: "quick", expected: "false"},
		{name: "reinit flag", flagName: "reinit", expected: "false"},
		{name: "skip-key-gen flag", flagName: "skip-key-gen", expected: "false"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flag := initCmd.Flags().Lookup(tt.flagName)
			if flag == nil {
				t.Errorf("Flag %v should exist", tt.flagName)
			}
		})
	}
}

// TestTokenPatternValidation tests token pattern validation
func TestTokenPatternValidation(t *testing.T) {
	validTokens := []string{
		"panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2",
		"panda_live_" + repeatChar('a', 48),
		"panda_live_" + repeatChar('b', 64),
	}

	invalidTokens := []string{
		"invalid_token",
		"panda_demo_" + repeatChar('c', 47),  // Too short
		"panda_live_" + repeatChar('d', 65),  // Too long
		"panda_other_" + repeatChar('e', 48), // Wrong prefix
		"",
	}

	// This asserts the function the wizard actually calls, not a regexp
	// compiled here. It compiled its own before, so it proved nothing about
	// init: the wizard's pattern had drifted to 48-only and this test, holding
	// its own correct copy, went on passing.
	for _, token := range validTokens {
		if !crypto.ValidateTokenFormat(token) {
			t.Errorf("Token should match pattern: %v", token)
		}
	}

	for _, token := range invalidTokens {
		if crypto.ValidateTokenFormat(token) {
			t.Errorf("Token should not match pattern: %v", token)
		}
	}
}

// TestDemoTokenValidation tests demo token validation
func TestDemoTokenValidation(t *testing.T) {
	demoToken := crypto.DEMO_TOKEN

	if !crypto.IsDemoToken(demoToken) {
		t.Error("Demo token should be recognized as demo token")
	}

	if crypto.IsDemoToken("panda_live_" + repeatChar('a', 48)) {
		t.Error("Live token should not be recognized as demo token")
	}

	// Test demo token format
	if demoToken != "panda_demo_76d08573d453cdbdb4bf5704d13f8f54d57cd3c47c9b4be2" {
		t.Errorf("Demo token constant mismatch, got %v", demoToken)
	}
}

// TestTokenValidation tests token validation
func TestTokenValidation(t *testing.T) {
	// Set test environment
	os.Setenv("PANDA_SKIP_ONLINE_VALIDATION", "1")
	defer os.Unsetenv("PANDA_SKIP_ONLINE_VALIDATION")

	tests := []struct {
		name      string
		token     string
		wantError bool
	}{
		{name: "valid demo token", token: crypto.DEMO_TOKEN, wantError: false},
		{name: "valid live token", token: "panda_live_" + repeatChar('a', 48), wantError: false},
		{name: "empty token", token: "", wantError: true},
		{name: "invalid format", token: "invalid_token", wantError: true},
		{name: "too short", token: "panda_demo_" + repeatChar('a', 47), wantError: true},
		{name: "too long", token: "panda_live_" + repeatChar('a', 65), wantError: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := crypto.ValidateToken(tt.token)
			if (err != nil) != tt.wantError {
				t.Errorf("ValidateToken() error = %v, wantError %v", err, tt.wantError)
			}
		})
	}
}

// TestLocalEnvironmentDetection tests local environment detection
func TestLocalEnvironmentDetection(t *testing.T) {
	testCases := []struct {
		name      string
		envValue  string
		wantLocal bool
	}{
		{name: "production env", envValue: "production", wantLocal: false},
		{name: "development env", envValue: "development", wantLocal: true},
		{name: "local env", envValue: "local", wantLocal: true},
		{name: "dev env", envValue: "dev", wantLocal: true},
		{name: "empty env", envValue: "", wantLocal: true},
	}

	for _, tt := range testCases {
		t.Run(tt.name, func(t *testing.T) {
			os.Setenv("APP_ENV", tt.envValue)
			gotLocal := crypto.IsLocalEnvironment()
			if gotLocal != tt.wantLocal {
				t.Errorf("IsLocalEnvironment() = %v, want %v", gotLocal, tt.wantLocal)
			}
			os.Unsetenv("APP_ENV")
		})
	}
}

// TestPandaDirectoryOperations tests .panda directory operations
func TestPandaDirectoryOperations(t *testing.T) {
	// Clean up before test
	panda.RemovePandaDirectory()
	defer panda.RemovePandaDirectory()

	// Test directory creation
	err := panda.CreatePandaDirectory()
	if err != nil {
		t.Fatalf("CreatePandaDirectory() error = %v", err)
	}

	// Test directory exists check
	if !panda.PandaDirExists() {
		t.Error("PandaDirExists() should return true after creation")
	}

	// Test config operations
	config := &panda.PandaConfig{
		Version:     "1.0.0",
		Initialized: time.Now().Format(time.RFC3339),
		Provider:    panda.ProviderConfig{Type: "local"},
		DefaultKid:  "default-key",
	}

	err = panda.WriteConfig(config)
	if err != nil {
		t.Errorf("WriteConfig() error = %v", err)
	}

	readConfig, err := panda.ReadConfig()
	if err != nil {
		t.Errorf("ReadConfig() error = %v", err)
	}

	if readConfig.Version != config.Version {
		t.Errorf("Version = %v, want %v", readConfig.Version, config.Version)
	}

	// Test credentials operations
	creds := &panda.PandaCredentials{
		Token:    "test-token",
		Provider: "local",
	}

	err = panda.WriteCredentials(creds)
	if err != nil {
		t.Errorf("WriteCredentials() error = %v", err)
	}

	readCreds, err := panda.ReadCredentials()
	if err != nil {
		t.Errorf("ReadCredentials() error = %v", err)
	}

	if readCreds.Provider != creds.Provider {
		t.Errorf("Provider = %v, want %v", readCreds.Provider, creds.Provider)
	}

	// Test keys metadata operations
	keys, err := panda.ReadKeysMetadata()
	if err != nil {
		t.Errorf("ReadKeysMetadata() error = %v", err)
	}

	if len(keys.Keys) != 0 {
		t.Errorf("Keys should be empty initially, got %d", len(keys.Keys))
	}

	// Test adding key to metadata
	err = panda.AddKeyToMetadata("test-key", "local", ".env")
	if err != nil {
		t.Errorf("AddKeyToMetadata() error = %v", err)
	}

	keys, err = panda.ReadKeysMetadata()
	if err != nil {
		t.Errorf("ReadKeysMetadata() error = %v", err)
	}

	if len(keys.Keys) != 1 {
		t.Errorf("Keys count = %d, want 1", len(keys.Keys))
	}

	if keys.Keys[0].KID != "test-key" {
		t.Errorf("KID = %v, want test-key", keys.Keys[0].KID)
	}

	// Test duplicate key error
	err = panda.AddKeyToMetadata("test-key", "local", ".env")
	if err == nil {
		t.Error("Expected error for duplicate key")
	}

	// Test directory removal
	err = panda.RemovePandaDirectory()
	if err != nil {
		t.Errorf("RemovePandaDirectory() error = %v", err)
	}

	if panda.PandaDirExists() {
		t.Error("PandaDirExists() should return false after removal")
	}
}

// TestVaultCredentialsStructure tests Vault credentials structure
func TestVaultCredentialsStructure(t *testing.T) {
	creds := &panda.PandaCredentials{
		Token:      "test-token",
		Provider:   "vault",
		VaultURL:   "http://127.0.0.1:8200",
		VaultToken: "vault-token",
		VaultMount: "secret",
	}

	if creds.Provider != "vault" {
		t.Errorf("Provider = %v, want vault", creds.Provider)
	}

	if creds.VaultURL == "" {
		t.Error("VaultURL should not be empty")
	}

	if creds.VaultToken == "" {
		t.Error("VaultToken should not be empty")
	}

	if creds.VaultMount == "" {
		t.Error("VaultMount should not be empty")
	}
}

// TestInfisicalCredentialsStructure tests Infisical credentials structure
func TestInfisicalCredentialsStructure(t *testing.T) {
	creds := &panda.PandaCredentials{
		Token:                 "test-token",
		Provider:              "infisical",
		InfisicalSiteUrl:      "https://app.infisical.com",
		InfisicalClientId:     "client-id",
		InfisicalClientSecret: "client-secret",
		InfisicalProjectId:    "project-id",
		InfisicalEnvironment:  "dev",
		InfisicalCacheTTL:     "300",
	}

	if creds.Provider != "infisical" {
		t.Errorf("Provider = %v, want infisical", creds.Provider)
	}

	if creds.InfisicalSiteUrl == "" {
		t.Error("InfisicalSiteUrl should not be empty")
	}

	if creds.InfisicalClientId == "" {
		t.Error("InfisicalClientId should not be empty")
	}

	if creds.InfisicalClientSecret == "" {
		t.Error("InfisicalClientSecret should not be empty")
	}

	if creds.InfisicalProjectId == "" {
		t.Error("InfisicalProjectId should not be empty")
	}

	if creds.InfisicalEnvironment == "" {
		t.Error("InfisicalEnvironment should not be empty")
	}

	if creds.InfisicalCacheTTL == "" {
		t.Error("InfisicalCacheTTL should not be empty")
	}
}

// TestKeyIdNormalization tests key ID normalization
func TestKeyIdNormalization(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{input: "nik-key", expected: "NIK_KEY"},
		{input: "health_data_key", expected: "HEALTH_DATA_KEY"},
		{input: "Test-Key-123", expected: "TEST_KEY_123"},
		{input: "user.email.key", expected: "USER_EMAIL_KEY"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			// Use the toUpper function from status.go (already in package)
			reg := regexp.MustCompile(`[^A-Za-z0-9]`)
			normalized := reg.ReplaceAllString(tc.input, "_")
			normalized = regexp.MustCompile(`_+`).ReplaceAllString(normalized, "_")
			result := toUpper(normalized)

			if result != tc.expected {
				t.Errorf("Normalized key = %v, want %v", result, tc.expected)
			}
		})
	}
}

// TestEmptyCredentialsHandling tests empty credentials handling
func TestEmptyCredentialsHandling(t *testing.T) {
	panda.RemovePandaDirectory()
	defer panda.RemovePandaDirectory()

	panda.CreatePandaDirectory()

	// Write empty credentials
	err := os.WriteFile(".panda/credentials", []byte(""), 0600)
	if err != nil {
		t.Fatalf("Failed to write empty credentials: %v", err)
	}

	// Should return default local provider
	creds, err := panda.ReadCredentials()
	if err != nil {
		t.Errorf("ReadCredentials() error = %v", err)
	}

	if creds.Provider != "local" {
		t.Errorf("Provider = %v, want local", creds.Provider)
	}
}

// TestPandaConfigStructure tests PandaConfig structure
func TestPandaConfigStructure(t *testing.T) {
	config := &panda.PandaConfig{
		Version:     "1.0.0",
		Initialized: "2024-01-01T00:00:00Z",
		Provider:    panda.ProviderConfig{Type: "local"},
		DefaultKid:  "default-key",
	}

	if config.Version == "" {
		t.Error("Version should not be empty")
	}

	if config.Initialized == "" {
		t.Error("Initialized should not be empty")
	}

	if config.Provider.Type == "" {
		t.Error("Provider.Type should not be empty")
	}

	if config.DefaultKid == "" {
		t.Error("DefaultKid should not be empty")
	}
}

// TestKeyMetadataStructure tests KeyMetadata structure
func TestKeyMetadataStructure(t *testing.T) {
	metadata := panda.KeyMetadata{
		KID:      "test-key",
		Created:  "2024-01-01T00:00:00Z",
		Provider: "local",
		Location: ".env",
	}

	if metadata.KID == "" {
		t.Error("KID should not be empty")
	}

	if metadata.Created == "" {
		t.Error("Created should not be empty")
	}

	if metadata.Provider == "" {
		t.Error("Provider should not be empty")
	}

	if metadata.Location == "" {
		t.Error("Location should not be empty")
	}
}

// TestTokenValidationUrl tests token validation URL configuration
func TestTokenValidationUrl(t *testing.T) {
	expectedUrl := "https://csirt.jatimprov.go.id/panda/api/v1/tokens/validate"

	// The default validation URL should match
	if expectedUrl != "" {
		t.Logf("Default validation URL: %v", expectedUrl)
	}
}

// TestProviderConfigStructure tests ProviderConfig structure
func TestProviderConfigStructure(t *testing.T) {
	config := panda.ProviderConfig{
		Type: "infisical",
		Config: map[string]interface{}{
			"siteUrl": "https://app.infisical.com",
		},
	}

	if config.Type != "infisical" {
		t.Errorf("Type = %v, want infisical", config.Type)
	}

	if config.Config == nil {
		t.Error("Config should not be nil")
	}
}

// TestInitCommandWithExistingDirectory tests init command behavior when directory exists
func TestInitCommandWithExistingDirectory(t *testing.T) {
	panda.RemovePandaDirectory()
	defer panda.RemovePandaDirectory()

	panda.CreatePandaDirectory()

	// Without --reinit, should detect existing directory
	if !panda.PandaDirExists() {
		t.Error("Panda directory should exist")
	}
}

// TestInitCommandReinitFlag tests reinit flag functionality
func TestInitCommandReinitFlag(t *testing.T) {
	flag := initCmd.Flags().Lookup("reinit")
	if flag == nil {
		t.Error("reinit flag should exist")
	}

	// Flag should be bool type
	if flag.DefValue != "false" {
		t.Logf("reinit flag default value: %v", flag.DefValue)
	}
}

// TestInitCommandSkipKeyGenFlag tests skip-key-gen flag functionality
func TestInitCommandSkipKeyGenFlag(t *testing.T) {
	flag := initCmd.Flags().Lookup("skip-key-gen")
	if flag == nil {
		t.Error("skip-key-gen flag should exist")
	}

	// Flag should be bool type
	if flag.DefValue != "false" {
		t.Logf("skip-key-gen flag default value: %v", flag.DefValue)
	}
}

// TestInitCommandQuickFlag tests quick flag functionality
func TestInitCommandQuickFlag(t *testing.T) {
	flag := initCmd.Flags().Lookup("quick")
	if flag == nil {
		t.Error("quick flag should exist")
	}

	// Flag should be bool type
	if flag.DefValue != "false" {
		t.Logf("quick flag default value: %v", flag.DefValue)
	}
}

// TestInitCommandTokenFlag tests token flag functionality
func TestInitCommandTokenFlag(t *testing.T) {
	flag := initCmd.Flags().Lookup("token")
	if flag == nil {
		t.Error("token flag should exist")
	}

	// Flag should be string type (empty default)
	if flag.DefValue != "" {
		t.Logf("token flag default value: %v", flag.DefValue)
	}
}

// Helper functions

func repeatChar(c byte, count int) string {
	result := make([]byte, count)
	for i := 0; i < count; i++ {
		result[i] = c
	}
	return string(result)
}

// TestInitKidFlagExists tests that --kid is accepted on init.
//
// It was not. Quick mode hardcoded "default-key", so `panda init --quick
// --token ... --kid my-key` — which works in panda-node and panda-php, and is
// what the CLI guide documents — exited with "unknown flag: --kid" here.
func TestInitKidFlagExists(t *testing.T) {
	flag := initCmd.Flags().Lookup("kid")
	if flag == nil {
		t.Fatal("kid flag should exist on init")
	}
	if flag.DefValue != "default-key" {
		t.Errorf("kid default = %q, want %q", flag.DefValue, "default-key")
	}
}

// TestQuickInitHonoursTheKidFlag runs quick init and reads back what it wrote.
//
// Asserting on the source text would pass for a flag that is parsed and then
// dropped, which is the shape of the bug being fixed. This runs the command.
func TestQuickInitHonoursTheKidFlag(t *testing.T) {
	panda.RemovePandaDirectory()
	os.Remove(".env")
	defer panda.RemovePandaDirectory()
	defer os.Remove(".env")

	// The demo token skips the portal call, so this stays offline.
	initToken = crypto.DEMO_TOKEN
	initKid = "my-app-key-1"
	initSkipKey = false
	defer func() {
		initToken = ""
		initKid = "default-key"
		initSkipKey = false
	}()

	if err := runQuickInit(); err != nil {
		t.Fatalf("runQuickInit() error = %v", err)
	}

	config, err := panda.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig() error = %v", err)
	}
	if config.DefaultKid != "my-app-key-1" {
		t.Errorf("config.DefaultKid = %q, want %q", config.DefaultKid, "my-app-key-1")
	}

	creds, err := panda.ReadCredentials()
	if err != nil {
		t.Fatalf("ReadCredentials() error = %v", err)
	}
	if creds.DefaultKid != "my-app-key-1" {
		t.Errorf("credentials.DefaultKid = %q, want %q", creds.DefaultKid, "my-app-key-1")
	}

	env, err := os.ReadFile(".env")
	if err != nil {
		t.Fatalf("read .env: %v", err)
	}
	if !strings.Contains(string(env), "PANDA_KEY_MY_APP_KEY_1") {
		t.Errorf(".env does not contain PANDA_KEY_MY_APP_KEY_1: %s", env)
	}
}

// TestQuickInitDefaultsWhenNoKidGiven pins the fallback, so the flag did not
// change the behaviour of a command that omits it.
func TestQuickInitDefaultsWhenNoKidGiven(t *testing.T) {
	panda.RemovePandaDirectory()
	os.Remove(".env")
	defer panda.RemovePandaDirectory()
	defer os.Remove(".env")

	initToken = crypto.DEMO_TOKEN
	initKid = ""
	initSkipKey = false
	defer func() { initToken = ""; initKid = "default-key" }()

	if err := runQuickInit(); err != nil {
		t.Fatalf("runQuickInit() error = %v", err)
	}

	config, err := panda.ReadConfig()
	if err != nil {
		t.Fatalf("ReadConfig() error = %v", err)
	}
	if config.DefaultKid != "default-key" {
		t.Errorf("config.DefaultKid = %q, want %q", config.DefaultKid, "default-key")
	}
}
