package panda

import (
	"os"
	"strings"
	"testing"
	"time"
)

// TestPandaDirExists tests directory existence check
func TestPandaDirExists(t *testing.T) {
	// Clean up first
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	if PandaDirExists() {
		t.Error("PandaDirExists() should return false initially")
	}

	// Create directory
	CreatePandaDirectory()

	if !PandaDirExists() {
		t.Error("PandaDirExists() should return true after creation")
	}
}

// TestCreatePandaDirectory tests directory creation
func TestCreatePandaDirectory(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	err := CreatePandaDirectory()
	if err != nil {
		t.Fatalf("CreatePandaDirectory() error = %v", err)
	}

	// Check directory exists
	info, err := os.Stat(PandaDir)
	if err != nil {
		t.Fatalf("Failed to stat .panda directory: %v", err)
	}

	if !info.IsDir() {
		t.Error(".panda should be a directory")
	}

	// Check credentials file exists
	credsPath := PandaDir + "/" + CredsFile
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		t.Error("credentials file should exist")
	}

	// Check keys.json exists
	keysPath := PandaDir + "/" + KeysFile
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		t.Error("keys.json should exist")
	}
}

// TestWriteConfig tests config writing
func TestWriteConfig(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	config := &PandaConfig{
		Version:     "1.0.0",
		Initialized: time.Now().Format(time.RFC3339),
		Provider:    ProviderConfig{Type: "local"},
		DefaultKid:  "default-key",
	}

	err := WriteConfig(config)
	if err != nil {
		t.Errorf("WriteConfig() error = %v", err)
	}

	// Verify file exists
	configPath := PandaDir + "/" + ConfigFile
	if _, err := os.Stat(configPath); os.IsNotExist(err) {
		t.Error("config.json should exist after WriteConfig")
	}
}

// TestReadConfig tests config reading
func TestReadConfig(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	config := &PandaConfig{
		Version:     "1.0.0",
		Initialized: "2024-01-01T00:00:00Z",
		Provider:    ProviderConfig{Type: "infisical"},
		DefaultKid:  "test-key",
	}

	WriteConfig(config)

	readConfig, err := ReadConfig()
	if err != nil {
		t.Errorf("ReadConfig() error = %v", err)
	}

	if readConfig.Version != config.Version {
		t.Errorf("Version = %v, want %v", readConfig.Version, config.Version)
	}

	if readConfig.Provider.Type != config.Provider.Type {
		t.Errorf("Provider.Type = %v, want %v", readConfig.Provider.Type, config.Provider.Type)
	}

	if readConfig.DefaultKid != config.DefaultKid {
		t.Errorf("DefaultKid = %v, want %v", readConfig.DefaultKid, config.DefaultKid)
	}
}

// TestWriteCredentials tests credentials writing
func TestWriteCredentials(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	creds := &PandaCredentials{
		Token:    "test_token",
		Provider: "local",
	}

	err := WriteCredentials(creds)
	if err != nil {
		t.Errorf("WriteCredentials() error = %v", err)
	}

	// Verify file exists
	credsPath := PandaDir + "/" + CredsFile
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		t.Error("credentials file should exist after WriteCredentials")
	}
}

// TestReadCredentials tests credentials reading
func TestReadCredentials(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	creds := &PandaCredentials{
		Token:      "test_token",
		Provider:   "vault",
		VaultURL:   "http://127.0.0.1:8200",
		VaultToken: "vault_token",
		VaultMount: "secret",
	}

	WriteCredentials(creds)

	readCreds, err := ReadCredentials()
	if err != nil {
		t.Errorf("ReadCredentials() error = %v", err)
	}

	if readCreds.Provider != creds.Provider {
		t.Errorf("Provider = %v, want %v", readCreds.Provider, creds.Provider)
	}

	if readCreds.VaultURL != creds.VaultURL {
		t.Errorf("VaultURL = %v, want %v", readCreds.VaultURL, creds.VaultURL)
	}
}

// TestEmptyCredentials tests empty credentials handling
func TestEmptyCredentials(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	// Write empty credentials
	os.WriteFile(PandaDir+"/"+CredsFile, []byte(""), 0600)

	creds, err := ReadCredentials()
	if err != nil {
		t.Errorf("ReadCredentials() error = %v", err)
	}

	if creds.Provider != "local" {
		t.Errorf("Provider = %v, want local (default)", creds.Provider)
	}
}

// TestInfisicalCredentials tests Infisical credentials
func TestInfisicalCredentials(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	creds := &PandaCredentials{
		Token:                  "test_token",
		Provider:               "infisical",
		InfisicalSiteUrl:       "https://app.infisical.com",
		InfisicalClientId:      "client-id",
		InfisicalClientSecret:  "client-secret",
		InfisicalProjectId:     "project-id",
		InfisicalEnvironment:   "dev",
		InfisicalCacheTTL:      "300",
	}

	WriteCredentials(creds)

	readCreds, err := ReadCredentials()
	if err != nil {
		t.Errorf("ReadCredentials() error = %v", err)
	}

	if readCreds.Provider != "infisical" {
		t.Errorf("Provider = %v, want infisical", readCreds.Provider)
	}

	if readCreds.InfisicalSiteUrl != creds.InfisicalSiteUrl {
		t.Errorf("InfisicalSiteUrl = %v, want %v", readCreds.InfisicalSiteUrl, creds.InfisicalSiteUrl)
	}

	if readCreds.InfisicalEnvironment != creds.InfisicalEnvironment {
		t.Errorf("InfisicalEnvironment = %v, want %v", readCreds.InfisicalEnvironment, creds.InfisicalEnvironment)
	}
}

// TestKeysMetadata tests keys metadata operations
func TestKeysMetadata(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	// Initial keys should be empty
	keys, err := ReadKeysMetadata()
	if err != nil {
		t.Errorf("ReadKeysMetadata() error = %v", err)
	}

	if len(keys.Keys) != 0 {
		t.Errorf("Initial keys length = %v, want 0", len(keys.Keys))
	}

	// Add a key
	err = AddKeyToMetadata("test-key-1", "local", ".env")
	if err != nil {
		t.Errorf("AddKeyToMetadata() error = %v", err)
	}

	keys, err = ReadKeysMetadata()
	if err != nil {
		t.Errorf("ReadKeysMetadata() error = %v", err)
	}

	if len(keys.Keys) != 1 {
		t.Errorf("Keys length = %v, want 1", len(keys.Keys))
	}

	if keys.Keys[0].KID != "test-key-1" {
		t.Errorf("KID = %v, want test-key-1", keys.Keys[0].KID)
	}

	if keys.Keys[0].Provider != "local" {
		t.Errorf("Provider = %v, want local", keys.Keys[0].Provider)
	}

	// Add another key
	AddKeyToMetadata("test-key-2", "vault", "secret/data")

	keys, err = ReadKeysMetadata()
	if err != nil {
		t.Errorf("ReadKeysMetadata() error = %v", err)
	}

	if len(keys.Keys) != 2 {
		t.Errorf("Keys length = %v, want 2", len(keys.Keys))
	}

	// Test duplicate key error
	err = AddKeyToMetadata("test-key-1", "local", ".env")
	if err == nil {
		t.Error("Expected error for duplicate key")
	}

	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("Error message should contain 'already exists', got %v", err)
	}
}

// TestRemovePandaDirectory tests directory removal
func TestRemovePandaDirectory(t *testing.T) {
	CreatePandaDirectory()

	// Create some files
	WriteConfig(&PandaConfig{Version: "1.0.0"})
	WriteCredentials(&PandaCredentials{Provider: "local"})

	err := RemovePandaDirectory()
	if err != nil {
		t.Errorf("RemovePandaDirectory() error = %v", err)
	}

	if PandaDirExists() {
		t.Error("PandaDirExists() should return false after removal")
	}

	if _, err := os.Stat(PandaDir); !os.IsNotExist(err) {
		t.Error(".panda directory should not exist after removal")
	}
}

// TestKeyMetadataStructure tests KeyMetadata structure
func TestKeyMetadataStructure(t *testing.T) {
	metadata := KeyMetadata{
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

// TestProviderConfigStructure tests ProviderConfig structure
func TestProviderConfigStructure(t *testing.T) {
	config := ProviderConfig{
		Type: "infisical",
		Config: map[string]interface{}{
			"siteUrl":    "https://app.infisical.com",
			"environment": "dev",
		},
	}

	if config.Type != "infisical" {
		t.Errorf("Type = %v, want infisical", config.Type)
	}

	if config.Config == nil {
		t.Error("Config should not be nil")
	}
}

// TestPandaConfigStructure tests PandaConfig structure
func TestPandaConfigStructure(t *testing.T) {
	config := PandaConfig{
		Version:     "1.0.0",
		Initialized: "2024-01-01T00:00:00Z",
		Provider:    ProviderConfig{Type: "local"},
		DefaultKid:  "default-key",
		Extra:       map[string]interface{}{"custom": "value"},
	}

	if config.Version == "" {
		t.Error("Version should not be empty")
	}

	if config.Initialized == "" {
		t.Error("Initialized should not be empty")
	}

	if config.DefaultKid == "" {
		t.Error("DefaultKid should not be empty")
	}
}

// TestKeyInfoStructure tests KeyInfo structure
func TestKeyInfoStructure(t *testing.T) {
	info := KeyInfo{
		Created:  "2024-01-01T00:00:00Z",
		Provider: "local",
	}

	if info.Created == "" {
		t.Error("Created should not be empty")
	}

	if info.Provider == "" {
		t.Error("Provider should not be empty")
	}
}

// TestCorruptedCredentials tests corrupted credentials handling
func TestCorruptedCredentials(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	// Write corrupted JSON
	os.WriteFile(PandaDir+"/"+CredsFile, []byte("{corrupted json}"), 0600)

	_, err := ReadCredentials()
	if err == nil {
		t.Error("Expected error for corrupted credentials")
	}
}

// TestCorruptedConfig tests corrupted config handling
func TestCorruptedConfig(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	// Write corrupted JSON
	os.WriteFile(PandaDir+"/"+ConfigFile, []byte("{invalid}"), 0644)

	_, err := ReadConfig()
	if err == nil {
		t.Error("Expected error for corrupted config")
	}
}

// TestCorruptedKeysMetadata tests corrupted keys.json handling
func TestCorruptedKeysMetadata(t *testing.T) {
	RemovePandaDirectory()
	defer RemovePandaDirectory()

	CreatePandaDirectory()

	// Write corrupted JSON
	os.WriteFile(PandaDir+"/"+KeysFile, []byte("{bad}"), 0644)

	_, err := ReadKeysMetadata()
	if err == nil {
		t.Error("Expected error for corrupted keys metadata")
	}
}
