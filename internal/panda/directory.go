package panda

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
)

const (
	PandaDir     = ".panda"
	ConfigFile   = "config.json"
	CredsFile    = "credentials"
	KeysFile     = "keys.json"
)

// PandaConfig represents the configuration stored in config.json
type PandaConfig struct {
	Version     string                 `json:"version"`
	Initialized string                 `json:"initialized"`
	Provider    ProviderConfig         `json:"provider"`
	DefaultKid  string                 `json:"defaultKid,omitempty"`
	Extra       map[string]interface{} `json:"-"` // For additional fields
}

// ProviderConfig holds provider-specific configuration
type ProviderConfig struct {
	Type   string                 `json:"type"`
	Config map[string]interface{} `json:"config,omitempty"`
}

// PandaCredentials holds stored credentials
type PandaCredentials struct {
	Token string `json:"token,omitempty"`
	// Provider selection
	Provider string `json:"provider"`
	// Default key ID
	DefaultKid string `json:"defaultKid,omitempty"`
	// Keys metadata
	Keys map[string]KeyInfo `json:"keys,omitempty"`
	// Vault options
	VaultURL        string `json:"vaultUrl,omitempty"`
	VaultToken      string `json:"vaultToken,omitempty"`
	VaultAuthMethod string `json:"vaultAuthMethod,omitempty"`
	VaultRoleId     string `json:"vaultRoleId,omitempty"`
	VaultSecretId   string `json:"vaultSecretId,omitempty"`
	VaultTokenTTL   string `json:"vaultTokenTTL,omitempty"`
	VaultMount      string `json:"vaultMount,omitempty"`
	// Infisical options
	InfisicalSiteUrl      string `json:"infisicalSiteUrl,omitempty"`
	InfisicalClientId     string `json:"infisicalClientId,omitempty"`
	InfisicalClientSecret string `json:"infisicalClientSecret,omitempty"`
	InfisicalProjectId    string `json:"infisicalProjectId,omitempty"`
	InfisicalEnvironment   string `json:"infisicalEnvironment,omitempty"`
	InfisicalCacheTTL     string `json:"infisicalCacheTTL,omitempty"`
}

// KeyInfo holds metadata about a key
type KeyInfo struct {
	Created  string `json:"created"`
	Provider string `json:"provider"`
}

// KeysJSON holds the keys metadata
type KeysJSON struct {
	Keys []KeyMetadata `json:"keys"`
}

// KeyMetadata holds metadata for a single key
type KeyMetadata struct {
	KID      string `json:"kid"`
	Created  string `json:"created"`
	Provider string `json:"provider"`
	Location string `json:"location"`
}

// PandaDirExists checks if .panda directory exists
func PandaDirExists() bool {
	pandaPath := filepath.Join(PandaDir)
	_, err := os.Stat(pandaPath)
	return err == nil
}

// CreatePandaDirectory creates the .panda directory structure
func CreatePandaDirectory() error {
	pandaPath := filepath.Join(PandaDir)

	if err := os.MkdirAll(pandaPath, 0700); err != nil {
		return fmt.Errorf("failed to create .panda directory: %w", err)
	}

	// Create empty credentials file with restricted permissions
	credsPath := filepath.Join(pandaPath, CredsFile)
	if _, err := os.Stat(credsPath); os.IsNotExist(err) {
		if err := os.WriteFile(credsPath, []byte(""), 0600); err != nil {
			return fmt.Errorf("failed to create credentials file: %w", err)
		}
	}

	// Create empty keys.json
	keysPath := filepath.Join(pandaPath, KeysFile)
	if _, err := os.Stat(keysPath); os.IsNotExist(err) {
		initialKeys := KeysJSON{Keys: []KeyMetadata{}}
		data, err := json.MarshalIndent(initialKeys, "", "  ")
		if err != nil {
			return fmt.Errorf("failed to marshal keys: %w", err)
		}
		if err := os.WriteFile(keysPath, data, 0644); err != nil {
			return fmt.Errorf("failed to create keys.json: %w", err)
		}
	}

	return nil
}

// ReadConfig reads the config.json file
func ReadConfig() (*PandaConfig, error) {
	configPath := filepath.Join(PandaDir, ConfigFile)

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read config: %w", err)
	}

	var config PandaConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	return &config, nil
}

// WriteConfig writes the config.json file
func WriteConfig(config *PandaConfig) error {
	configPath := filepath.Join(PandaDir, ConfigFile)

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}

	if err := os.WriteFile(configPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write config: %w", err)
	}

	return nil
}

// ReadCredentials reads the credentials file
func ReadCredentials() (*PandaCredentials, error) {
	credsPath := filepath.Join(PandaDir, CredsFile)

	data, err := os.ReadFile(credsPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read credentials: %w", err)
	}

	if len(data) == 0 {
		return &PandaCredentials{Provider: "local"}, nil
	}

	var creds PandaCredentials
	if err := json.Unmarshal(data, &creds); err != nil {
		return nil, fmt.Errorf("failed to parse credentials: %w", err)
	}

	return &creds, nil
}

// WriteCredentials writes the credentials file
func WriteCredentials(creds *PandaCredentials) error {
	credsPath := filepath.Join(PandaDir, CredsFile)

	data, err := json.MarshalIndent(creds, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal credentials: %w", err)
	}

	if err := os.WriteFile(credsPath, data, 0600); err != nil {
		return fmt.Errorf("failed to write credentials: %w", err)
	}

	return nil
}

// ReadKeysMetadata reads the keys.json file
func ReadKeysMetadata() (*KeysJSON, error) {
	keysPath := filepath.Join(PandaDir, KeysFile)

	data, err := os.ReadFile(keysPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read keys: %w", err)
	}

	var keys KeysJSON
	if err := json.Unmarshal(data, &keys); err != nil {
		return nil, fmt.Errorf("failed to parse keys: %w", err)
	}

	return &keys, nil
}

// WriteKeysMetadata writes the keys.json file
func WriteKeysMetadata(keys *KeysJSON) error {
	keysPath := filepath.Join(PandaDir, KeysFile)

	data, err := json.MarshalIndent(keys, "", "  ")
	if err != nil {
		return fmt.Errorf("failed to marshal keys: %w", err)
	}

	if err := os.WriteFile(keysPath, data, 0644); err != nil {
		return fmt.Errorf("failed to write keys: %w", err)
	}

	return nil
}

// AddKeyToMetadata adds a key to the keys metadata
func AddKeyToMetadata(kid, provider, location string) error {
	keys, err := ReadKeysMetadata()
	if err != nil {
		return err
	}

	// Check if key already exists
	for _, k := range keys.Keys {
		if k.KID == kid {
			return fmt.Errorf("key '%s' already exists", kid)
		}
	}

	keys.Keys = append(keys.Keys, KeyMetadata{
		KID:      kid,
		Created:  getCurrentTimestamp(),
		Provider: provider,
		Location: location,
	})

	return WriteKeysMetadata(keys)
}

// RemovePandaDirectory removes the .panda directory
func RemovePandaDirectory() error {
	return os.RemoveAll(PandaDir)
}

func getCurrentTimestamp() string {
	// Simple timestamp format
	return "2026-08-12T00:00:00Z"
}
