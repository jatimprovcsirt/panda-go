package crypto

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

type KeyProvider interface {
	GetKey(kid string) ([]byte, error)
}

type LocalKeyProvider struct {
	mu   sync.RWMutex
	keys map[string][]byte
}

func NewLocalKeyProvider() *LocalKeyProvider {
	return &LocalKeyProvider{
		keys: make(map[string][]byte),
	}
}

func (p *LocalKeyProvider) SetKey(kid string, key []byte) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys[kid] = key
}

func (p *LocalKeyProvider) GetKey(kid string) ([]byte, error) {
	p.mu.RLock()
	key, ok := p.keys[kid]
	p.mu.RUnlock()
	if ok {
		return key, nil
	}

	// Read environment
	reg := regexp.MustCompile(`[^A-Za-z0-9]`)
	normalizedKid := strings.ToUpper(reg.ReplaceAllString(kid, "_"))
	envName := fmt.Sprintf("PANDA_KEY_%s", normalizedKid)

	val := os.Getenv("PANDA_KEY_" + kid)
	if val == "" {
		val = os.Getenv(envName)
	}

	if val == "" {
		return nil, fmt.Errorf("%w: key not found for kid %s (expected env %s)", ErrKeyNotFound, kid, envName)
	}

	decoded, err := base64.StdEncoding.DecodeString(val)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("%w: key for kid %s must be 32-byte base64 string", ErrKeyNotFound, kid)
	}

	return decoded, nil
}

// VaultKeyProviderConfig holds configuration for VaultKeyProvider
type VaultKeyProviderConfig struct {
	VaultURL    string
	VaultToken  string
	MountPath   string
	Namespace   string

	// AppRole authentication
	RoleID    string
	SecretID  string
	AuthToken string // 'token' or 'approle'
	TokenTTL  int   // Token TTL in seconds
	CacheTTL  int   // Key cache TTL in seconds
}

// VaultKeyProvider fetches encryption keys from HashiCorp Vault KV v2
//
// Supports two authentication methods:
// 1. Token-based authentication (vaultToken)
// 2. AppRole authentication (roleId + secretId with automatic token renewal)
//
// Keys are cached in memory with a configurable TTL to reduce API calls.
type VaultKeyProvider struct {
	config     VaultKeyProviderConfig
	cache      map[string]cachedKey
	cacheMu    sync.RWMutex
	tokenMu    sync.Mutex

	// Token-based auth
	vaultToken string

	// AppRole-based auth
	roleId      string
	secretId    string
	currentToken string
	tokenExpires  time.Time
}

// NewVaultKeyProvider creates a VaultKeyProvider with token authentication
// Deprecated: Use NewVaultKeyProviderWithConfig for AppRole support
func NewVaultKeyProvider(vaultURL, vaultToken, mountPath string) *VaultKeyProvider {
	config := VaultKeyProviderConfig{
		VaultURL:   vaultURL,
		VaultToken:  vaultToken,
		MountPath:   mountPath,
		Namespace:   "",
		RoleID:      "",
		SecretID:    "",
		AuthToken:    "token",
		TokenTTL:    3600,
		CacheTTL:     300,
	}
	return NewVaultKeyProviderWithConfig(config)
}

// NewVaultKeyProviderWithConfig creates a VaultKeyProvider with full configuration
func NewVaultKeyProviderWithConfig(config VaultKeyProviderConfig) *VaultKeyProvider {
	// Normalize URLs and paths
	config.VaultURL = strings.TrimRight(config.VaultURL, "/")
	config.MountPath = strings.Trim(config.MountPath, "/")
	if config.MountPath == "" {
		config.MountPath = "secret"
	}

	// Determine auth method
	if config.RoleID != "" && config.SecretID != "" {
		config.AuthToken = "approle"
	} else {
		config.AuthToken = "token"
	}

	// Set defaults
	if config.TokenTTL == 0 {
		config.TokenTTL = 3600
	}
	if config.CacheTTL == 0 {
		config.CacheTTL = 300
	}

	return &VaultKeyProvider{
		config:     config,
		cache:      make(map[string]cachedKey),
		vaultToken: config.VaultToken,
		roleId:     config.RoleID,
		secretId:   config.SecretID,
	}
}

// ensureToken ensures we have a valid Vault token
func (p *VaultKeyProvider) ensureToken() (string, error) {
	if p.config.AuthToken == "token" {
		return p.vaultToken, nil
	}

	p.tokenMu.Lock()
	defer p.tokenMu.Unlock()

	// Check if we have a valid cached token
	if p.currentToken != "" && time.Now().Before(p.tokenExpires) {
		return p.currentToken, nil
	}

	// Fetch new AppRole token
	return p.fetchAppRoleToken()
}

// fetchAppRoleToken fetches a new Vault token using AppRole authentication
func (p *VaultKeyProvider) fetchAppRoleToken() (string, error) {
	url := fmt.Sprintf("%s/v1/auth/approle/login", p.config.VaultURL)
	payload := map[string]string{
		"role_id":   p.roleId,
		"secret_id": p.secretId,
	}

	body, err := json.Marshal(payload)
	if err != nil {
		return "", fmt.Errorf("%w: failed to marshal AppRole payload: %v", ErrKeyNotFound, err)
	}

	req, err := http.NewRequest("POST", url, bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("%w: failed to create AppRole request: %v", ErrKeyNotFound, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	tr := &http.Transport{}
	if os.Getenv("PANDA_VAULT_INSECURE") == "1" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Timeout:   10 * time.Second,
		Transport: tr,
	}

	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("%w: AppRole request failed: %v", ErrKeyNotFound, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("%w: AppRole authentication failed (HTTP %d): %s", ErrKeyNotFound, resp.StatusCode, string(respBody))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("%w: failed to read AppRole response: %v", ErrKeyNotFound, err)
	}

	var authResp struct {
		Auth struct {
			ClientToken    string  `json:"client_token"`
			LeaseDuration  float64 `json:"lease_duration"`
		} `json:"auth"`
	}

	if err := json.Unmarshal(respBody, &authResp); err != nil {
		return "", fmt.Errorf("%w: failed to parse AppRole response: %v", ErrKeyNotFound, err)
	}

	if authResp.Auth.ClientToken == "" {
		return "", fmt.Errorf("%w: no client_token in AppRole response", ErrKeyNotFound)
	}

	p.currentToken = authResp.Auth.ClientToken

	// Set token expiry (use lease duration if provided, otherwise default to token TTL)
	leaseDuration := int(authResp.Auth.LeaseDuration)
	if leaseDuration == 0 {
		leaseDuration = p.config.TokenTTL
	}
	// Refresh 5 minutes (300 seconds) before expiry
	p.tokenExpires = time.Now().Add(time.Duration(leaseDuration-300) * time.Second)

	return p.currentToken, nil
}

func (p *VaultKeyProvider) GetKey(kid string) ([]byte, error) {
	// Check cache first (with TTL)
	p.cacheMu.RLock()
	cached, ok := p.cache[kid]
	p.cacheMu.RUnlock()
	if ok && cached.expires.After(time.Now()) {
		return cached.key, nil
	}

	// Ensure we have a valid token
	token, err := p.ensureToken()
	if err != nil {
		return nil, err
	}

	// Build the Vault API URL for KV v2
	var url string
	if p.config.Namespace != "" {
		url = fmt.Sprintf("%s/v1/%s/%s/data/%s", p.config.VaultURL, p.config.Namespace, p.config.MountPath, kid)
	} else {
		url = fmt.Sprintf("%s/v1/%s/data/%s", p.config.VaultURL, p.config.MountPath, kid)
	}

	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrKeyNotFound, err)
	}

	req.Header.Set("X-Vault-Token", token)
	req.Header.Set("Accept", "application/json")

	tr := &http.Transport{}
	if os.Getenv("PANDA_VAULT_INSECURE") == "1" {
		tr.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	}

	client := &http.Client{
		Timeout:   5 * time.Second,
		Transport: tr,
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %v", ErrKeyNotFound, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: key '%s' not found in Vault", ErrKeyNotFound, kid)
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("%w: Vault returned status code %d: %s", ErrKeyNotFound, resp.StatusCode, string(body))
	}

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrKeyNotFound, err)
	}

	var data struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.Unmarshal(respBody, &data); err != nil {
		return nil, fmt.Errorf("%w: failed to parse Vault response: %v", ErrKeyNotFound, err)
	}

	keyVal, ok := data.Data.Data["key"].(string)
	if !ok {
		keyVal, ok = data.Data.Data["value"].(string)
	}

	if !ok || keyVal == "" {
		return nil, fmt.Errorf("%w: key field not found in Vault response", ErrKeyNotFound)
	}

	decoded, err := base64.StdEncoding.DecodeString(keyVal)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("%w: Vault key is not a valid 32-byte base64 string", ErrKeyNotFound)
	}

	// Cache the key with TTL
	p.cacheMu.Lock()
	p.cache[kid] = cachedKey{
		key:     decoded,
		expires: time.Now().Add(time.Duration(p.config.CacheTTL) * time.Second),
	}
	p.cacheMu.Unlock()

	return decoded, nil
}

type HsmKeyProvider struct{}

func (p *HsmKeyProvider) GetKey(kid string) ([]byte, error) {
	return nil, fmt.Errorf("panda: HSM Key Provider is not implemented in this version")
}

// InfisicalKeyProvider fetches encryption keys from Infisical
//
// This provider uses Universal Auth (Machine Identity credentials) to authenticate
// with Infisical and retrieve encryption keys. Keys are cached in memory with a
// configurable TTL to reduce API calls.
type InfisicalKeyProvider struct {
	siteUrl      string
	clientId     string
	clientSecret string
	projectId    string
	environment  string
	cache        map[string]cachedKey
	cacheTTL     time.Duration
	mu           sync.RWMutex

	// Authentication state
	accessToken   string
	tokenExpires  time.Time
	authenticated bool
	authMu        sync.Mutex
}

// cachedKey represents a cached key with expiration time
type cachedKey struct {
	key     []byte
	expires time.Time
}

// NewInfisicalKeyProvider creates a new InfisicalKeyProvider
//
// Parameters:
//   - siteUrl: Infisical site URL (e.g., https://app.infisical.com)
//   - clientId: Machine Identity Client ID
//   - clientSecret: Machine Identity Client Secret
//   - projectId: Infisical Project ID
//   - environment: Environment name (dev, prod, etc.)
//   - cacheTTL: Cache TTL in seconds (default: 300)
func NewInfisicalKeyProvider(siteUrl, clientId, clientSecret, projectId, environment string, cacheTTL int) *InfisicalKeyProvider {
	if cacheTTL <= 0 {
		cacheTTL = 300
	}
	return &InfisicalKeyProvider{
		siteUrl:      strings.TrimRight(siteUrl, "/"),
		clientId:     clientId,
		clientSecret: clientSecret,
		projectId:    projectId,
		environment:  environment,
		cache:        make(map[string]cachedKey),
		cacheTTL:     time.Duration(cacheTTL) * time.Second,
	}
}

// ensureAuthenticated checks if we have a valid access token and authenticates if needed
func (p *InfisicalKeyProvider) ensureAuthenticated() error {
	p.authMu.Lock()
	defer p.authMu.Unlock()

	// Check if we have a valid cached token
	if p.authenticated && p.accessToken != "" && time.Now().Before(p.tokenExpires) {
		return nil
	}

	// Authenticate using Universal Auth
	authUrl := fmt.Sprintf("%s/api/v1/auth/universal-auth/login", p.siteUrl)
	payload := map[string]string{
		"clientId":     p.clientId,
		"clientSecret": p.clientSecret,
	}

	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("%w: failed to marshal auth payload: %v", ErrKeyNotFound, err)
	}

	req, err := http.NewRequest("POST", authUrl, bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("%w: failed to create auth request: %v", ErrKeyNotFound, err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("%w: auth request failed: %v", ErrKeyNotFound, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("%w: Infisical authentication failed (HTTP %d)", ErrKeyNotFound, resp.StatusCode)
	}

	var authResp struct {
		AccessToken string `json:"accessToken"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&authResp); err != nil {
		return fmt.Errorf("%w: failed to parse auth response: %v", ErrKeyNotFound, err)
	}

	if authResp.AccessToken == "" {
		return fmt.Errorf("%w: no access token in auth response", ErrKeyNotFound)
	}

	p.accessToken = authResp.AccessToken
	// Token expires in 9.5 minutes (Infisical tokens are 10min)
	p.tokenExpires = time.Now().Add(9 * time.Minute + 30 * time.Second)
	p.authenticated = true

	return nil
}

// GetKey retrieves the 32-byte encryption key for the given key identifier
func (p *InfisicalKeyProvider) GetKey(kid string) ([]byte, error) {
	// Check cache first
	p.mu.RLock()
	cached, ok := p.cache[kid]
	p.mu.RUnlock()

	if ok && cached.expires.After(time.Now()) {
		return cached.key, nil
	}

	// Ensure we have a valid access token
	if err := p.ensureAuthenticated(); err != nil {
		return nil, err
	}

	// Fetch secret from Infisical
	apiUrl := fmt.Sprintf("%s/api/v3/secrets/raw?projectId=%s&environment=%s&secretPath=%s",
		p.siteUrl, p.projectId, p.environment, kid)

	req, err := http.NewRequest("GET", apiUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrKeyNotFound, err)
	}

	req.Header.Set("Authorization", "Bearer "+p.accessToken)
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: request failed: %v", ErrKeyNotFound, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: Could not retrieve key '%s' from Infisical (HTTP %d)", ErrKeyNotFound, kid, resp.StatusCode)
	}

	var secretResp struct {
		SecretValue string `json:"secretValue"`
		Secret      string `json:"secret"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&secretResp); err != nil {
		return nil, fmt.Errorf("%w: failed to parse response: %v", ErrKeyNotFound, err)
	}

	secretValue := secretResp.SecretValue
	if secretValue == "" {
		secretValue = secretResp.Secret
	}

	if secretValue == "" {
		return nil, fmt.Errorf("%w: key '%s' not found in Infisical response", ErrKeyNotFound, kid)
	}

	decoded, err := base64.StdEncoding.DecodeString(secretValue)
	if err != nil || len(decoded) != 32 {
		return nil, fmt.Errorf("%w: key '%s' is not a valid 32-byte base64 string", ErrKeyNotFound, kid)
	}

	// Cache the key
	p.mu.Lock()
	p.cache[kid] = cachedKey{
		key:     decoded,
		expires: time.Now().Add(p.cacheTTL),
	}
	p.mu.Unlock()

	return decoded, nil
}
