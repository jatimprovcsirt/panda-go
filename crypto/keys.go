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

type VaultKeyProvider struct {
	vaultURL   string
	vaultToken string
	mountPath  string
	cache      map[string][]byte
	mu         sync.RWMutex
}

func NewVaultKeyProvider(vaultURL, vaultToken, mountPath string) *VaultKeyProvider {
	return &VaultKeyProvider{
		vaultURL:   strings.TrimRight(vaultURL, "/"),
		vaultToken: vaultToken,
		mountPath:  strings.Trim(mountPath, "/"),
		cache:      make(map[string][]byte),
	}
}

func (p *VaultKeyProvider) GetKey(kid string) ([]byte, error) {
	p.mu.RLock()
	cached, ok := p.cache[kid]
	p.mu.RUnlock()
	if ok {
		return cached, nil
	}

	url := fmt.Sprintf("%s/v1/%s/data/%s", p.vaultURL, p.mountPath, kid)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to create request: %v", ErrKeyNotFound, err)
	}

	req.Header.Set("X-Vault-Token", p.vaultToken)
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

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: Vault returned status code %d", ErrKeyNotFound, resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("%w: failed to read response: %v", ErrKeyNotFound, err)
	}

	var data struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}

	if err := json.Unmarshal(body, &data); err != nil {
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

	p.mu.Lock()
	p.cache[kid] = decoded
	p.mu.Unlock()

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
