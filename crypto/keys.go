package crypto

import (
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
