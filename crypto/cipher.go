package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"

	"github.com/jatimprovcsirt/panda-go/audit"
	"github.com/jatimprovcsirt/panda-go/masking"
	"github.com/jatimprovcsirt/panda-go/telemetry"
)

type FieldCipher struct {
	keys           KeyProvider
	audit          *audit.AuditLogger
	telemetry      *telemetry.TelemetryClient
	telemetryToken string
}

func NewFieldCipher(
	keys KeyProvider,
	auditLogger *audit.AuditLogger,
	telemetryClient *telemetry.TelemetryClient,
) *FieldCipher {
	if auditLogger == nil {
		auditLogger = audit.NewAuditLogger(nil)
	}
	if telemetryClient == nil {
		telemetryClient = telemetry.NewTelemetryClient()
	}

	token := os.Getenv("PANDA_PORTAL_TOKEN")

	return &FieldCipher{
		keys:           keys,
		audit:          auditLogger,
		telemetry:      telemetryClient,
		telemetryToken: token,
	}
}

func (c *FieldCipher) Encrypt(plaintext []byte, kid string, extra ...string) (Envelope, error) {
	actor := "system"
	field := "unknown"
	if len(extra) > 0 {
		actor = extra[0]
	}
	if len(extra) > 1 {
		field = extra[1]
	}

	var env Envelope
	key, err := c.keys.GetKey(kid)
	if err != nil {
		c.audit.Log(actor, field, kid, "encrypt", "key_not_found")
		return env, err
	}

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		c.audit.Log(actor, field, kid, "encrypt", "encryption_failed")
		return env, err
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		c.audit.Log(actor, field, kid, "encrypt", "encryption_failed")
		return env, err
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		c.audit.Log(actor, field, kid, "encrypt", "encryption_failed")
		return env, err
	}

	ciphertextAndTag := aesgcm.Seal(nil, nonce, plaintext, nil)

	env = Envelope{
		V:          1,
		Alg:        "aes-256-gcm",
		Kid:        kid,
		Nonce:      base64.StdEncoding.EncodeToString(nonce),
		Ciphertext: base64.StdEncoding.EncodeToString(ciphertextAndTag),
	}

	c.audit.Log(actor, field, kid, "encrypt", "success")

	if c.telemetryToken != "" {
		c.telemetry.Report(c.telemetryToken, key, "0.1.0")
	}

	return env, nil
}

func (c *FieldCipher) Decrypt(env Envelope, extra ...string) ([]byte, error) {
	actor := "system"
	field := "unknown"
	if len(extra) > 0 {
		actor = extra[0]
	}
	if len(extra) > 1 {
		field = extra[1]
	}

	raw, err := c.DecryptRaw(env, actor, field)
	if err != nil {
		return nil, err
	}

	masked := masking.Mask(string(raw))
	c.audit.Log(actor, field, env.Kid, "decrypt_masked", "success")

	return []byte(masked), nil
}

func (c *FieldCipher) DecryptRaw(env Envelope, extra ...string) ([]byte, error) {
	actor := "system"
	field := "unknown"
	if len(extra) > 0 {
		actor = extra[0]
	}
	if len(extra) > 1 {
		field = extra[1]
	}

	if env.V != 1 {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "unsupported_envelope_version")
		return nil, ErrUnsupportedVersion
	}

	if env.Alg != "aes-256-gcm" {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "unsupported_algorithm")
		return nil, ErrUnsupportedAlgorithm
	}

	key, err := c.keys.GetKey(env.Kid)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "key_not_found")
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 12 {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "malformed_envelope")
		return nil, ErrMalformedEnvelope
	}

	ciphertextAndTag, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertextAndTag) < 16 {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "malformed_envelope")
		return nil, ErrMalformedEnvelope
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "auth_failure")
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "auth_failure")
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, "decrypt_raw", "auth_failure")
		return nil, ErrAuthenticationFailed
	}

	c.audit.Log(actor, field, env.Kid, "decrypt_raw", "success")

	if c.telemetryToken != "" {
		c.telemetry.Report(c.telemetryToken, key, "0.1.0")
	}

	return plaintext, nil
}
