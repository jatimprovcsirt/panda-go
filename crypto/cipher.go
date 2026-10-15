package crypto

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"

	"github.com/jatimprovcsirt/panda-go/audit"
	"github.com/jatimprovcsirt/panda-go/masking"
	"github.com/jatimprovcsirt/panda-go/telemetry"
)

type FieldCipher struct {
	keys  KeyProvider
	audit *audit.AuditLogger
}

// NewFieldCipher creates a cipher.
//
// The third parameter — a telemetry client — is gone. It existed so every
// cipher carried a token and an HTTP client, and the cipher used them to make
// a network request inside encrypt() and decryptRaw(). Counting is now a
// package-level operation-counter increment (see telemetry.Count), and the
// reporting happens on a timer, nowhere near an operation.
func NewFieldCipher(
	keys KeyProvider,
	auditLogger *audit.AuditLogger,
) *FieldCipher {
	if auditLogger == nil {
		auditLogger = audit.NewAuditLogger(nil)
	}

	return &FieldCipher{
		keys:  keys,
		audit: auditLogger,
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

	telemetry.Count(telemetry.Encrypt)

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

	// The label goes in, rather than being logged here as well: the shared
	// implementation logs every outcome, so logging again here wrote two
	// audit entries per masked read — one of them claiming a raw decrypt.
	raw, err := c.decryptRaw(env, actor, field, "decrypt_masked")
	if err != nil {
		return nil, err
	}

	masked := masking.Mask(string(raw))
	c.audit.Log(actor, field, env.Kid, "decrypt_masked", "success")

	// Counted here, at the public method, and the raw path below is NOT
	// counted by this call. Decrypt used to call the exported DecryptRaw, so
	// an implementation that counted inside DecryptRaw would have counted
	// every masked read twice and classified it as a raw one — which is the
	// governance signal, and it would have been silently wrong.
	telemetry.Count(telemetry.Decrypt)

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

	plaintext, err := c.decryptRaw(env, actor, field, "decrypt_raw")
	if err != nil {
		return nil, err
	}

	c.audit.Log(actor, field, env.Kid, "decrypt_raw", "success")
	telemetry.Count(telemetry.DecryptRaw)

	return plaintext, nil
}

// decryptRaw is the shared implementation. Unexported and uncounted, so the
// two public paths above each count exactly once.
func (c *FieldCipher) decryptRaw(env Envelope, actor, field, label string) ([]byte, error) {

	if env.V != 1 {
		c.audit.Log(actor, field, env.Kid, label, "unsupported_envelope_version")
		return nil, ErrUnsupportedVersion
	}

	if env.Alg != "aes-256-gcm" {
		c.audit.Log(actor, field, env.Kid, label, "unsupported_algorithm")
		return nil, ErrUnsupportedAlgorithm
	}

	key, err := c.keys.GetKey(env.Kid)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, label, "key_not_found")
		return nil, err
	}

	nonce, err := base64.StdEncoding.DecodeString(env.Nonce)
	if err != nil || len(nonce) != 12 {
		c.audit.Log(actor, field, env.Kid, label, "malformed_envelope")
		return nil, ErrMalformedEnvelope
	}

	ciphertextAndTag, err := base64.StdEncoding.DecodeString(env.Ciphertext)
	if err != nil || len(ciphertextAndTag) < 16 {
		c.audit.Log(actor, field, env.Kid, label, "malformed_envelope")
		return nil, ErrMalformedEnvelope
	}

	block, err := aes.NewCipher(key)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, label, "auth_failure")
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	aesgcm, err := cipher.NewGCM(block)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, label, "auth_failure")
		return nil, fmt.Errorf("%w: %v", ErrAuthenticationFailed, err)
	}

	plaintext, err := aesgcm.Open(nil, nonce, ciphertextAndTag, nil)
	if err != nil {
		c.audit.Log(actor, field, env.Kid, label, "auth_failure")
		return nil, ErrAuthenticationFailed
	}

	// No success entry here. The two public methods log their own, because
	// only they know which one ran — and the shared implementation logging
	// one wrote a false "raw" entry for every masked read.
	return plaintext, nil
}
