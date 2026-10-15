package crypto

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/jatimprovcsirt/panda-go/blindindex"
	"github.com/jatimprovcsirt/panda-go/masking"
)

type TestVectorFile struct {
	Positive []struct {
		Description string `json:"description"`
		Key         string `json:"key"`
		Kid         string `json:"kid"`
		Nonce       string `json:"nonce"`
		Plaintext   string `json:"plaintext"`
		Envelope    struct {
			V          int    `json:"v"`
			Alg        string `json:"alg"`
			Kid        string `json:"kid"`
			Nonce      string `json:"nonce"`
			Ciphertext string `json:"ciphertext"`
		} `json:"envelope"`
	} `json:"positive"`
	Negative []struct {
		Description string `json:"description"`
		Key         string `json:"key"`
		Kid         string `json:"kid"`
		Envelope    struct {
			V          int    `json:"v"`
			Alg        string `json:"alg"`
			Kid        string `json:"kid"`
			Nonce      string `json:"nonce"`
			Ciphertext string `json:"ciphertext"`
		} `json:"envelope"`
		ExpectedError string `json:"expected_error"`
	} `json:"negative"`
}

func TestFieldCipher_PositiveVectors(t *testing.T) {
	path := filepath.Join("..", "spec", "vectors", "vectors.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join("..", "..", "panda-spec", "vectors", "vectors.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read vectors file: %v", err)
	}

	var vectorFile TestVectorFile
	if err := json.Unmarshal(data, &vectorFile); err != nil {
		t.Fatalf("Failed to parse vectors file: %v", err)
	}

	for _, v := range vectorFile.Positive {
		t.Run(v.Description, func(t *testing.T) {
			key, err := base64.StdEncoding.DecodeString(v.Key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}

			keyProvider := NewLocalKeyProvider()
			keyProvider.SetKey(v.Kid, key)

			cipher := NewFieldCipher(keyProvider, nil)

			env := Envelope{
				V:          v.Envelope.V,
				Alg:        v.Envelope.Alg,
				Kid:        v.Envelope.Kid,
				Nonce:      v.Envelope.Nonce,
				Ciphertext: v.Envelope.Ciphertext,
			}

			// 1. Decrypt raw
			decryptedRaw, err := cipher.DecryptRaw(env)
			if err != nil {
				t.Fatalf("DecryptRaw failed: %v", err)
			}

			if string(decryptedRaw) != v.Plaintext {
				t.Errorf("Expected plaintext %q, got %q", v.Plaintext, string(decryptedRaw))
			}

			// 2. Decrypt masked (default)
			decryptedMasked, err := cipher.Decrypt(env)
			if err != nil {
				t.Fatalf("Decrypt failed: %v", err)
			}

			expectedMasked := masking.Mask(v.Plaintext)
			if string(decryptedMasked) != expectedMasked {
				t.Errorf("Expected masked %q, got %q", expectedMasked, string(decryptedMasked))
			}

			// 3. Encrypt and Decrypt raw round-trip
			newEnv, err := cipher.Encrypt([]byte(v.Plaintext), v.Kid)
			if err != nil {
				t.Fatalf("Encrypt failed: %v", err)
			}

			roundtripRaw, err := cipher.DecryptRaw(newEnv)
			if err != nil {
				t.Fatalf("Roundtrip DecryptRaw failed: %v", err)
			}

			if string(roundtripRaw) != v.Plaintext {
				t.Errorf("Roundtrip expected %q, got %q", v.Plaintext, string(roundtripRaw))
			}
		})
	}
}

func TestFieldCipher_NegativeVectors(t *testing.T) {
	path := filepath.Join("..", "spec", "vectors", "vectors.json")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		path = filepath.Join("..", "..", "panda-spec", "vectors", "vectors.json")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("Failed to read vectors file: %v", err)
	}

	var vectorFile TestVectorFile
	if err := json.Unmarshal(data, &vectorFile); err != nil {
		t.Fatalf("Failed to parse vectors file: %v", err)
	}

	for _, v := range vectorFile.Negative {
		t.Run(v.Description, func(t *testing.T) {
			key, err := base64.StdEncoding.DecodeString(v.Key)
			if err != nil {
				t.Fatalf("Failed to decode key: %v", err)
			}

			keyProvider := NewLocalKeyProvider()
			keyProvider.SetKey(v.Kid, key)

			cipher := NewFieldCipher(keyProvider, nil)

			env := Envelope{
				V:          v.Envelope.V,
				Alg:        v.Envelope.Alg,
				Kid:        v.Envelope.Kid,
				Nonce:      v.Envelope.Nonce,
				Ciphertext: v.Envelope.Ciphertext,
			}

			var expectedErr error
			switch v.ExpectedError {
			case "AuthenticationFailed":
				expectedErr = ErrAuthenticationFailed
			case "UnsupportedEnvelopeVersion":
				expectedErr = ErrUnsupportedVersion
			case "UnsupportedAlgorithm":
				expectedErr = ErrUnsupportedAlgorithm
			case "MalformedEnvelope":
				expectedErr = ErrMalformedEnvelope
			}

			_, err = cipher.DecryptRaw(env)
			if err == nil {
				t.Fatalf("Expected error %v, got nil", expectedErr)
			}

			if !errors.Is(err, expectedErr) {
				t.Errorf("Expected error wrapping %v, got %v", expectedErr, err)
			}
		})
	}
}

func TestBlindIndexing(t *testing.T) {
	key := []byte("thisisasecretkeyof32byteslength!")
	nik := "32-01-01-250199-0001"
	email := " User@Example.COM  "

	nikIndex := blindindex.Generate(nik, key, "nik")
	if nikIndex != blindindex.Generate("3201012501990001", key, "none") {
		t.Errorf("Failed blind indexing for NIK")
	}

	emailIndex := blindindex.Generate(email, key, "email")
	if emailIndex != blindindex.Generate("user@example.com", key, "none") {
		t.Errorf("Failed blind indexing for email")
	}
}
