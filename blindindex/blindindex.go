package blindindex

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"regexp"
	"strings"
)

var nonDigitsRegexp = regexp.MustCompile(`\D`)

func Normalize(plaintext, normalization string) string {
	switch strings.ToLower(normalization) {
	case "digits", "nik", "phone":
		return nonDigitsRegexp.ReplaceAllString(plaintext, "")
	case "lowercase", "email":
		return strings.ToLower(strings.TrimSpace(plaintext))
	case "trim":
		return strings.TrimSpace(plaintext)
	case "none", "raw":
	default:
	}
	return plaintext
}

func Generate(plaintext string, key []byte, normalization string) string {
	normalized := Normalize(plaintext, normalization)
	mac := hmac.New(sha256.New, key)
	mac.Write([]byte(normalized))
	digest := mac.Sum(nil)
	return base64.StdEncoding.EncodeToString(digest)
}
