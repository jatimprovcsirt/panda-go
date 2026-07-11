package crypto

import "errors"

var (
	ErrUnsupportedVersion   = errors.New("panda: unsupported envelope version")
	ErrUnsupportedAlgorithm = errors.New("panda: unsupported algorithm")
	ErrAuthenticationFailed = errors.New("panda: ciphertext authentication failed")
	ErrMalformedEnvelope    = errors.New("panda: malformed envelope structure")
	ErrKeyNotFound          = errors.New("panda: key not found")
	ErrInvalidToken         = errors.New("panda: invalid or missing access token")
)
