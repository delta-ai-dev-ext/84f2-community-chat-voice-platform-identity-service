// Package security holds the cryptographic primitives shared by the service:
// Argon2id password hashing in PHC string format and the opaque-token helpers
// used for refresh, verification and password-reset tokens.
package security

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"golang.org/x/crypto/argon2"
)

// Argon2id parameters. Memory is expressed in KiB.
type Argon2Params struct {
	Memory      uint32
	Iterations  uint32
	Parallelism uint8
	SaltLength  uint32
	KeyLength   uint32
}

// DefaultArgon2Params are the production Argon2id parameters.
func DefaultArgon2Params() Argon2Params {
	return Argon2Params{Memory: 64 * 1024, Iterations: 3, Parallelism: 2, SaltLength: 16, KeyLength: 32}
}

// TestArgon2Params are fast parameters used only by tests.
func TestArgon2Params() Argon2Params {
	return Argon2Params{Memory: 8 * 1024, Iterations: 1, Parallelism: 1, SaltLength: 16, KeyLength: 32}
}

// dummySecret is verified against the dummy hash so unknown accounts cost the
// same wall-clock time as known ones.
const dummySecret = "identity_service-timing-equalisation-secret"

// ErrInvalidHash is returned when a stored hash cannot be parsed.
var ErrInvalidHash = errors.New("security: invalid argon2id hash format")

// Hasher hashes and verifies passwords with Argon2id.
type Hasher struct {
	params    Argon2Params
	dummyHash string
}

// NewHasher builds a Hasher and pre-computes the dummy hash used for
// enumeration-safe sign-in.
func NewHasher(params Argon2Params) (*Hasher, error) {
	if params.Memory == 0 || params.Iterations == 0 || params.Parallelism == 0 || params.SaltLength == 0 || params.KeyLength == 0 {
		return nil, errors.New("security: argon2id parameters must be non-zero")
	}
	dummy, err := hashWith(params, dummySecret)
	if err != nil {
		return nil, err
	}
	return &Hasher{params: params, dummyHash: dummy}, nil
}

// Hash returns the PHC-formatted Argon2id hash of password.
func (h *Hasher) Hash(password string) (string, error) {
	return hashWith(h.params, password)
}

// Verify compares password against a PHC-formatted Argon2id hash in constant
// time. A malformed hash yields ErrInvalidHash and a false result.
func (h *Hasher) Verify(password, encoded string) (bool, error) {
	params, salt, want, err := decodeHash(encoded)
	if err != nil {
		return false, err
	}
	got := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, uint32(len(want)))
	return subtle.ConstantTimeCompare(got, want) == 1, nil
}

// VerifyDummy burns the same amount of work as a real verification so that an
// unknown email is indistinguishable from a wrong password. It always returns
// false and never fails.
func (h *Hasher) VerifyDummy(password string) bool {
	_, _ = h.Verify(password, h.dummyHash)
	return false
}

// DummyHash returns the pre-computed dummy hash (exposed for tests).
func (h *Hasher) DummyHash() string { return h.dummyHash }

func hashWith(params Argon2Params, password string) (string, error) {
	salt := make([]byte, params.SaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("security: generate salt: %w", err)
	}
	key := argon2.IDKey([]byte(password), salt, params.Iterations, params.Memory, params.Parallelism, params.KeyLength)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s",
		argon2.Version, params.Memory, params.Iterations, params.Parallelism,
		base64.RawStdEncoding.EncodeToString(salt),
		base64.RawStdEncoding.EncodeToString(key),
	), nil
}

func decodeHash(encoded string) (Argon2Params, []byte, []byte, error) {
	var params Argon2Params
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" {
		return params, nil, nil, ErrInvalidHash
	}
	var version int
	if _, err := fmt.Sscanf(parts[2], "v=%d", &version); err != nil || version != argon2.Version {
		return params, nil, nil, ErrInvalidHash
	}
	if _, err := fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &params.Memory, &params.Iterations, &params.Parallelism); err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	salt, err := base64.RawStdEncoding.DecodeString(parts[4])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	key, err := base64.RawStdEncoding.DecodeString(parts[5])
	if err != nil {
		return params, nil, nil, ErrInvalidHash
	}
	params.SaltLength = uint32(len(salt))
	params.KeyLength = uint32(len(key))
	return params, salt, key, nil
}

// tokenByteLength is the entropy of an opaque token before base64 encoding.
const tokenByteLength = 32

// NewOpaqueToken returns a fresh high-entropy token and its SHA-256 hash. Only
// the hash is ever persisted.
func NewOpaqueToken() (token string, hash string, err error) {
	buf := make([]byte, tokenByteLength)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("security: generate token: %w", err)
	}
	token = base64.RawURLEncoding.EncodeToString(buf)
	return token, HashToken(token), nil
}

// HashToken returns the lowercase hex SHA-256 hash of an opaque token.
func HashToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

// ConstantTimeEqual compares two strings without leaking their contents through
// timing.
func ConstantTimeEqual(a, b string) bool {
	return subtle.ConstantTimeCompare([]byte(a), []byte(b)) == 1
}
