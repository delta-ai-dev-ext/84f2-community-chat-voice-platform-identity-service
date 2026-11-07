package models

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
)

// NewUUID returns a random RFC 4122 version 4 UUID in canonical text form.
func NewUUID() (string, error) {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "", fmt.Errorf("generate uuid: %w", err)
	}
	b[6] = (b[6] & 0x0f) | 0x40 // version 4
	b[8] = (b[8] & 0x3f) | 0x80 // variant 10
	return UUIDFromBytes(b), nil
}

// UUIDFromHash derives a stable, version-4-shaped UUID from a SHA-256 digest.
// It is used to make client-supplied idempotency keys deterministic without
// storing extra state.
func UUIDFromHash(hash [32]byte) string {
	var b [16]byte
	copy(b[:], hash[:16])
	b[6] = (b[6] & 0x0f) | 0x40
	b[8] = (b[8] & 0x3f) | 0x80
	return UUIDFromBytes(b)
}

// UUIDFromBytes formats 16 bytes as a canonical UUID string.
func UUIDFromBytes(b [16]byte) string {
	dst := make([]byte, 36)
	hex.Encode(dst[0:8], b[0:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], b[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], b[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], b[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:36], b[10:16])
	return string(dst)
}

// IsUUID reports whether s is a canonical UUID string.
func IsUUID(s string) bool {
	if len(s) != 36 {
		return false
	}
	for i, r := range s {
		switch i {
		case 8, 13, 18, 23:
			if r != '-' {
				return false
			}
		default:
			isHex := (r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')
			if !isHex {
				return false
			}
		}
	}
	return true
}

// NormalizeEmail canonicalises an email address for case-insensitive storage
// and lookup.
func NormalizeEmail(email string) string {
	return strings.ToLower(strings.TrimSpace(email))
}

// NormalizeUsername canonicalises a username for case-insensitive storage and
// lookup.
func NormalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}
