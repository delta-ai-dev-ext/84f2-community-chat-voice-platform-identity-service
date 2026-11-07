package security

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newTestHasher(t *testing.T) *Hasher {
	t.Helper()
	hasher, err := NewHasher(TestArgon2Params())
	require.NoError(t, err)
	return hasher
}

func TestHashIsPHCFormattedArgon2id(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	encoded, err := hasher.Hash("correct horse battery staple")
	require.NoError(t, err)

	assert.True(t, strings.HasPrefix(encoded, "$argon2id$v=19$m=8192,t=1,p=1$"), encoded)
	assert.Len(t, strings.Split(encoded, "$"), 6)
	assert.NotContains(t, encoded, "correct horse battery staple")
}

func TestHashUsesUniqueSaltPerCall(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	first, err := hasher.Hash("same-password")
	require.NoError(t, err)
	second, err := hasher.Hash("same-password")
	require.NoError(t, err)

	assert.NotEqual(t, first, second)
}

func TestVerifyRoundTrip(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	encoded, err := hasher.Hash("s3cret-password")
	require.NoError(t, err)

	ok, err := hasher.Verify("s3cret-password", encoded)
	require.NoError(t, err)
	assert.True(t, ok)

	ok, err = hasher.Verify("s3cret-passwore", encoded)
	require.NoError(t, err)
	assert.False(t, ok)
}

func TestVerifyRejectsMalformedHashes(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	for _, encoded := range []string{
		"",
		"plain-text",
		"$argon2i$v=19$m=8192,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=13$m=8192,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=x,t=1,p=1$c2FsdA$aGFzaA",
		"$argon2id$v=19$m=8192,t=1,p=1$***$aGFzaA",
	} {
		ok, err := hasher.Verify("anything", encoded)
		assert.False(t, ok, encoded)
		assert.ErrorIs(t, err, ErrInvalidHash, encoded)
	}
}

func TestDummyVerifyAlwaysFails(t *testing.T) {
	t.Parallel()

	hasher := newTestHasher(t)
	assert.False(t, hasher.VerifyDummy("any password"))
	assert.NotEmpty(t, hasher.DummyHash())

	ok, err := hasher.Verify(dummySecret, hasher.DummyHash())
	require.NoError(t, err)
	assert.True(t, ok)
}

func TestNewHasherRejectsZeroParameters(t *testing.T) {
	t.Parallel()

	_, err := NewHasher(Argon2Params{})
	require.Error(t, err)

	params := TestArgon2Params()
	params.KeyLength = 0
	_, err = NewHasher(params)
	require.Error(t, err)
}

func TestOpaqueTokensAreUniqueAndHashed(t *testing.T) {
	t.Parallel()

	token, hash, err := NewOpaqueToken()
	require.NoError(t, err)
	assert.NotEmpty(t, token)
	assert.Equal(t, HashToken(token), hash)
	assert.NotEqual(t, token, hash)
	assert.Len(t, hash, 64)

	other, otherHash, err := NewOpaqueToken()
	require.NoError(t, err)
	assert.NotEqual(t, token, other)
	assert.NotEqual(t, hash, otherHash)
}

func TestConstantTimeEqual(t *testing.T) {
	t.Parallel()

	assert.True(t, ConstantTimeEqual("abc", "abc"))
	assert.False(t, ConstantTimeEqual("abc", "abd"))
	assert.False(t, ConstantTimeEqual("abc", "abcd"))
}
