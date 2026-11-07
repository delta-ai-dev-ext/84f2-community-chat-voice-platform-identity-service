package service

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"sync"
	"time"

	"go.uber.org/zap"

	"identity_service/internal/clock"
	"identity_service/internal/models"
	"identity_service/internal/repository"
)

// SigningAlgorithm is the JWS algorithm used for access tokens.
const SigningAlgorithm = "RS256"

// rsaKeyBits is the modulus size of a freshly generated signing key.
const rsaKeyBits = 2048

// ErrUnknownSigningKey is returned when no published key matches a JWT kid.
var ErrUnknownSigningKey = errors.New("service: unknown signing key")

// keyMaterial is the in-memory current signing key.
type keyMaterial struct {
	kid       string
	key       *rsa.PrivateKey
	createdAt time.Time
}

// KeyManager owns the access-token signing keys and their rotation:
// current → next → retired, with retired keys staying published during the
// overlap window so in-flight tokens keep verifying.
type KeyManager struct {
	repos            repository.SigningKeyRepository
	tx               repository.Transactor
	clock            clock.Clock
	rotationInterval time.Duration
	overlap          time.Duration
	cacheTTL         time.Duration
	logger           *zap.Logger

	mu         sync.RWMutex
	current    *keyMaterial
	publicKeys map[string]*rsa.PublicKey
	loadedAt   time.Time
}

// NewKeyManager builds a key manager. tx may be nil (used only in tests).
func NewKeyManager(repos repository.SigningKeyRepository, tx repository.Transactor, clk clock.Clock, rotationInterval, overlap time.Duration, logger *zap.Logger) *KeyManager {
	if logger == nil {
		logger = zap.NewNop()
	}
	return &KeyManager{
		repos:            repos,
		tx:               tx,
		clock:            clk,
		rotationInterval: rotationInterval,
		overlap:          overlap,
		cacheTTL:         30 * time.Second,
		logger:           logger,
		publicKeys:       map[string]*rsa.PublicKey{},
	}
}

// EnsureKeys guarantees that a current and a next key exist, prunes retired
// keys past the overlap window, rotates when the current key is due, and loads
// the signing material. It is called once at startup.
func (m *KeyManager) EnsureKeys(ctx context.Context) error {
	now := m.clock.Now()
	if _, err := m.repos.DeleteRetiredBefore(ctx, now.Add(-m.overlap)); err != nil {
		return fmt.Errorf("service: prune retired signing keys: %w", err)
	}

	current, err := m.repos.GetByStatus(ctx, models.SigningKeyCurrent)
	if errors.Is(err, repository.ErrNotFound) {
		if err := m.createKey(ctx, models.SigningKeyCurrent); err != nil {
			return err
		}
		current = nil
	} else if err != nil {
		return fmt.Errorf("service: load current signing key: %w", err)
	}

	if _, err := m.repos.GetByStatus(ctx, models.SigningKeyNext); errors.Is(err, repository.ErrNotFound) {
		if err := m.createKey(ctx, models.SigningKeyNext); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("service: load next signing key: %w", err)
	}

	if current != nil && m.rotationInterval > 0 && now.Sub(current.CreatedAt) >= m.rotationInterval {
		if err := m.Rotate(ctx); err != nil {
			return err
		}
	}
	return m.Refresh(ctx)
}

// Rotate retires the current key, promotes the next key to current and
// generates a fresh next key. The retired key stays published until the overlap
// window closes.
func (m *KeyManager) Rotate(ctx context.Context) error {
	now := m.clock.Now()
	rotate := func(ctx context.Context) error {
		current, err := m.repos.GetByStatus(ctx, models.SigningKeyCurrent)
		if err != nil {
			return fmt.Errorf("service: load current signing key: %w", err)
		}
		next, err := m.repos.GetByStatus(ctx, models.SigningKeyNext)
		if err != nil {
			return fmt.Errorf("service: load next signing key: %w", err)
		}
		if err := m.repos.SetStatus(ctx, current.Kid, models.SigningKeyRetired, &now); err != nil {
			return fmt.Errorf("service: retire signing key: %w", err)
		}
		if err := m.repos.SetStatus(ctx, next.Kid, models.SigningKeyCurrent, nil); err != nil {
			return fmt.Errorf("service: promote signing key: %w", err)
		}
		return m.createKey(ctx, models.SigningKeyNext)
	}

	var err error
	if m.tx != nil {
		err = m.tx.WithTx(ctx, rotate)
	} else {
		err = rotate(ctx)
	}
	if err != nil {
		return err
	}
	m.logger.Info("signing key rotated", zap.String("operation", "key_rotation"), zap.String("status", "ok"))
	return m.Refresh(ctx)
}

// createKey generates an RSA key pair and stores it with the given status.
func (m *KeyManager) createKey(ctx context.Context, status models.SigningKeyStatus) error {
	key, err := rsa.GenerateKey(rand.Reader, rsaKeyBits)
	if err != nil {
		return fmt.Errorf("service: generate signing key: %w", err)
	}
	jwk, err := publicJWK(&key.PublicKey)
	if err != nil {
		return err
	}
	jwkJSON, err := json.Marshal(jwk)
	if err != nil {
		return fmt.Errorf("service: marshal jwk: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("service: marshal private key: %w", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})

	return m.repos.Create(ctx, &models.SigningKey{
		Kid:          jwk.Kid,
		Algorithm:    SigningAlgorithm,
		PublicKeyJWK: jwkJSON,
		PrivateKey:   string(pemBytes),
		Status:       status,
		CreatedAt:    m.clock.Now(),
	})
}

// Refresh reloads the current key and the published verification key set.
func (m *KeyManager) Refresh(ctx context.Context) error {
	current, err := m.repos.GetByStatus(ctx, models.SigningKeyCurrent)
	if err != nil {
		return fmt.Errorf("service: load current signing key: %w", err)
	}
	privateKey, err := parsePrivateKey(current.PrivateKey)
	if err != nil {
		return err
	}
	published, err := m.repos.ListPublished(ctx, m.clock.Now().Add(-m.overlap))
	if err != nil {
		return fmt.Errorf("service: list published signing keys: %w", err)
	}
	keys := make(map[string]*rsa.PublicKey, len(published))
	for i := range published {
		var jwk models.JWK
		if err := json.Unmarshal(published[i].PublicKeyJWK, &jwk); err != nil {
			return fmt.Errorf("service: decode stored jwk: %w", err)
		}
		publicKey, err := jwkPublicKey(jwk)
		if err != nil {
			return err
		}
		keys[jwk.Kid] = publicKey
	}

	m.mu.Lock()
	m.current = &keyMaterial{kid: current.Kid, key: privateKey, createdAt: current.CreatedAt}
	m.publicKeys = keys
	m.loadedAt = m.clock.Now()
	m.mu.Unlock()
	return nil
}

// Current returns the kid and private key used to sign access tokens.
func (m *KeyManager) Current(ctx context.Context) (string, *rsa.PrivateKey, error) {
	m.mu.RLock()
	current := m.current
	m.mu.RUnlock()
	if current != nil && m.clock.Now().Sub(current.createdAt) < m.rotationInterval {
		return current.kid, current.key, nil
	}
	if err := m.Refresh(ctx); err != nil {
		if current != nil {
			return current.kid, current.key, nil
		}
		return "", nil, err
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.current == nil {
		return "", nil, ErrUnknownSigningKey
	}
	return m.current.kid, m.current.key, nil
}

// PublicKey returns the published verification key for kid.
func (m *KeyManager) PublicKey(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	m.mu.RLock()
	key, ok := m.publicKeys[kid]
	stale := m.clock.Now().Sub(m.loadedAt) > m.cacheTTL
	m.mu.RUnlock()
	if ok && !stale {
		return key, nil
	}
	if err := m.Refresh(ctx); err != nil {
		if ok {
			return key, nil
		}
		return nil, fmt.Errorf("%w: %s", ErrUnknownSigningKey, kid)
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	if key, ok := m.publicKeys[kid]; ok {
		return key, nil
	}
	return nil, fmt.Errorf("%w: %s", ErrUnknownSigningKey, kid)
}

// JWKS returns the public key set: current first, then next, then retired keys
// that are still inside the overlap window.
func (m *KeyManager) JWKS(ctx context.Context) (*models.JWKS, error) {
	published, err := m.repos.ListPublished(ctx, m.clock.Now().Add(-m.overlap))
	if err != nil {
		return nil, fmt.Errorf("service: list published signing keys: %w", err)
	}
	jwks := &models.JWKS{Keys: make([]models.JWK, 0, len(published))}
	for i := range published {
		var jwk models.JWK
		if err := json.Unmarshal(published[i].PublicKeyJWK, &jwk); err != nil {
			return nil, fmt.Errorf("service: decode stored jwk: %w", err)
		}
		jwks.Keys = append(jwks.Keys, jwk)
	}
	return jwks, nil
}

// publicJWK renders the public half of an RSA key as a JWK with a
// deterministic, content-derived kid.
func publicJWK(key *rsa.PublicKey) (models.JWK, error) {
	modulus := key.N.Bytes()
	if len(modulus) == 0 {
		return models.JWK{}, errors.New("service: invalid rsa public key")
	}
	sum := sha256.Sum256(modulus)
	return models.JWK{
		Kty: "RSA",
		Kid: hex.EncodeToString(sum[:8]),
		Alg: SigningAlgorithm,
		Use: "sig",
		N:   base64.RawURLEncoding.EncodeToString(modulus),
		E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()),
	}, nil
}

// jwkPublicKey rebuilds an RSA public key from a published JWK.
func jwkPublicKey(jwk models.JWK) (*rsa.PublicKey, error) {
	if jwk.Kty != "RSA" {
		return nil, fmt.Errorf("service: unsupported jwk type %q", jwk.Kty)
	}
	modulus, err := base64.RawURLEncoding.DecodeString(jwk.N)
	if err != nil {
		return nil, fmt.Errorf("service: decode jwk modulus: %w", err)
	}
	exponent, err := base64.RawURLEncoding.DecodeString(jwk.E)
	if err != nil {
		return nil, fmt.Errorf("service: decode jwk exponent: %w", err)
	}
	return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: int(new(big.Int).SetBytes(exponent).Int64())}, nil
}

// parsePrivateKey decodes the stored PEM PKCS#8 private key.
func parsePrivateKey(encoded string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(encoded))
	if block == nil {
		return nil, errors.New("service: invalid private key encoding")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("service: parse private key: %w", err)
	}
	key, ok := parsed.(*rsa.PrivateKey)
	if !ok {
		return nil, errors.New("service: private key is not RSA")
	}
	return key, nil
}
