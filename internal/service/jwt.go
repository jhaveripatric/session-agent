package service

import (
	"crypto/ecdsa"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/jhaveripatric/session-agent/internal/crypto"
)

var (
	ErrInvalidToken = errors.New("invalid token")
	ErrExpiredToken = errors.New("token expired")
)

// Claims represents JWT claims with user info.
type Claims struct {
	UserID   string   `json:"user_id"`
	Username string   `json:"username"`
	Roles    []string `json:"roles,omitempty"`
	jwt.RegisteredClaims
}

// JWTService handles ES256 JWT signing and validation.
type JWTService struct {
	privateKey    *ecdsa.PrivateKey
	issuer        string
	audience      string
	keyID         string
	accessExpiry  time.Duration
	refreshExpiry time.Duration
}

// JWTConfig holds JWT service configuration.
type JWTConfig struct {
	PrivateKeyPath string
	Issuer         string
	Audience       string
	KeyID          string
	AccessExpiry   time.Duration
	RefreshExpiry  time.Duration
}

// NewJWTService creates a new ES256 JWT service.
func NewJWTService(cfg JWTConfig) (*JWTService, error) {
	privateKey, err := crypto.LoadPrivateKey(cfg.PrivateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("load private key: %w", err)
	}

	return &JWTService{
		privateKey:    privateKey,
		issuer:        cfg.Issuer,
		audience:      cfg.Audience,
		keyID:         cfg.KeyID,
		accessExpiry:  cfg.AccessExpiry,
		refreshExpiry: cfg.RefreshExpiry,
	}, nil
}

// TokenPair contains access and refresh tokens.
type TokenPair struct {
	AccessToken  string
	RefreshToken string
	ExpiresAt    time.Time
}

// Generate creates a token pair for the given user.
func (s *JWTService) Generate(userID, username string, roles []string) (*TokenPair, error) {
	now := time.Now()
	accessExp := now.Add(s.accessExpiry)

	// Access token claims
	accessClaims := Claims{
		UserID:   userID,
		Username: username,
		Roles:    roles,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    s.issuer,
			Subject:   userID,
			Audience:  jwt.ClaimStrings{s.audience},
			ExpiresAt: jwt.NewNumericDate(accessExp),
			IssuedAt:  jwt.NewNumericDate(now),
			ID:        uuid.New().String(),
		},
	}

	// Create access token with ES256
	accessToken := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	accessToken.Header["kid"] = s.keyID

	accessSigned, err := accessToken.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign access token: %w", err)
	}

	// Refresh token (simpler claims, longer expiry)
	refreshClaims := jwt.RegisteredClaims{
		Issuer:    s.issuer,
		Subject:   userID,
		Audience:  jwt.ClaimStrings{s.audience},
		ExpiresAt: jwt.NewNumericDate(now.Add(s.refreshExpiry)),
		IssuedAt:  jwt.NewNumericDate(now),
		ID:        uuid.New().String(),
	}

	refreshToken := jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaims)
	refreshToken.Header["kid"] = s.keyID

	refreshSigned, err := refreshToken.SignedString(s.privateKey)
	if err != nil {
		return nil, fmt.Errorf("sign refresh token: %w", err)
	}

	return &TokenPair{
		AccessToken:  accessSigned,
		RefreshToken: refreshSigned,
		ExpiresAt:    accessExp,
	}, nil
}

// Validate verifies a token and returns claims.
func (s *JWTService) Validate(tokenStr string) (*Claims, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &Claims{}, func(t *jwt.Token) (any, error) {
		if t.Method.Alg() != "ES256" {
			return nil, ErrInvalidToken
		}
		return &s.privateKey.PublicKey, nil
	})

	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return nil, ErrExpiredToken
		}
		return nil, ErrInvalidToken
	}

	claims, ok := token.Claims.(*Claims)
	if !ok || !token.Valid {
		return nil, ErrInvalidToken
	}

	return claims, nil
}

// ExpiryDuration returns the access token expiry duration.
func (s *JWTService) ExpiryDuration() time.Duration {
	return s.accessExpiry
}
