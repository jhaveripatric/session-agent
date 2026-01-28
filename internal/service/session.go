package service

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/jhaveripatric/session-agent/internal/store"
)

var (
	ErrSessionNotFound = errors.New("session not found")
	ErrSessionExpired  = errors.New("session expired")
	ErrInvalidCreds    = errors.New("invalid credentials")
)

type Session struct {
	ID        string
	UserID    string
	Username  string
	Roles     []string
	Token     string
	ClientIP  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type SessionService struct {
	store  *store.SQLiteStore
	jwtSvc *JWTService
}

func NewSessionService(s *store.SQLiteStore, j *JWTService) *SessionService {
	return &SessionService{store: s, jwtSvc: j}
}

func (s *SessionService) CreateSession(ctx context.Context, userID, username string, roles []string, clientIP string) (*Session, error) {
	tokenPair, err := s.jwtSvc.Generate(userID, username, roles)
	if err != nil {
		return nil, err
	}

	sess := &store.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     tokenPair.AccessToken,
		ClientIP:  clientIP,
		CreatedAt: time.Now(),
		ExpiresAt: tokenPair.ExpiresAt,
	}

	if err := s.store.SaveSession(ctx, sess); err != nil {
		return nil, err
	}

	return &Session{
		ID:        sess.ID,
		UserID:    sess.UserID,
		Username:  username,
		Roles:     roles,
		Token:     sess.Token,
		ClientIP:  sess.ClientIP,
		CreatedAt: sess.CreatedAt,
		ExpiresAt: sess.ExpiresAt,
	}, nil
}

func (s *SessionService) ValidateSession(ctx context.Context, token string) (*Session, error) {
	claims, err := s.jwtSvc.Validate(token)
	if err != nil {
		return nil, err
	}

	sess, err := s.store.GetSessionByToken(ctx, token)
	if err != nil {
		return nil, ErrSessionNotFound
	}

	if time.Now().After(sess.ExpiresAt) {
		return nil, ErrSessionExpired
	}

	return &Session{
		ID:        sess.ID,
		UserID:    claims.UserID,
		Username:  claims.Username,
		Roles:     claims.Roles,
		Token:     sess.Token,
		ClientIP:  sess.ClientIP,
		CreatedAt: sess.CreatedAt,
		ExpiresAt: sess.ExpiresAt,
	}, nil
}

func (s *SessionService) InvalidateSession(ctx context.Context, token string) error {
	return s.store.DeleteSession(ctx, token)
}

func (s *SessionService) CleanupExpired(ctx context.Context) (int64, error) {
	return s.store.DeleteExpiredSessions(ctx)
}
