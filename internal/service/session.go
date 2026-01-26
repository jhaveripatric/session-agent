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

func (s *SessionService) CreateSession(ctx context.Context, userID, username, clientIP string) (*Session, error) {
	token, expiresAt, err := s.jwtSvc.Generate(userID, username)
	if err != nil {
		return nil, err
	}

	sess := &store.Session{
		ID:        uuid.New().String(),
		UserID:    userID,
		Token:     token,
		ClientIP:  clientIP,
		CreatedAt: time.Now(),
		ExpiresAt: expiresAt,
	}

	if err := s.store.SaveSession(ctx, sess); err != nil {
		return nil, err
	}

	return &Session{
		ID:        sess.ID,
		UserID:    sess.UserID,
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
