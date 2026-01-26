package store

import (
	"context"
	"database/sql"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

type Session struct {
	ID        string
	UserID    string
	Token     string
	ClientIP  string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type SQLiteStore struct {
	db *sql.DB
}

func NewSQLiteStore(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite3", path)
	if err != nil {
		return nil, err
	}

	store := &SQLiteStore{db: db}
	if err := store.migrate(); err != nil {
		db.Close()
		return nil, err
	}

	return store, nil
}

func (s *SQLiteStore) migrate() error {
	_, err := s.db.Exec(`
		CREATE TABLE IF NOT EXISTS sessions (
			id TEXT PRIMARY KEY,
			user_id TEXT NOT NULL,
			token TEXT UNIQUE NOT NULL,
			client_ip TEXT,
			created_at DATETIME NOT NULL,
			expires_at DATETIME NOT NULL
		);
		CREATE INDEX IF NOT EXISTS idx_sessions_token ON sessions(token);
		CREATE INDEX IF NOT EXISTS idx_sessions_user_id ON sessions(user_id);
		CREATE INDEX IF NOT EXISTS idx_sessions_expires_at ON sessions(expires_at);
	`)
	return err
}

func (s *SQLiteStore) SaveSession(ctx context.Context, sess *Session) error {
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, user_id, token, client_ip, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, sess.UserID, sess.Token, sess.ClientIP, sess.CreatedAt, sess.ExpiresAt)
	return err
}

func (s *SQLiteStore) GetSessionByToken(ctx context.Context, token string) (*Session, error) {
	row := s.db.QueryRowContext(ctx, `
		SELECT id, user_id, token, client_ip, created_at, expires_at
		FROM sessions WHERE token = ?`, token)

	var sess Session
	err := row.Scan(&sess.ID, &sess.UserID, &sess.Token, &sess.ClientIP, &sess.CreatedAt, &sess.ExpiresAt)
	if err != nil {
		return nil, err
	}
	return &sess, nil
}

func (s *SQLiteStore) DeleteSession(ctx context.Context, token string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE token = ?", token)
	return err
}

func (s *SQLiteStore) DeleteExpiredSessions(ctx context.Context) (int64, error) {
	result, err := s.db.ExecContext(ctx, "DELETE FROM sessions WHERE expires_at < ?", time.Now())
	if err != nil {
		return 0, err
	}
	return result.RowsAffected()
}

func (s *SQLiteStore) Ping() error {
	return s.db.Ping()
}

func (s *SQLiteStore) Close() error {
	return s.db.Close()
}
