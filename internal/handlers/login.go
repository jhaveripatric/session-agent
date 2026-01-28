package handlers

import (
	"context"
	"encoding/json"
	"time"

	"github.com/google/uuid"
	"github.com/jhaveripatric/go-agent-kit/events"
	"github.com/jhaveripatric/go-agent-kit/observability"
	"github.com/jhaveripatric/session-agent/internal/service"
)

type LoginRequest struct {
	Username string   `json:"username"`
	Password string   `json:"password"`
	ClientIP string   `json:"_client_ip"`
	UserID   string   `json:"user_id,omitempty"`
	Roles    []string `json:"roles,omitempty"`
}

type SessionCreated struct {
	UserID    string    `json:"user_id"`
	Username  string    `json:"username"`
	Roles     []string  `json:"roles,omitempty"`
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type SessionInvalid struct {
	Reason string `json:"reason"`
}

type ValidateRequest struct {
	Token string `json:"token"`
}

type ValidateResponse struct {
	Valid     bool     `json:"valid"`
	UserID    string   `json:"user_id,omitempty"`
	Username  string   `json:"username,omitempty"`
	Roles     []string `json:"roles,omitempty"`
	ExpiresAt string   `json:"expires_at,omitempty"`
	Reason    string   `json:"reason,omitempty"`
}

type LogoutRequest struct {
	Token string `json:"token"`
}

type LoginHandler struct {
	sessSvc   *service.SessionService
	publisher events.Publisher
	logger    *observability.Logger
}

func NewLoginHandler(sessSvc *service.SessionService, pub events.Publisher, log *observability.Logger) *LoginHandler {
	return &LoginHandler{sessSvc: sessSvc, publisher: pub, logger: log}
}

func (h *LoginHandler) HandleLogin(ctx context.Context, event *events.Event) error {
	var req LoginRequest
	if err := unmarshalData(event.Data, &req); err != nil {
		return h.emitInvalid(ctx, "invalid request format")
	}

	h.logger.InfoContext(ctx, "login request", "username", req.Username, "client_ip", req.ClientIP)

	userID := req.UserID
	if userID == "" {
		userID = uuid.New().String()
	}

	// Default roles if not specified
	roles := req.Roles
	if len(roles) == 0 {
		roles = []string{"user"}
	}

	session, err := h.sessSvc.CreateSession(ctx, userID, req.Username, roles, req.ClientIP)
	if err != nil {
		h.logger.ErrorContext(ctx, "failed to create session", "error", err)
		return h.emitInvalid(ctx, "session creation failed")
	}

	return h.emitCreated(ctx, SessionCreated{
		UserID:    session.UserID,
		Username:  req.Username,
		Roles:     session.Roles,
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
	})
}

func (h *LoginHandler) HandleValidate(ctx context.Context, event *events.Event) error {
	var req ValidateRequest
	if err := unmarshalData(event.Data, &req); err != nil {
		return h.emitValidateResponse(ctx, ValidateResponse{Valid: false, Reason: "invalid request"})
	}

	session, err := h.sessSvc.ValidateSession(ctx, req.Token)
	if err != nil {
		h.logger.DebugContext(ctx, "session validation failed", "error", err)
		return h.emitValidateResponse(ctx, ValidateResponse{Valid: false, Reason: err.Error()})
	}

	return h.emitValidateResponse(ctx, ValidateResponse{
		Valid:     true,
		UserID:    session.UserID,
		Username:  session.Username,
		Roles:     session.Roles,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
	})
}

func (h *LoginHandler) HandleLogout(ctx context.Context, event *events.Event) error {
	var req LogoutRequest
	if err := unmarshalData(event.Data, &req); err != nil {
		return nil
	}

	if err := h.sessSvc.InvalidateSession(ctx, req.Token); err != nil {
		h.logger.ErrorContext(ctx, "failed to invalidate session", "error", err)
	}

	h.logger.InfoContext(ctx, "session invalidated")
	return nil
}

func (h *LoginHandler) emitCreated(ctx context.Context, data SessionCreated) error {
	event := events.NewEvent("io.agenteco.auth.session.created.v1", "session-agent")
	event.WithData(data)
	return h.publisher.Publish(ctx, event)
}

func (h *LoginHandler) emitInvalid(ctx context.Context, reason string) error {
	event := events.NewEvent("io.agenteco.auth.session.invalid.v1", "session-agent")
	event.WithData(SessionInvalid{Reason: reason})
	return h.publisher.Publish(ctx, event)
}

func (h *LoginHandler) emitValidateResponse(ctx context.Context, resp ValidateResponse) error {
	eventType := "io.agenteco.auth.session.valid.v1"
	if !resp.Valid {
		eventType = "io.agenteco.auth.session.invalid.v1"
	}
	event := events.NewEvent(eventType, "session-agent")
	event.WithData(resp)
	return h.publisher.Publish(ctx, event)
}

func unmarshalData(data any, v any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
