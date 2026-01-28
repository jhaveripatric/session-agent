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

type LogoutResponse struct {
	Success bool `json:"success"`
}

type LoginHandler struct {
	sessSvc   *service.SessionService
	publisher events.Publisher
	logger    *observability.Logger
}

func NewLoginHandler(sessSvc *service.SessionService, pub events.Publisher, log *observability.Logger) *LoginHandler {
	return &LoginHandler{sessSvc: sessSvc, publisher: pub, logger: log}
}

func (h *LoginHandler) HandleLogin(ctx context.Context, request *events.Event) error {
	var req LoginRequest
	if err := unmarshalData(request.Data, &req); err != nil {
		return h.replyInvalid(ctx, request, "invalid request format")
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
		return h.replyInvalid(ctx, request, "session creation failed")
	}

	response := events.NewEvent("io.agenteco.auth.session.created.v1", "session-agent")
	response.WithData(SessionCreated{
		UserID:    session.UserID,
		Username:  req.Username,
		Roles:     session.Roles,
		Token:     session.Token,
		ExpiresAt: session.ExpiresAt,
	})

	return h.publisher.Reply(ctx, request, response)
}

func (h *LoginHandler) HandleValidate(ctx context.Context, request *events.Event) error {
	var req ValidateRequest
	if err := unmarshalData(request.Data, &req); err != nil {
		return h.replyValidate(ctx, request, ValidateResponse{Valid: false, Reason: "invalid request"})
	}

	session, err := h.sessSvc.ValidateSession(ctx, req.Token)
	if err != nil {
		h.logger.DebugContext(ctx, "session validation failed", "error", err)
		return h.replyValidate(ctx, request, ValidateResponse{Valid: false, Reason: err.Error()})
	}

	return h.replyValidate(ctx, request, ValidateResponse{
		Valid:     true,
		UserID:    session.UserID,
		Username:  session.Username,
		Roles:     session.Roles,
		ExpiresAt: session.ExpiresAt.Format(time.RFC3339),
	})
}

func (h *LoginHandler) HandleLogout(ctx context.Context, request *events.Event) error {
	var req LogoutRequest
	if err := unmarshalData(request.Data, &req); err != nil {
		return h.replyLogout(ctx, request, false)
	}

	if err := h.sessSvc.InvalidateSession(ctx, req.Token); err != nil {
		h.logger.ErrorContext(ctx, "failed to invalidate session", "error", err)
		return h.replyLogout(ctx, request, false)
	}

	h.logger.InfoContext(ctx, "session invalidated")
	return h.replyLogout(ctx, request, true)
}

func (h *LoginHandler) replyInvalid(ctx context.Context, request *events.Event, reason string) error {
	response := events.NewEvent("io.agenteco.auth.session.invalid.v1", "session-agent")
	response.WithData(SessionInvalid{Reason: reason})
	return h.publisher.Reply(ctx, request, response)
}

func (h *LoginHandler) replyValidate(ctx context.Context, request *events.Event, resp ValidateResponse) error {
	eventType := "io.agenteco.auth.session.valid.v1"
	if !resp.Valid {
		eventType = "io.agenteco.auth.session.invalid.v1"
	}
	response := events.NewEvent(eventType, "session-agent")
	response.WithData(resp)
	return h.publisher.Reply(ctx, request, response)
}

func (h *LoginHandler) replyLogout(ctx context.Context, request *events.Event, success bool) error {
	response := events.NewEvent("io.agenteco.auth.session.ended.v1", "session-agent")
	response.WithData(LogoutResponse{Success: success})
	return h.publisher.Reply(ctx, request, response)
}

func unmarshalData(data any, v any) error {
	b, err := json.Marshal(data)
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
