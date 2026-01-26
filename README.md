# session-agent

JWT session management agent for the agent ecosystem. Handles user authentication by issuing and validating JWT tokens.

## Features

- JWT token generation with configurable expiry
- Session storage in SQLite
- Token validation and refresh
- Session invalidation (logout)
- Automatic cleanup of expired sessions

## Events

### Subscribes To

| Event | Description |
|-------|-------------|
| `io.agenteco.auth.login.requested.v1` | Process login request, create session |
| `io.agenteco.auth.session.validate.v1` | Validate an existing session token |
| `io.agenteco.auth.logout.requested.v1` | Invalidate a session |

### Publishes

| Event | Description |
|-------|-------------|
| `io.agenteco.auth.session.created.v1` | Session successfully created with token |
| `io.agenteco.auth.session.invalid.v1` | Session validation failed |
| `io.agenteco.auth.session.valid.v1` | Session is valid |

## Configuration

```yaml
name: session-agent

health:
  port: 8081

amqp:
  url: amqp://guest:guest@localhost:5672/
  exchange: agenteco.events
  queue: session-agent

jwt:
  secret: your-secret-key
  issuer: agenteco
  expiry_mins: 60

store:
  path: ./sessions.db
```

## Usage

### Build

```bash
go build -o bin/session-agent ./cmd/session-agent
```

### Run

```bash
./bin/session-agent config.yaml
```

### With agent-app-kit

```bash
# Add from registry
agent-app agent add session-agent@1.0.0

# Or add locally
agent-app agent add ./session-agent
```

## Event Payloads

### Login Request

```json
{
  "username": "user@example.com",
  "password": "secret",
  "client_ip": "192.168.1.1"
}
```

### Session Created

```json
{
  "user_id": "uuid",
  "username": "user@example.com",
  "token": "jwt-token",
  "expires_at": "2024-01-01T12:00:00Z"
}
```

### Validate Request

```json
{
  "token": "jwt-token"
}
```

## License

MIT
