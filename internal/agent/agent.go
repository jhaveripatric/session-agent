package agent

import (
	"context"
	"os"

	"github.com/jhaveripatric/go-agent-kit/events"
	"github.com/jhaveripatric/go-agent-kit/lifecycle"
	"github.com/jhaveripatric/go-agent-kit/observability"
	"github.com/jhaveripatric/session-agent/internal/handlers"
	"github.com/jhaveripatric/session-agent/internal/service"
	"github.com/jhaveripatric/session-agent/internal/store"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Name    string                     `yaml:"name"`
	Logging observability.LoggingConfig `yaml:"logging"`
	AMQP    AMQPConfig                 `yaml:"amqp"`
	JWT     JWTConfig                  `yaml:"jwt"`
	Store   StoreConfig                `yaml:"store"`
}

type AMQPConfig struct {
	URL      string `yaml:"url"`
	Exchange string `yaml:"exchange"`
	Queue    string `yaml:"queue"`
}

type JWTConfig struct {
	Secret     string `yaml:"secret"`
	Issuer     string `yaml:"issuer"`
	ExpiryMins int    `yaml:"expiry_mins"`
}

type StoreConfig struct {
	Path string `yaml:"path"`
}

type Agent struct {
	config     Config
	logger     *observability.Logger
	store      *store.SQLiteStore
	jwtSvc     *service.JWTService
	sessSvc    *service.SessionService
	handlers   *handlers.LoginHandler
	subscriber events.Subscriber
	publisher  events.Publisher
}

func New(configPath string) (*Agent, error) {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	setDefaults(&cfg)
	return &Agent{config: cfg}, nil
}

func setDefaults(cfg *Config) {
	if cfg.Name == "" {
		cfg.Name = "session-agent"
	}
	if cfg.JWT.ExpiryMins == 0 {
		cfg.JWT.ExpiryMins = 60
	}
	if cfg.Store.Path == "" {
		cfg.Store.Path = "./sessions.db"
	}
}

func (a *Agent) Name() string { return a.config.Name }

func (a *Agent) Start(ctx context.Context) error {
	a.logger = observability.NewLogger(a.config.Logging)

	var err error
	a.store, err = store.NewSQLiteStore(a.config.Store.Path)
	if err != nil {
		return err
	}

	a.jwtSvc = service.NewJWTService(a.config.JWT.Secret, a.config.JWT.Issuer, a.config.JWT.ExpiryMins)
	a.sessSvc = service.NewSessionService(a.store, a.jwtSvc)

	a.publisher, err = events.NewPublisher(events.PublisherConfig{
		URL:      a.config.AMQP.URL,
		Exchange: a.config.AMQP.Exchange,
	})
	if err != nil {
		return err
	}

	a.subscriber, err = events.NewSubscriber(events.SubscriberConfig{
		URL:       a.config.AMQP.URL,
		Exchange:  a.config.AMQP.Exchange,
		QueueName: a.config.AMQP.Queue,
	})
	if err != nil {
		return err
	}

	a.handlers = handlers.NewLoginHandler(a.sessSvc, a.publisher, a.logger)

	// Subscribe to auth events
	routingKeys := []string{
		"io.agenteco.auth.login.requested.v1",
		"io.agenteco.auth.session.validate.v1",
		"io.agenteco.auth.logout.requested.v1",
	}
	if err := a.subscriber.SubscribeMultiple(routingKeys, a.handleEvent); err != nil {
		return err
	}

	a.logger.Info("starting session-agent", "queue", a.config.AMQP.Queue)
	go a.subscriber.Start(ctx)
	return nil
}

func (a *Agent) Stop(ctx context.Context) error {
	a.logger.Info("stopping session-agent")
	if a.subscriber != nil {
		a.subscriber.Close()
	}
	if a.publisher != nil {
		a.publisher.Close()
	}
	if a.store != nil {
		a.store.Close()
	}
	return nil
}

func (a *Agent) Health() lifecycle.HealthStatus {
	if a.store == nil {
		return lifecycle.HealthStatus{Alive: true, Ready: false}
	}
	if err := a.store.Ping(); err != nil {
		return lifecycle.HealthStatus{Alive: true, Ready: false, Details: map[string]any{"db": "error"}}
	}
	return lifecycle.HealthStatus{Alive: true, Ready: true, Details: map[string]any{"db": "ok"}}
}

func (a *Agent) handleEvent(ctx context.Context, event *events.Event) error {
	switch event.Type {
	case "io.agenteco.auth.login.requested.v1":
		return a.handlers.HandleLogin(ctx, event)
	case "io.agenteco.auth.session.validate.v1":
		return a.handlers.HandleValidate(ctx, event)
	case "io.agenteco.auth.logout.requested.v1":
		return a.handlers.HandleLogout(ctx, event)
	default:
		a.logger.Debug("ignoring event", "type", event.Type)
		return nil
	}
}
