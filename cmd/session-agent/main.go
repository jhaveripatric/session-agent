package main

import (
	"context"
	"log"
	"os"

	"github.com/jhaveripatric/go-agent-kit/lifecycle"
	"github.com/jhaveripatric/session-agent/internal/agent"
)

func main() {
	configPath := "config.yaml"
	if len(os.Args) > 1 {
		configPath = os.Args[1]
	}

	a, err := agent.New(configPath)
	if err != nil {
		log.Fatalf("failed to create agent: %v", err)
	}

	runner := lifecycle.NewRunner(a)
	if err := runner.Run(context.Background()); err != nil {
		log.Fatalf("agent failed: %v", err)
	}
}
