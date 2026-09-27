package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/cat-cc-Lcos/FNCache/internal/agent"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func main() {
	manifest := flag.String("static-config", "", "path to a StaticRuntimeConfiguration manifest")
	flag.Parse()
	if *manifest == "" {
		fmt.Fprintln(os.Stderr, "-static-config is required")
		os.Exit(2)
	}
	if err := run(*manifest); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(path string) (err error) {
	config, err := agent.LoadStaticRuntimeManifest(path)
	if err != nil {
		return err
	}
	runtime, err := agent.NewStaticRuntime(context.Background(), config)
	if err != nil {
		return fmt.Errorf("create static runtime: %w", err)
	}
	defer func() {
		if closeErr := runtime.Close(); err == nil && closeErr != nil {
			err = fmt.Errorf("close static runtime: %w", closeErr)
		}
	}()
	result, err := runtime.RunOnce(context.Background())
	if err != nil {
		return fmt.Errorf("run static reconciliation: %w", err)
	}
	if result.State != reconcile.AgentReady {
		return fmt.Errorf("static reconciliation did not reach Ready: %s", result.State)
	}
	return nil
}
