package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cat-cc-Lcos/FNCache/internal/agent"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func main() {
	manifest := flag.String("static-config", "", "path to a StaticRuntimeConfiguration manifest")
	configPath := flag.String("config", "", "path to an AgentConfiguration for dynamic Kubernetes mode")
	flag.Parse()
	if (*manifest == "") == (*configPath == "") {
		fmt.Fprintln(os.Stderr, "exactly one of -static-config or -config is required")
		os.Exit(2)
	}
	var err error
	if *manifest != "" {
		err = run(*manifest)
	} else {
		err = runDynamic(*configPath)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func runDynamic(path string) error {
	runtime, err := agent.NewDynamicRuntime(path)
	if err != nil {
		return fmt.Errorf("create dynamic runtime: %w", err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runtime.Run(ctx)
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
