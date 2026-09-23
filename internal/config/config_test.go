package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadDefaultsAndEnvironment(t *testing.T) {
	t.Setenv("ONCACHE_CONFIG", "")
	t.Setenv("ONCACHE_NODE_NAME", "node-a")
	t.Setenv("ONCACHE_LOG_LEVEL", "debug")
	t.Setenv("ONCACHE_INSTALLATION_ID", "install-a")

	cfg, err := Load("")
	if err != nil {
		t.Fatal(err)
	}
	if cfg.NodeName != "node-a" || cfg.LogLevel != "debug" || cfg.InstallationID != "install-a" {
		t.Fatalf("environment overrides not applied: %+v", cfg)
	}
}

func TestLoadRejectsUnknownField(t *testing.T) {
	path := writeConfig(t, "nodeName: node-a\nunknown: true\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestLoadRejectsDangerousPath(t *testing.T) {
	path := writeConfig(t, "nodeName: node-a\npinRoot: /sys/fs/bpf/oncache\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected pinRoot validation error")
	}
}

func TestLoadRejectsHeartbeatConstraint(t *testing.T) {
	path := writeConfig(t, "nodeName: node-a\nheartbeat:\n  interval: 2s\n  timeout: 5s\n")
	if _, err := Load(path); err == nil {
		t.Fatal("expected heartbeat validation error")
	}
}

func writeConfig(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agent.yaml")
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
	return path
}
