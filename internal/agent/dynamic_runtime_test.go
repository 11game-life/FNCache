package agent

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
)

func dynamicTestConfig() config.AgentConfiguration {
	return config.AgentConfiguration{
		APIVersion: "oncache.io/v1alpha1", Kind: "AgentConfiguration", NodeName: "node-a", RuntimeEndpoint: "unix:///run/containerd/containerd.sock",
		PinRoot: "/sys/fs/bpf/oncache/v1", StateDir: "/var/lib/oncache/v1", Datapath: config.DatapathConfig{ELFPath: "/opt/oncache/bpf/tc_prog_kern.o", ELFBuildID: "sha256:test"}, Overlay: config.OverlayConfig{Type: "flannel-vxlan", Device: "auto", VXLANLinkName: "flannel.1"},
		Markers: config.MarkerConfig{Chain: "ONCACHE", Comment: "oncache:test", MissMask: 0x04, EstablishedMask: 0x08}, Heartbeat: config.HeartbeatConfig{Interval: config.Duration(time.Second), Timeout: config.Duration(5 * time.Second)},
		Kube: config.KubeConfig{MaxStaleness: config.Duration(30 * time.Second), ResyncInterval: config.Duration(10 * time.Millisecond)}, Health: config.HealthConfig{Interval: config.Duration(5 * time.Second)},
		Scan: config.ScanConfig{IncrementalInterval: config.Duration(30 * time.Second), FullInterval: config.Duration(5 * time.Minute)}, Maps: config.MapConfig{IngressCacheMaxEntries: 1024, EgressIPCacheMaxEntries: 4096, EgressCacheMaxEntries: 1024, PolicyCacheMaxEntries: 4096, DevMapMaxEntries: 8},
		Server: config.ServerConfig{ListenAddress: ":9090"}, Features: config.FeatureConfig{Enabled: true},
	}
}

func TestDynamicRuntimeStartsKubernetesControlChain(t *testing.T) {
	runtime, err := newDynamicRuntime(dynamicTestConfig(), fake.NewSimpleClientset())
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- runtime.Run(ctx) }()
	deadline := time.Now().Add(time.Second)
	for runtime.State() != KubeBootstrapReady && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.State() != KubeBootstrapReady {
		t.Fatalf("dynamic runtime state = %s", runtime.State())
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("dynamic runtime did not stop")
	}
}

func TestNewDynamicRuntimeRejectsInvalidConfiguration(t *testing.T) {
	cfg := dynamicTestConfig()
	cfg.NodeName = ""
	if _, err := newDynamicRuntime(cfg, fake.NewSimpleClientset()); err == nil {
		t.Fatal("invalid dynamic configuration was accepted")
	}
}
