package agent

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type dynamicObserverPreflight struct{}

func (dynamicObserverPreflight) Check(context.Context, discovery.PreflightRequest) (discovery.CapabilityReport, error) {
	return discovery.CapabilityReport{Supported: true}, nil
}

type dynamicObserverFlannel struct{}

func (dynamicObserverFlannel) Discover(context.Context, flannel.DiscoveryRequest) (flannel.FlannelConfig, error) {
	return flannel.FlannelConfig{BackendType: "vxlan", VXLANLink: resolver.LinkIdentity{IfIndex: 9, IfName: "flannel.1"}, UnderlayLink: resolver.LinkIdentity{IfIndex: 2, IfName: "eth0", MAC: []byte{1, 2, 3, 4, 5, 6}}, UnderlayIPv4: netip.MustParseAddr("192.0.2.10"), PodCIDR: netip.MustParsePrefix("10.42.0.0/24"), VNI: 1, UDPPort: 8472, MTU: 1450, MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft", Fingerprint: "dynamic"}, nil
}

type dynamicObserverEndpoints struct{}

func (dynamicObserverEndpoints) Scan(context.Context, []resolver.PodSnapshot) (resolver.EndpointScanResult, error) {
	return resolver.EndpointScanResult{Endpoints: map[string]resolver.Endpoint{"pod-local": {Pod: resolver.PodIdentity{Namespace: "default", Name: "local", UID: "pod-local"}, Node: resolver.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 7}, HostLink: resolver.LinkIdentity{IfIndex: 8}}}}, nil
}

type dynamicObserverPins struct{}

func (dynamicObserverPins) Scan(context.Context) (reconcile.ActualState, error) {
	return reconcile.ActualState{Programs: map[string]reconcile.ProgramState{"tc_init_e": {ID: 1, Name: "tc_init_e"}, "tc_restore": {ID: 2, Name: "tc_restore"}, "tc_init_in": {ID: 3, Name: "tc_init_in"}, "tc_masq": {ID: 4, Name: "tc_masq"}}, Maps: map[string]reconcile.MapState{}}, nil
}

type dynamicObserverTC struct{}

func (dynamicObserverTC) Scan(context.Context, []resolver.LinkIdentity) (reconcile.ActualState, error) {
	return reconcile.ActualState{}, nil
}

type dynamicObserverRules struct{}

func (dynamicObserverRules) Scan(context.Context, flannel.MarkerRuleSpec) (reconcile.RuleState, error) {
	return reconcile.RuleState{Present: true}, nil
}

func TestDynamicObserverBuildsLatestDesiredAndActualState(t *testing.T) {
	cfg := dynamicTestConfig()
	store := kube.NewSnapshotStore()
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-a"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertNode(kube.NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-b", UID: "node-b"}, InternalIPv4: netip.MustParseAddr("192.0.2.11")}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: "local", UID: "pod-local"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.42.0.2"), Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	if err := store.UpsertPod(resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: "remote", UID: "pod-remote"}, NodeName: "node-b", PodIPv4: netip.MustParseAddr("10.42.1.2"), Phase: "Running"}); err != nil {
		t.Fatal(err)
	}
	sources := controlplane.Sources{Preflight: dynamicObserverPreflight{}, Flannel: dynamicObserverFlannel{}, Endpoints: dynamicObserverEndpoints{}, Pins: dynamicObserverPins{}, TC: dynamicObserverTC{}, Rules: dynamicObserverRules{}}
	observer, err := NewDynamicObserver(cfg, store, sources)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := observer.Desired(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := desired.LocalEndpoints["pod-local"]; !ok {
		t.Fatalf("local endpoint missing: %#v", desired.LocalEndpoints)
	}
	if desired.RemoteEndpoints[netip.MustParseAddr("10.42.1.2")].NodeIPv4 != netip.MustParseAddr("192.0.2.11") {
		t.Fatalf("remote mapping missing: %#v", desired.RemoteEndpoints)
	}
	if _, err := observer.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
}
