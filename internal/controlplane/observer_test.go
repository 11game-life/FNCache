package controlplane

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type fakePreflight struct {
	report discovery.CapabilityReport
	err    error
	calls  int
}

func (f *fakePreflight) Check(context.Context, discovery.PreflightRequest) (discovery.CapabilityReport, error) {
	f.calls++
	return f.report, f.err
}

type fakeFlannel struct {
	config flannel.FlannelConfig
	err    error
	calls  int
}

func (f *fakeFlannel) Discover(context.Context, flannel.DiscoveryRequest) (flannel.FlannelConfig, error) {
	f.calls++
	return f.config, f.err
}

type fakeEndpoints struct {
	result resolver.EndpointScanResult
	err    error
	pods   []resolver.PodSnapshot
}

func (f *fakeEndpoints) Scan(_ context.Context, pods []resolver.PodSnapshot) (resolver.EndpointScanResult, error) {
	f.pods = pods
	return f.result, f.err
}

type fakePins struct {
	actual reconcile.ActualState
	err    error
}

func (f *fakePins) Scan(context.Context) (reconcile.ActualState, error) { return f.actual, f.err }

type fakeTC struct {
	actual reconcile.ActualState
	err    error
	links  []resolver.LinkIdentity
}

func (f *fakeTC) Scan(_ context.Context, links []resolver.LinkIdentity) (reconcile.ActualState, error) {
	f.links = links
	return f.actual, f.err
}

type fakeRules struct {
	state reconcile.RuleState
	err   error
}

func (f *fakeRules) Scan(context.Context, flannel.MarkerRuleSpec) (reconcile.RuleState, error) {
	return f.state, f.err
}

func TestObserverDiscoverBuildsDesiredState(t *testing.T) {
	preflight := &fakePreflight{report: discovery.CapabilityReport{Supported: true}}
	flannelSource := &fakeFlannel{config: testFlannelConfig()}
	endpoint := testEndpoint()
	endpoints := &fakeEndpoints{result: resolver.EndpointScanResult{
		Endpoints: map[string]resolver.Endpoint{endpoint.Pod.UID: endpoint},
		Skipped:   map[string]error{"pod-pending": resolver.ErrEndpointNotReady},
	}}
	input := testInput()
	observer, err := NewObserver(testSources(preflight, flannelSource, endpoints), input)
	if err != nil {
		t.Fatal(err)
	}
	desired, err := observer.Discover(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if !desired.Enabled || desired.Generation != 7 || desired.Datapath.ABI != reconcile.BPFABIVersion ||
		desired.Datapath.VXLANVNI != 1 || desired.Flannel.Fingerprint != "flannel-fp" {
		t.Fatalf("unexpected desired state: %+v", desired)
	}
	if _, ok := desired.LocalEndpoints[endpoint.Pod.UID]; !ok {
		t.Fatalf("ready endpoint missing: %+v", desired.LocalEndpoints)
	}
	if _, ok := desired.LocalEndpoints["pod-pending"]; ok {
		t.Fatalf("skipped endpoint was included: %+v", desired.LocalEndpoints)
	}
	if !reflect.DeepEqual(endpoints.pods, input.Pods) {
		t.Fatalf("unexpected endpoint inputs: got=%+v want=%+v", endpoints.pods, input.Pods)
	}
}

func TestObserverDiscoverStopsSafelyWhenUnsupported(t *testing.T) {
	preflight := &fakePreflight{report: discovery.CapabilityReport{Supported: false}}
	flannelSource := &fakeFlannel{config: testFlannelConfig()}
	endpoints := &fakeEndpoints{}
	observer, err := NewObserver(testSources(preflight, flannelSource, endpoints), testInput())
	if err != nil {
		t.Fatal(err)
	}
	desired, err := observer.Discover(context.Background())
	if err != nil || desired.Enabled || flannelSource.calls != 0 || endpoints.pods != nil {
		t.Fatalf("unsupported discovery was not stopped: desired=%+v err=%v flannelCalls=%d pods=%v", desired, err, flannelSource.calls, endpoints.pods)
	}
}

func TestObserverScanMergesReadSideState(t *testing.T) {
	pins := &fakePins{actual: reconcile.ActualState{Maps: map[string]reconcile.MapState{"control_map": {ID: 7}}}}
	tc := &fakeTC{actual: reconcile.ActualState{Attachments: []reconcile.AttachmentState{{Handle: 0x100}}}}
	rules := &fakeRules{state: reconcile.RuleState{Present: true, Fingerprint: "rule-fp"}}
	sources := testSources(&fakePreflight{report: discovery.CapabilityReport{Supported: true}}, &fakeFlannel{config: testFlannelConfig()}, &fakeEndpoints{})
	sources.Pins, sources.TC, sources.Rules = pins, tc, rules
	input := testInput()
	observer, err := NewObserver(sources, input)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := observer.Scan(context.Background())
	if err != nil || actual.Maps["control_map"].ID != 7 || len(actual.Attachments) != 1 ||
		actual.Attachments[0].Handle != 0x100 || actual.FlannelRule.Fingerprint != "rule-fp" {
		t.Fatalf("unexpected actual state: actual=%+v err=%v", actual, err)
	}
	if !reflect.DeepEqual(tc.links, input.TCLinks) {
		t.Fatalf("unexpected TC links: got=%+v want=%+v", tc.links, input.TCLinks)
	}
}

func TestObserverRefreshesTCLinksAfterEndpointRediscovery(t *testing.T) {
	endpoint := testEndpoint()
	base := resolver.LinkIdentity{IfIndex: 2, IfName: "eth0"}
	oldPeer := resolver.LinkIdentity{NetNSInode: 42, IfIndex: 11, IfName: "eth0"}
	oldHost := resolver.LinkIdentity{IfIndex: 21, IfName: "veth-old"}
	pins := &fakePins{}
	tc := &fakeTC{}
	rules := &fakeRules{}
	endpoints := &fakeEndpoints{result: resolver.EndpointScanResult{
		Endpoints: map[string]resolver.Endpoint{endpoint.Pod.UID: endpoint},
	}}
	sources := testSources(&fakePreflight{report: discovery.CapabilityReport{Supported: true}}, &fakeFlannel{config: testFlannelConfig()}, endpoints)
	sources.Pins, sources.TC, sources.Rules = pins, tc, rules
	input := testInput()
	input.TCLinks = []resolver.LinkIdentity{base, oldPeer, oldHost}
	input.BaseTCLinks = []resolver.LinkIdentity{base}
	observer, err := NewObserver(sources, input)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Discover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := observer.Scan(context.Background()); err != nil {
		t.Fatal(err)
	}
	want := []resolver.LinkIdentity{base, endpoint.PeerLink, endpoint.HostLink}
	if !reflect.DeepEqual(tc.links, want) {
		t.Fatalf("observer retained stale endpoint links: got=%+v want=%+v", tc.links, want)
	}
}

func TestObserverPropagatesScanError(t *testing.T) {
	want := errors.New("pins unavailable")
	sources := testSources(&fakePreflight{report: discovery.CapabilityReport{Supported: true}}, &fakeFlannel{config: testFlannelConfig()}, &fakeEndpoints{})
	sources.Pins = &fakePins{err: want}
	observer, _ := NewObserver(sources, testInput())
	if _, err := observer.Scan(context.Background()); !errors.Is(err, want) {
		t.Fatalf("expected pin scan error: %v", err)
	}
}

func testSources(preflight *fakePreflight, flannelSource *fakeFlannel, endpoints *fakeEndpoints) Sources {
	return Sources{Preflight: preflight, Flannel: flannelSource, Endpoints: endpoints, Pins: &fakePins{}, TC: &fakeTC{}, Rules: &fakeRules{}}
}

func testInput() ObservationInput {
	return ObservationInput{
		Generation:       7,
		PreflightRequest: discovery.PreflightRequest{Node: resolver.NodeIdentity{Name: "node-a"}, PinRoot: "/sys/fs/bpf/oncache/v1", StateDir: "/var/lib/oncache/v1", RuntimeURI: "unix:///run/containerd/containerd.sock", Overlay: "flannel-vxlan"},
		FlannelRequest:   flannel.DiscoveryRequest{VXLANLinkName: "flannel.1", UnderlayDevice: "eth0", MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft"},
		MarkerRule:       flannel.MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"},
		Pods:             []resolver.PodSnapshot{{Identity: resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"}, NodeName: "node-a", PodIPv4: netip.MustParseAddr("10.244.1.10"), Phase: "Running"}},
		TCLinks:          []resolver.LinkIdentity{{IfIndex: 2, IfName: "eth0"}},
	}
}

func testFlannelConfig() flannel.FlannelConfig {
	return flannel.FlannelConfig{BackendType: "vxlan", VXLANLink: resolver.LinkIdentity{IfIndex: 8, IfName: "flannel.1"}, UnderlayLink: resolver.LinkIdentity{IfIndex: 2, IfName: "eth0"}, UnderlayIPv4: netip.MustParseAddr("192.0.2.10"), PodCIDR: netip.MustParsePrefix("10.244.2.0/24"), VNI: 1, UDPPort: 8472, MTU: 1450, MissMask: 0x04, EstablishedMask: 0x08, IPTablesBackend: "iptables-nft", Fingerprint: "flannel-fp"}
}

func testEndpoint() resolver.Endpoint {
	return resolver.Endpoint{Pod: resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"}, Node: resolver.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.244.1.10"), NetNSInode: 42, PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 10, IfName: "eth0"}, HostLink: resolver.LinkIdentity{IfIndex: 20, IfName: "vethweb"}}
}
