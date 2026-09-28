package controlplane

import (
	"context"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

func TestEndpointEnsurerAttachesPodFilters(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	endpoint := endpointEnsureTestEndpoint()
	desired := reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]resolver.Endpoint{endpoint.Pod.UID: endpoint}}
	actual := reconcile.ActualState{Programs: map[string]reconcile.ProgramState{
		"tc_init_in": {ID: 20, Name: "tc_init_in"},
		"tc_masq":    {ID: 21, Name: "tc_masq"},
	}}
	changed, err := ensurer.EnsureEndpoint(context.Background(), desired, actual, endpoint)
	if err != nil || !changed || len(backend.attached) != 2 {
		t.Fatalf("unexpected endpoint ensure: changed=%v attached=%+v err=%v", changed, backend.attached, err)
	}
	if backend.attached[0].Program != "tc_init_in" || backend.attached[0].Link.IfIndex != endpoint.PeerLink.IfIndex || backend.attached[0].Link.NetNSPath != endpoint.PeerLink.NetNSPath || backend.attached[0].Handle != 0x201 ||
		backend.attached[1].Program != "tc_masq" || backend.attached[1].Link.IfIndex != endpoint.HostLink.IfIndex || backend.attached[1].Handle != 0x200 {
		t.Fatalf("unexpected endpoint attachments: %+v", backend.attached)
	}
}

func TestEndpointEnsurerRejectsIdentityMismatchBeforeWriting(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	expected := endpointEnsureTestEndpoint()
	actualEndpoint := expected
	actualEndpoint.HostLink.IfIndex++
	desired := reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]resolver.Endpoint{expected.Pod.UID: expected}}
	actual := endpointEnsureTestActualPrograms()
	if _, err := ensurer.EnsureEndpoint(context.Background(), desired, actual, actualEndpoint); err == nil || len(backend.attached) != 0 {
		t.Fatalf("identity mismatch was not rejected before writes: err=%v attached=%+v", err, backend.attached)
	}
}

func TestEndpointEnsurerValidatesProgramsBeforeWriting(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	endpoint := endpointEnsureTestEndpoint()
	desired := reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]resolver.Endpoint{endpoint.Pod.UID: endpoint}}
	actual := endpointEnsureTestActualPrograms()
	delete(actual.Programs, "tc_masq")
	if _, err := ensurer.EnsureEndpoint(context.Background(), desired, actual, endpoint); err == nil || len(backend.attached) != 0 {
		t.Fatalf("missing program was not rejected before writes: err=%v attached=%+v", err, backend.attached)
	}
}

func TestEndpointEnsurerDisabledIsNoOp(t *testing.T) {
	backend := &fakeBaseTCBackend{}
	tc, _ := datapath.NewTCManager(backend)
	ensurer, _ := NewEndpointEnsurer(tc)
	endpoint := endpointEnsureTestEndpoint()
	desired := reconcile.DesiredState{Enabled: false, LocalEndpoints: map[string]resolver.Endpoint{endpoint.Pod.UID: endpoint}}
	changed, err := ensurer.EnsureEndpoint(context.Background(), desired, reconcile.ActualState{}, endpoint)
	if err != nil || changed || len(backend.attached) != 0 {
		t.Fatalf("disabled endpoint ensure changed state: changed=%v attached=%+v err=%v", changed, backend.attached, err)
	}
}

func endpointEnsureTestEndpoint() resolver.Endpoint {
	return resolver.Endpoint{
		Pod:  resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"},
		Node: resolver.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.244.1.10"), NetNSInode: 42,
		PeerLink: resolver.LinkIdentity{NetNSInode: 42, NetNSPath: "/proc/123/ns/net", IfIndex: 10, IfName: "eth0"},
		HostLink: resolver.LinkIdentity{IfIndex: 20, IfName: "vethweb"},
	}
}

func endpointEnsureTestActualPrograms() reconcile.ActualState {
	return reconcile.ActualState{Programs: map[string]reconcile.ProgramState{
		"tc_init_in": {ID: 20, Name: "tc_init_in"},
		"tc_masq":    {ID: 21, Name: "tc_masq"},
	}}
}
