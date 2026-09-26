package controlplane

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type fakeMapStore struct {
	values map[string][]byte
	keys   map[string][]byte
	calls  []string
}

func (s *fakeMapStore) Ensure(_ context.Context, name string, key, value []byte) (bool, error) {
	if s.values == nil {
		s.values = make(map[string][]byte)
		s.keys = make(map[string][]byte)
	}
	if existing, ok := s.values[name]; ok && string(existing) == string(value) && string(s.keys[name]) == string(key) {
		return false, nil
	}
	s.calls = append(s.calls, name)
	s.keys[name] = append([]byte(nil), key...)
	s.values[name] = append([]byte(nil), value...)
	return true, nil
}

func TestMapEnsurerWritesABIEntries(t *testing.T) {
	store := &fakeMapStore{}
	ensurer, err := NewMapEnsurer(store)
	if err != nil {
		t.Fatal(err)
	}
	endpoint := mapEnsureTestEndpoint()
	desired := mapEnsureDesired(endpoint)
	changed, err := ensurer.EnsureEndpointMaps(context.Background(), desired, mapEnsureActual(), endpoint, true)
	if err != nil || !changed || len(store.calls) != 2 {
		t.Fatalf("unexpected Map ensure: changed=%v calls=%v err=%v", changed, store.calls, err)
	}
	if len(store.keys["ingress_cache"]) != 4 || len(store.values["ingress_cache"]) != 16 ||
		len(store.keys["devmap"]) != 4 || len(store.values["devmap"]) != 12 {
		t.Fatalf("unexpected ABI sizes: keys=%v values=%v", store.keys, store.values)
	}
	ingress := store.values["ingress_cache"]
	if binary.NativeEndian.Uint32(ingress[:4]) != uint32(endpoint.HostLink.IfIndex) ||
		string(ingress[4:10]) != string(endpoint.PeerLink.MAC) || string(ingress[10:16]) != string(endpoint.HostLink.MAC) {
		t.Fatalf("unexpected ingress value: %v", ingress)
	}
	device := store.values["devmap"]
	if binary.NativeEndian.Uint32(store.keys["devmap"]) != 2 ||
		string(device[:4]) != string([]byte{192, 0, 2, 10}) || string(device[4:10]) != string([]byte{2, 0, 0, 0, 0, 1}) ||
		device[10] != 0 || device[11] != 0 {
		t.Fatalf("unexpected devmap entry: key=%v value=%v", store.keys["devmap"], device)
	}
}

func TestMapEnsurerIsIdempotentAndRequiresDisabledPath(t *testing.T) {
	store := &fakeMapStore{}
	ensurer, _ := NewMapEnsurer(store)
	endpoint := mapEnsureTestEndpoint()
	desired := mapEnsureDesired(endpoint)
	if _, err := ensurer.EnsureEndpointMaps(context.Background(), desired, mapEnsureActual(), endpoint, false); err == nil || len(store.calls) != 0 {
		t.Fatalf("Map update ran while fast path was enabled: err=%v calls=%v", err, store.calls)
	}
	if _, err := ensurer.EnsureEndpointMaps(context.Background(), desired, mapEnsureActual(), endpoint, true); err != nil {
		t.Fatal(err)
	}
	changed, err := ensurer.EnsureEndpointMaps(context.Background(), desired, mapEnsureActual(), endpoint, true)
	if err != nil || changed || len(store.calls) != 2 {
		t.Fatalf("identical Map state was rewritten: changed=%v calls=%v err=%v", changed, store.calls, err)
	}
}

func TestMapEnsurerRejectsInvalidIdentityOrSchema(t *testing.T) {
	store := &fakeMapStore{}
	ensurer, _ := NewMapEnsurer(store)
	endpoint := mapEnsureTestEndpoint()
	desired := mapEnsureDesired(endpoint)
	badEndpoint := endpoint
	badEndpoint.HostLink.IfIndex++
	if _, err := ensurer.EnsureEndpointMaps(context.Background(), desired, mapEnsureActual(), badEndpoint, true); err == nil || len(store.calls) != 0 {
		t.Fatalf("identity mismatch was accepted: err=%v calls=%v", err, store.calls)
	}
	actual := mapEnsureActual()
	actual.Maps["devmap"] = reconcile.MapState{Name: "devmap", KeySize: 4, ValueSize: 8, MaxEntries: 8}
	if _, err := ensurer.EnsureEndpointMaps(context.Background(), desired, actual, endpoint, true); err == nil || len(store.calls) != 0 {
		t.Fatalf("Map schema mismatch was accepted: err=%v calls=%v", err, store.calls)
	}
}

func mapEnsureTestEndpoint() resolver.Endpoint {
	return resolver.Endpoint{
		Pod:  resolver.PodIdentity{Namespace: "default", Name: "web", UID: "pod-a"},
		Node: resolver.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.244.1.10"), NetNSInode: 42,
		PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 10, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 2}},
		HostLink: resolver.LinkIdentity{IfIndex: 20, IfName: "vethweb", MAC: []byte{2, 0, 0, 0, 0, 3}},
	}
}

func mapEnsureDesired(endpoint resolver.Endpoint) reconcile.DesiredState {
	return reconcile.DesiredState{Enabled: true, LocalEndpoints: map[string]resolver.Endpoint{endpoint.Pod.UID: endpoint}, Flannel: reconcile.FlannelState{UnderlayLink: resolver.LinkIdentity{IfIndex: 2, IfName: "eth0", MAC: []byte{2, 0, 0, 0, 0, 1}}, UnderlayIPv4: netip.MustParseAddr("192.0.2.10")}}
}

func mapEnsureActual() reconcile.ActualState {
	return reconcile.ActualState{Maps: map[string]reconcile.MapState{
		"ingress_cache": {Name: "ingress_cache", KeySize: 4, ValueSize: 16, MaxEntries: 1024},
		"devmap":        {Name: "devmap", KeySize: 4, ValueSize: 12, MaxEntries: 8},
	}}
}
