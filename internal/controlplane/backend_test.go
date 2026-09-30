package controlplane

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type backendObserver struct {
	desired reconcile.DesiredState
	actual  reconcile.ActualState
	scans   int
}

func (f *backendObserver) Discover(context.Context) (reconcile.DesiredState, error) {
	return f.desired, nil
}
func (f *backendObserver) Scan(context.Context) (reconcile.ActualState, error) {
	f.scans++
	return f.actual, nil
}

type backendControl struct{ disabled bool }

func (f *backendControl) Disable(context.Context) error { f.disabled = true; return nil }

type backendCollection struct{ calls int }

func (f *backendCollection) EnsureCollection(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	f.calls++
	return true, nil
}

type backendMarker struct{ calls int }

func (f *backendMarker) EnsureMarker(context.Context, reconcile.DesiredState) (bool, error) {
	f.calls++
	return true, nil
}

type backendEnsurer struct {
	calls int
	err   error
}

type backendRemover struct {
	calls int
	uids  []string
}

func (r *backendRemover) Remove(_ context.Context, owned reconcile.OwnedEndpoint, _ reconcile.ActualState, _ reconcile.DesiredState) error {
	r.calls++
	r.uids = append(r.uids, owned.PodUID)
	return nil
}

func (f *backendEnsurer) EnsureBase(context.Context, reconcile.DesiredState, reconcile.ActualState) (bool, error) {
	f.calls++
	return true, f.err
}

func (f *backendEnsurer) EnsureEndpoint(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint) (bool, error) {
	f.calls++
	return true, f.err
}

func (f *backendEnsurer) EnsureEndpointMaps(context.Context, reconcile.DesiredState, reconcile.ActualState, resolver.Endpoint, bool) (bool, error) {
	f.calls++
	return true, f.err
}

func TestFirstPassBackendRunsAllStagesAndPublishesLastScan(t *testing.T) {
	desired := publishTestDesired()
	observer := &backendObserver{desired: desired, actual: publishTestActual(desired)}
	control := &backendControl{}
	collection := &backendCollection{}
	marker := &backendMarker{}
	base := &backendEnsurer{}
	endpoint := &backendEnsurer{}
	maps := &backendEnsurer{}
	store := &fakeOwnershipCommitter{events: new([]string)}
	publish := &fakeControlPublisher{events: store.events}
	remover := &backendRemover{}
	publisher, err := NewPublisher(store, publish, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: observer, Control: control, Collection: collection, Marker: marker,
		Base: base, Endpoint: endpoint, Maps: maps, Ownership: store, Remover: remover, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != reconcile.AgentReady || !control.disabled {
		t.Fatalf("first-pass reconcile failed: result=%+v err=%v", result, err)
	}
	if collection.calls != 1 || marker.calls != 1 || base.calls != 1 || endpoint.calls != 1 || maps.calls != 1 {
		t.Fatalf("ensure stages were not called once: collection=%d marker=%d base=%d endpoint=%d maps=%d", collection.calls, marker.calls, base.calls, endpoint.calls, maps.calls)
	}
	if observer.scans < 3 || len(*store.events) != 2 || (*store.events)[0] != "commit" || (*store.events)[1] != "publish" {
		t.Fatalf("unexpected scan or publish sequence: scans=%d events=%v", observer.scans, *store.events)
	}
}

func TestFirstPassBackendLeavesUnsupportedNodeDisabled(t *testing.T) {
	desired := publishTestDesired()
	desired.Enabled = false
	desired.Capability.Supported = false
	observer := &backendObserver{desired: desired, actual: reconcile.ActualState{}}
	control := &backendControl{}
	collection := &backendCollection{}
	marker := &backendMarker{}
	base := &backendEnsurer{}
	endpoint := &backendEnsurer{}
	maps := &backendEnsurer{}
	store := &fakeOwnershipCommitter{events: new([]string)}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: observer, Control: control, Collection: collection, Marker: marker,
		Base: base, Endpoint: endpoint, Maps: maps, Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != reconcile.AgentDisabled || !control.disabled {
		t.Fatalf("unsupported node did not remain disabled: result=%+v err=%v controlDisabled=%v", result, err, control.disabled)
	}
	if observer.scans != 0 || collection.calls != 0 || marker.calls != 0 || base.calls != 0 || endpoint.calls != 0 || maps.calls != 0 || len(*store.events) != 0 {
		t.Fatalf("disabled path performed unsafe work: scans=%d collection=%d marker=%d base=%d endpoint=%d maps=%d events=%v", observer.scans, collection.calls, marker.calls, base.calls, endpoint.calls, maps.calls, *store.events)
	}
}

func TestFirstPassBackendStopsBeforeOwnershipOnEnsureFailure(t *testing.T) {
	desired := publishTestDesired()
	store := &fakeOwnershipCommitter{events: new([]string)}
	publisher, _ := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)},
		Control:  &backendControl{}, Collection: &backendCollection{}, Marker: &backendMarker{},
		Base: &backendEnsurer{err: errors.New("base failed")}, Endpoint: &backendEnsurer{},
		Maps: &backendEnsurer{}, Ownership: store, Remover: &backendRemover{}, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, _ := reconcile.NewCoordinator(backend)
	if _, err := coordinator.FullReconcile(context.Background()); err == nil {
		t.Fatal("ensure failure was not returned")
	}
	if len(*store.events) != 0 {
		t.Fatalf("ownership was changed after ensure failure: %v", *store.events)
	}
}

func TestFirstPassBackendCleansRemovedAndReplacedOwnedEndpoints(t *testing.T) {
	tests := []struct {
		name     string
		previous reconcile.OwnedEndpoint
		wantUID  string
	}{
		{name: "removed", previous: reconcile.OwnedEndpoint{PodUID: "pod-old", PodIPv4: netip.MustParseAddr("10.244.1.11"), NetNSInode: 43, PeerIfIndex: 11, HostIfIndex: 21}, wantUID: "pod-old"},
		{name: "replaced", previous: reconcile.OwnedEndpoint{PodUID: "pod-a", PodIPv4: netip.MustParseAddr("10.244.1.11"), NetNSInode: 43, PeerIfIndex: 11, HostIfIndex: 21}, wantUID: "pod-a"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			desired := publishTestDesired()
			store := &fakeOwnershipCommitter{events: new([]string), state: reconcile.OwnershipState{
				SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "sha256:build", ABI: reconcile.BPFABIVersion,
				Endpoints: map[string]reconcile.OwnedEndpoint{tt.previous.PodUID: tt.previous},
			}}
			publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
			if err != nil {
				t.Fatal(err)
			}
			remover := &backendRemover{}
			backend, err := NewFirstPassBackend(FirstPassBackendConfig{
				Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
				Collection: &backendCollection{}, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
				Ownership: store, Remover: remover, Publisher: publisher,
			})
			if err != nil {
				t.Fatal(err)
			}
			coordinator, err := reconcile.NewCoordinator(backend)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := coordinator.FullReconcile(context.Background()); err != nil {
				t.Fatal(err)
			}
			if remover.calls != 1 || len(remover.uids) != 1 || remover.uids[0] != tt.wantUID {
				t.Fatalf("unexpected cleanup calls: calls=%d uids=%v", remover.calls, remover.uids)
			}
		})
	}
}

func TestFirstPassBackendRefreshesOwnershipAfterBuildMismatch(t *testing.T) {
	desired := publishTestDesired()
	store := &fakeOwnershipCommitter{events: new([]string), state: reconcile.OwnershipState{
		SchemaVersion: 1, InstallationID: "install-a", NodeUID: "node-a", ELFBuildID: "old-build", ABI: reconcile.BPFABIVersion,
		Endpoints: map[string]reconcile.OwnedEndpoint{"pod-old": {PodUID: "pod-old", PodIPv4: netip.MustParseAddr("10.244.1.11"), NetNSInode: 43, PeerIfIndex: 11, HostIfIndex: 21}},
	}}
	publisher, err := NewPublisher(store, &fakeControlPublisher{events: store.events}, publishTestConfig())
	if err != nil {
		t.Fatal(err)
	}
	remover := &backendRemover{}
	backend, err := NewFirstPassBackend(FirstPassBackendConfig{
		Observer: &backendObserver{desired: desired, actual: publishTestActual(desired)}, Control: &backendControl{},
		Collection: &backendCollection{}, Marker: &backendMarker{}, Base: &backendEnsurer{}, Endpoint: &backendEnsurer{}, Maps: &backendEnsurer{},
		Ownership: store, Remover: remover, Publisher: publisher,
	})
	if err != nil {
		t.Fatal(err)
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		t.Fatal(err)
	}
	result, err := coordinator.FullReconcile(context.Background())
	if err != nil || result.State != reconcile.AgentReady {
		t.Fatalf("build mismatch prevented recovery: result=%+v err=%v", result, err)
	}
	if remover.calls != 0 || store.state.ELFBuildID != publishTestConfig().ELFBuildID || store.state.ABI != reconcile.BPFABIVersion {
		t.Fatalf("ownership was not refreshed safely: remover=%d state=%+v", remover.calls, store.state)
	}
}
