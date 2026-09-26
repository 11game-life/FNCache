package datapath

import (
	"context"
	"errors"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type fakeTCBackend struct {
	qdisc    TCQdiscState
	filters  []TCFilterState
	ensures  int
	attached int
	removed  int
}

func (b *fakeTCBackend) EnsureClsact(ctx context.Context, link resolver.LinkIdentity) (TCQdiscState, error) {
	if err := ctx.Err(); err != nil {
		return TCQdiscState{}, err
	}
	b.ensures++
	return b.qdisc, nil
}

func (b *fakeTCBackend) ListFilters(ctx context.Context, _ resolver.LinkIdentity) ([]TCFilterState, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return append([]TCFilterState(nil), b.filters...), nil
}

func (b *fakeTCBackend) AttachFilter(ctx context.Context, spec TCFilterSpec) (TCFilterState, error) {
	if err := ctx.Err(); err != nil {
		return TCFilterState{}, err
	}
	state := TCFilterState{Link: spec.Link, Hook: spec.Hook, Program: spec.Program, ProgramID: spec.ProgramID, Priority: spec.Priority, Handle: spec.Handle, DirectAction: spec.DirectAction}
	b.filters = append(b.filters, state)
	b.attached++
	return state, nil
}

func (b *fakeTCBackend) RemoveFilter(ctx context.Context, spec TCFilterSpec) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for i, filter := range b.filters {
		if sameFilter(filter, spec) {
			b.filters = append(b.filters[:i], b.filters[i+1:]...)
			b.removed++
			return nil
		}
	}
	return nil
}

func testLink() resolver.LinkIdentity {
	return resolver.LinkIdentity{NetNSInode: 42, IfIndex: 7}
}

func TestNewFixedFilterUsesFrozenIdentity(t *testing.T) {
	checks := []struct {
		program string
		hook    TCHook
		handle  uint32
	}{
		{program: "tc_init_e", hook: HookEgress, handle: 0x100},
		{program: "tc_restore", hook: HookIngress, handle: 0x101},
		{program: "tc_masq", hook: HookIngress, handle: 0x200},
		{program: "tc_init_in", hook: HookIngress, handle: 0x201},
	}
	for _, check := range checks {
		spec, err := NewFixedFilter(testLink(), check.program, 10, true)
		if err != nil {
			t.Fatal(err)
		}
		if spec.Hook != check.hook || spec.Priority != FixedTCPriority || spec.Handle != check.handle {
			t.Fatalf("unexpected fixed identity: %+v", spec)
		}
	}
}

func TestTCManagerEnsureIsIdempotent(t *testing.T) {
	link := testLink()
	backend := &fakeTCBackend{qdisc: TCQdiscState{Link: link, Exists: true}}
	manager, err := NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewFixedFilter(link, "tc_init_e", 10, true)
	if err != nil {
		t.Fatal(err)
	}
	first, err := manager.EnsureFilter(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	second, err := manager.EnsureFilter(context.Background(), spec)
	if err != nil {
		t.Fatal(err)
	}
	if !sameFilter(first, spec) || !sameFilter(second, spec) || backend.attached != 1 || len(backend.filters) != 1 {
		t.Fatalf("filter was not reused: first=%+v second=%+v backend=%+v", first, second, backend)
	}
}

func TestTCManagerAllowsFixedIngressFiltersToCoexist(t *testing.T) {
	link := testLink()
	backend := &fakeTCBackend{qdisc: TCQdiscState{Link: link, Exists: true}}
	manager, err := NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	programs := []struct {
		name string
		id   uint32
	}{
		{name: "tc_restore", id: 10},
		{name: "tc_masq", id: 11},
		{name: "tc_init_in", id: 12},
	}
	for _, program := range programs {
		spec, err := NewFixedFilter(link, program.name, program.id, true)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := manager.EnsureFilter(context.Background(), spec); err != nil {
			t.Fatalf("failed to attach %s: %v", program.name, err)
		}
	}
	if backend.attached != len(programs) || len(backend.filters) != len(programs) {
		t.Fatalf("fixed ingress filters did not coexist: attached=%d filters=%d", backend.attached, len(backend.filters))
	}
}

func TestTCManagerRejectsFixedPriorityConflict(t *testing.T) {
	link := testLink()
	backend := &fakeTCBackend{
		qdisc:   TCQdiscState{Link: link, Exists: true},
		filters: []TCFilterState{{Link: link, Hook: HookEgress, ProgramID: 99, Priority: FixedTCPriority, Handle: 0x999, DirectAction: true}},
	}
	manager, _ := NewTCManager(backend)
	spec, _ := NewFixedFilter(link, "tc_init_e", 10, true)
	_, err := manager.EnsureFilter(context.Background(), spec)
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.ReasonCode() != reconcile.ReasonTCForeignConflict || backend.attached != 0 {
		t.Fatalf("expected foreign conflict, err=%v backend=%+v", err, backend)
	}
}

func TestTCManagerRemoveRechecksProgramID(t *testing.T) {
	link := testLink()
	backend := &fakeTCBackend{
		filters: []TCFilterState{{Link: link, Hook: HookIngress, ProgramID: 99, Priority: FixedTCPriority, Handle: 0x200, DirectAction: true}},
	}
	manager, _ := NewTCManager(backend)
	spec, _ := NewFixedFilter(link, "tc_masq", 10, true)
	err := manager.RemoveFilter(context.Background(), spec)
	if err == nil || backend.removed != 0 || len(backend.filters) != 1 {
		t.Fatalf("foreign filter was removed: err=%v backend=%+v", err, backend)
	}
}

func TestTCManagerStopsBeforeBackendOnCancellation(t *testing.T) {
	backend := &fakeTCBackend{qdisc: TCQdiscState{Link: testLink(), Exists: true}}
	manager, _ := NewTCManager(backend)
	spec, _ := NewFixedFilter(testLink(), "tc_init_e", 10, true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := manager.EnsureFilter(ctx, spec); !errors.Is(err, context.Canceled) || backend.ensures != 0 {
		t.Fatalf("expected cancellation before backend call: err=%v ensures=%d", err, backend.ensures)
	}
}
