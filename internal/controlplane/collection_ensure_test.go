package controlplane

import (
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
)

type fakeCollectionHandle struct {
	unpinCalls int
	closeCalls int
}

func (h *fakeCollectionHandle) Unpin() error { h.unpinCalls++; return nil }
func (h *fakeCollectionHandle) Close() error { h.closeCalls++; return nil }

func TestCollectionEnsurerSkipsReadyCollection(t *testing.T) {
	called := false
	ensurer, err := newCollectionEnsurer("/tmp/oncache-test.o", "/sys/fs/bpf/oncache/v1", func(string) (collectionOps, error) {
		called = true
		return collectionOps{}, nil
	}, func(context.Context, string) error { return nil })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, readyCollectionState()); err != nil || changed || called {
		t.Fatalf("ready collection was not a no-op: changed=%v err=%v called=%v", changed, err, called)
	}
}

func TestCollectionEnsurerLoadsPinsAndInitializesControl(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	handle := &fakeCollectionHandle{}
	loaded := false
	initialized := false
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return &ebpf.CollectionSpec{}, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) {
				loaded = true
				return handle, nil
			},
		}, nil
	}, func(context.Context, string) error {
		initialized = true
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, reconcile.ActualState{})
	if err != nil || !changed || !loaded || !initialized || handle.closeCalls != 1 || handle.unpinCalls != 0 {
		t.Fatalf("collection was not ensured: changed=%v err=%v loaded=%v initialized=%v handle=%+v", changed, err, loaded, initialized, handle)
	}
}

func TestCollectionEnsurerRollsBackWhenControlInitializationFails(t *testing.T) {
	elf := filepath.Join(t.TempDir(), "datapath.o")
	if err := os.WriteFile(elf, []byte("elf"), 0600); err != nil {
		t.Fatal(err)
	}
	handle := &fakeCollectionHandle{}
	want := errors.New("control init failed")
	ensurer, err := newCollectionEnsurer(elf, filepath.Join(t.TempDir(), "bpf"), func(string) (collectionOps, error) {
		return collectionOps{
			loadCollection: func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error) {
				return &ebpf.CollectionSpec{}, nil
			},
			loadAndPin: func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error) { return handle, nil },
		}, nil
	}, func(context.Context, string) error { return want })
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := ensurer.EnsureCollection(context.Background(), reconcile.DesiredState{Enabled: true}, reconcile.ActualState{}); err == nil || !errors.Is(err, want) || changed || handle.unpinCalls != 1 || handle.closeCalls != 1 {
		t.Fatalf("control failure was not rolled back: changed=%v err=%v handle=%+v", changed, err, handle)
	}
}

func readyCollectionState() reconcile.ActualState {
	schema := datapath.V1Schema()
	actual := reconcile.ActualState{Programs: make(map[string]reconcile.ProgramState), Maps: make(map[string]reconcile.MapState)}
	for _, name := range schema.Programs {
		actual.Programs[name] = reconcile.ProgramState{ID: 1, Name: name}
	}
	for _, expected := range schema.Maps {
		actual.Maps[expected.Name] = reconcile.MapState{ID: 1, Name: expected.Name, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries}
	}
	return actual
}
