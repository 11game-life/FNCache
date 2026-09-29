package datapath

import (
	"context"
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeMapHandle struct {
	value       []byte
	lookupErr   error
	updateErr   error
	deleteErr   error
	updated     []byte
	lookupCalls int
	updateCalls int
	deleted     [][]byte
	closeCalls  int
}

func (m *fakeMapHandle) LookupBytes(any) ([]byte, error) {
	m.lookupCalls++
	if m.lookupErr != nil {
		return nil, m.lookupErr
	}
	return append([]byte(nil), m.value...), nil
}

func (m *fakeMapHandle) Update(_, value any, _ ebpf.MapUpdateFlags) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	data, ok := value.([]byte)
	if !ok {
		return errors.New("unexpected Map value")
	}
	m.updated = append([]byte(nil), data...)
	m.value = append([]byte(nil), data...)
	return nil
}

func (m *fakeMapHandle) Delete(key any) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	data, ok := key.([]byte)
	if !ok {
		return errors.New("unexpected Map key")
	}
	m.deleted = append(m.deleted, append([]byte(nil), data...))
	return nil
}

func (m *fakeMapHandle) ListKeys() ([][]byte, error) {
	if m.value == nil {
		return nil, nil
	}
	return [][]byte{append([]byte(nil), m.value...)}, nil
}

func (m *fakeMapHandle) Close() error {
	m.closeCalls++
	return nil
}

func TestMapWriterEnsureUpdatesOnlyWhenValueChanges(t *testing.T) {
	root := t.TempDir()
	handle := &fakeMapHandle{value: []byte{1, 2}}
	writer, err := newMapWriter(root, func(path string) (mapHandle, error) {
		if path != filepath.Join(root, "maps", "ingress_cache") {
			t.Fatalf("unexpected Map path: %q", path)
		}
		return handle, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	changed, err := writer.Ensure(context.Background(), "ingress_cache", []byte{9}, []byte{1, 2})
	if err != nil || changed || handle.updateCalls != 0 {
		t.Fatalf("unchanged value was updated: changed=%v updates=%d err=%v", changed, handle.updateCalls, err)
	}
	changed, err = writer.Ensure(context.Background(), "ingress_cache", []byte{9}, []byte{3, 4})
	if err != nil || !changed || handle.updateCalls != 1 || string(handle.updated) != string([]byte{3, 4}) {
		t.Fatalf("changed value was not updated: changed=%v updates=%d value=%v err=%v", changed, handle.updateCalls, handle.updated, err)
	}
	if handle.lookupCalls != 2 || handle.closeCalls != 2 {
		t.Fatalf("unexpected Map calls: lookups=%d closes=%d", handle.lookupCalls, handle.closeCalls)
	}
}

func TestMapWriterEnsureHandlesMissingKeyAndRejectsTraversal(t *testing.T) {
	handle := &fakeMapHandle{}
	writer, _ := newMapWriter(t.TempDir(), func(string) (mapHandle, error) { return handle, nil })
	changed, err := writer.Ensure(context.Background(), "devmap", []byte{1}, []byte{2})
	if err != nil || !changed || handle.updateCalls != 1 {
		t.Fatalf("missing key was not created: changed=%v updates=%d err=%v", changed, handle.updateCalls, err)
	}
	if _, err := writer.Ensure(context.Background(), "../devmap", []byte{1}, []byte{2}); err == nil {
		t.Fatal("Map path traversal was accepted")
	}
}

func TestMapWriterEnsurePropagatesFailuresAndCancellation(t *testing.T) {
	lookupErr := errors.New("lookup failed")
	writer, _ := newMapWriter(t.TempDir(), func(string) (mapHandle, error) {
		return &fakeMapHandle{lookupErr: lookupErr}, nil
	})
	if _, err := writer.Ensure(context.Background(), "devmap", []byte{1}, []byte{2}); !errors.Is(err, lookupErr) {
		t.Fatalf("lookup error was not propagated: %v", err)
	}
	called := false
	writer, _ = newMapWriter(t.TempDir(), func(string) (mapHandle, error) {
		called = true
		return &fakeMapHandle{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := writer.Ensure(ctx, "devmap", []byte{1}, []byte{2}); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("cancellation was not honored: err=%v called=%v", err, called)
	}
}

func TestMapWriterDeleteAndClearAreIdempotent(t *testing.T) {
	handle := &fakeMapHandle{value: []byte{1, 2}}
	writer, _ := newMapWriter(t.TempDir(), func(string) (mapHandle, error) { return handle, nil })
	deleted, err := writer.Delete(context.Background(), "ingress_cache", []byte{1, 2})
	if err != nil || !deleted || len(handle.deleted) != 1 {
		t.Fatalf("Map key was not deleted: deleted=%v calls=%d err=%v", deleted, len(handle.deleted), err)
	}
	count, err := writer.Clear(context.Background(), "policy_cache")
	if err != nil || count != 1 || len(handle.deleted) != 2 {
		t.Fatalf("Map was not cleared: count=%d calls=%d err=%v", count, len(handle.deleted), err)
	}
	missing := &fakeMapHandle{deleteErr: ebpf.ErrKeyNotExist}
	writer, _ = newMapWriter(t.TempDir(), func(string) (mapHandle, error) { return missing, nil })
	deleted, err = writer.Delete(context.Background(), "ingress_cache", []byte{1})
	if err != nil || deleted {
		t.Fatalf("missing Map key was not idempotent: deleted=%v err=%v", deleted, err)
	}
}
