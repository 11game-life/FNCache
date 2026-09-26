package datapath

import (
	"context"
	"errors"
	"path/filepath"
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeControlMap struct {
	value       ControlV1
	lookupErr   error
	updateErr   error
	closeErr    error
	updated     ControlV1
	lookupCalls int
	updateCalls int
	closeCalls  int
}

func (m *fakeControlMap) Lookup(_ interface{}, value interface{}) error {
	m.lookupCalls++
	if m.lookupErr != nil {
		return m.lookupErr
	}
	control, ok := value.(*ControlV1)
	if !ok {
		return errors.New("unexpected lookup value")
	}
	*control = m.value
	return nil
}

func (m *fakeControlMap) Update(_ interface{}, value interface{}, _ ebpf.MapUpdateFlags) error {
	m.updateCalls++
	if m.updateErr != nil {
		return m.updateErr
	}
	control, ok := value.(*ControlV1)
	if !ok {
		return errors.New("unexpected update value")
	}
	m.updated = *control
	return nil
}

func (m *fakeControlMap) Close() error {
	m.closeCalls++
	return m.closeErr
}

func TestControlWriterDisablePreservesControlState(t *testing.T) {
	mapValue := ControlV1{ABIVersion: 1, Enabled: 1, Generation: 42, HeartbeatNS: 100, HeartbeatTimeoutNS: 500, Flags: 3, Reserved: 7}
	fake := &fakeControlMap{value: mapValue}
	root := t.TempDir()
	writer, err := newControlWriter(root, func(path string) (controlMap, error) {
		want := filepath.Join(root, "maps", "control_map")
		if path != want {
			t.Fatalf("unexpected control Map path: got=%q want=%q", path, want)
		}
		return fake, nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Disable(context.Background()); err != nil {
		t.Fatal(err)
	}
	if fake.updated.Enabled != 0 || fake.updated.ABIVersion != mapValue.ABIVersion ||
		fake.updated.Generation != mapValue.Generation || fake.updated.HeartbeatNS != mapValue.HeartbeatNS ||
		fake.updated.HeartbeatTimeoutNS != mapValue.HeartbeatTimeoutNS || fake.updated.Flags != mapValue.Flags ||
		fake.updated.Reserved != mapValue.Reserved {
		t.Fatalf("disable did not preserve control state: got=%+v want=%+v", fake.updated, mapValue)
	}
	if fake.lookupCalls != 1 || fake.updateCalls != 1 || fake.closeCalls != 1 {
		t.Fatalf("unexpected Map calls: lookup=%d update=%d close=%d", fake.lookupCalls, fake.updateCalls, fake.closeCalls)
	}
}

func TestControlWriterDisableRejectsInvalidOrUnavailableMap(t *testing.T) {
	tests := []struct {
		name      string
		value     ControlV1
		lookupErr error
		updateErr error
		want      string
	}{
		{name: "ABI mismatch", value: ControlV1{ABIVersion: 2}, want: "ABI mismatch"},
		{name: "lookup failure", lookupErr: errors.New("lookup failed"), want: "read control Map"},
		{name: "update failure", value: ControlV1{ABIVersion: 1}, updateErr: errors.New("update failed"), want: "disable fast path"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			fake := &fakeControlMap{value: test.value, lookupErr: test.lookupErr, updateErr: test.updateErr}
			writer, err := newControlWriter(t.TempDir(), func(string) (controlMap, error) { return fake, nil })
			if err != nil {
				t.Fatal(err)
			}
			if err := writer.Disable(context.Background()); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("unexpected disable error: %v", err)
			}
		})
	}
}

func TestControlWriterDisableHonorsCancellation(t *testing.T) {
	called := false
	writer, _ := newControlWriter(t.TempDir(), func(string) (controlMap, error) {
		called = true
		return &fakeControlMap{}, nil
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := writer.Disable(ctx); !errors.Is(err, context.Canceled) || called {
		t.Fatalf("unexpected cancellation result: err=%v called=%v", err, called)
	}
}
