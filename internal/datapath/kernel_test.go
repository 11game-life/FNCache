package datapath

import (
	"errors"
	"path/filepath"
	"testing"

	"github.com/cilium/ebpf"
)

type fakeObject struct {
	name       string
	failPin    bool
	pinned     bool
	unpinCount int
}

func (o *fakeObject) Pin(string) error {
	if o.failPin {
		return errors.New("injected pin failure")
	}
	o.pinned = true
	return nil
}
func (o *fakeObject) Unpin() error { o.unpinCount++; return nil }
func (o *fakeObject) Close() error { return nil }

type fakeLoader struct {
	handle   *CollectionHandle
	existing map[string]MapDescriptor
}

func (f *fakeLoader) InspectMap(path string) (MapDescriptor, bool, error) {
	for name, descriptor := range f.existing {
		if filepath.Base(path) == name {
			return descriptor, true, nil
		}
	}
	return MapDescriptor{}, false, nil
}

func (f *fakeLoader) Load(_ *ebpf.CollectionSpec, _ ebpf.CollectionOptions) (*CollectionHandle, error) {
	return f.handle, nil
}

func TestLoadAndPinRollsBackProgramPins(t *testing.T) {
	schema := V1Schema()
	objects := make(map[string]KernelObject)
	programs := make(map[string]KernelObject)
	for _, name := range schema.Maps {
		objects[name.Name] = &fakeObject{name: name.Name}
	}
	for _, name := range schema.Programs {
		programs[name] = &fakeObject{name: name, failPin: name == "tc_restore"}
	}
	loader := &fakeLoader{handle: &CollectionHandle{Maps: objects, Programs: programs}}
	manager, err := NewManagerWithLoader(t.TempDir(), loader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LoadAndPin(collectionFor(schema), schema); err == nil {
		t.Fatal("expected injected pin failure")
	}
	for _, object := range objects {
		if object.(*fakeObject).unpinCount == 0 {
			t.Fatal("new Map was not rolled back")
		}
	}
}

func TestLoadAndPinRejectsExistingMapMismatch(t *testing.T) {
	schema := V1Schema()
	loader := &fakeLoader{handle: &CollectionHandle{}, existing: map[string]MapDescriptor{
		"control_map": {Type: ebpf.Array, KeySize: 4, ValueSize: 1, MaxEntries: 1},
	}}
	manager, err := NewManagerWithLoader(t.TempDir(), loader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := manager.LoadAndPin(collectionFor(schema), schema); err == nil {
		t.Fatal("expected existing Map mismatch")
	}
}
