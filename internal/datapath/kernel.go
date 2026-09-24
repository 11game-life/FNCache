package datapath

import (
	"os"

	"github.com/cilium/ebpf"
)

type KernelObject interface {
	Pin(string) error
	Unpin() error
	Close() error
}

type CollectionHandle struct {
	Maps     map[string]KernelObject
	Programs map[string]KernelObject
	close    func() error
}

func (c *CollectionHandle) Close() error {
	if c.close == nil {
		return nil
	}
	return c.close()
}

type KernelLoader interface {
	InspectMap(string) (MapDescriptor, bool, error)
	Load(*ebpf.CollectionSpec, ebpf.CollectionOptions) (*CollectionHandle, error)
}

type ciliumLoader struct{}

func (ciliumLoader) InspectMap(path string) (MapDescriptor, bool, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return MapDescriptor{}, false, nil
	} else if err != nil {
		return MapDescriptor{}, false, err
	}
	m, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return MapDescriptor{}, true, err
	}
	defer m.Close()
	info, err := m.Info()
	if err != nil {
		return MapDescriptor{}, true, err
	}
	return MapDescriptor{Type: info.Type, KeySize: info.KeySize, ValueSize: info.ValueSize, MaxEntries: info.MaxEntries, Flags: info.Flags}, true, nil
}

func (ciliumLoader) Load(spec *ebpf.CollectionSpec, options ebpf.CollectionOptions) (*CollectionHandle, error) {
	collection, err := ebpf.NewCollectionWithOptions(spec, options)
	if err != nil {
		return nil, err
	}
	handle := &CollectionHandle{Maps: make(map[string]KernelObject), Programs: make(map[string]KernelObject), close: func() error {
		collection.Close()
		return nil
	}}
	for name, object := range collection.Maps {
		handle.Maps[name] = object
	}
	for name, object := range collection.Programs {
		handle.Programs[name] = object
	}
	return handle, nil
}
