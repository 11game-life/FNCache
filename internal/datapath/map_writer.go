package datapath

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"

	"github.com/cilium/ebpf"
)

type mapHandle interface {
	LookupBytes(any) ([]byte, error)
	Update(any, any, ebpf.MapUpdateFlags) error
	Close() error
}

type mapOpener func(string) (mapHandle, error)

type MapWriter struct {
	pinRoot string
	open    mapOpener
}

func NewMapWriter(pinRoot string) (*MapWriter, error) {
	return newMapWriter(pinRoot, openPinnedMap)
}

func newMapWriter(pinRoot string, open mapOpener) (*MapWriter, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if open == nil {
		return nil, fmt.Errorf("Map opener is required")
	}
	return &MapWriter{pinRoot: filepath.Clean(pinRoot), open: open}, nil
}

func (w *MapWriter) Ensure(ctx context.Context, name string, key, value []byte) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if name == "" || filepath.Base(name) != name || len(key) == 0 || len(value) == 0 {
		return false, fmt.Errorf("invalid Map update input")
	}
	path := filepath.Join(w.pinRoot, "maps", name)
	object, err := w.open(path)
	if err != nil {
		return false, fmt.Errorf("open pinned Map %s: %w", name, err)
	}
	defer func() { _ = object.Close() }()

	existing, err := object.LookupBytes(key)
	if err != nil {
		return false, fmt.Errorf("lookup Map %s: %w", name, err)
	}
	if existing != nil {
		if len(existing) != len(value) {
			return false, fmt.Errorf("Map %s value size mismatch: got %d want %d", name, len(existing), len(value))
		}
		if bytes.Equal(existing, value) {
			return false, nil
		}
	}
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if err := object.Update(key, value, ebpf.UpdateAny); err != nil {
		return false, fmt.Errorf("update Map %s: %w", name, err)
	}
	return true, nil
}

func openPinnedMap(path string) (mapHandle, error) {
	return ebpf.LoadPinnedMap(path, nil)
}
