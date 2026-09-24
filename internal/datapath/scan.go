package datapath

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
)

type pinBackend interface {
	List(string) ([]string, error)
	InspectMap(string, MapSchema) (reconcile.MapState, error)
	InspectProgram(string, string) (reconcile.ProgramState, error)
}

type PinScanner struct {
	pinRoot string
	backend pinBackend
	now     func() time.Time
}

func NewPinScanner(pinRoot string) (*PinScanner, error) {
	return newPinScanner(pinRoot, ciliumPinBackend{})
}

func newPinScanner(pinRoot string, backend pinBackend) (*PinScanner, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if backend == nil {
		return nil, fmt.Errorf("BPF pin scan backend is required")
	}
	return &PinScanner{pinRoot: filepath.Clean(pinRoot), backend: backend, now: time.Now}, nil
}

func (s *PinScanner) Scan(ctx context.Context) (reconcile.ActualState, error) {
	actual := reconcile.ActualState{ScannedAt: s.now(), Maps: make(map[string]reconcile.MapState), Programs: make(map[string]reconcile.ProgramState)}
	schema := V1Schema()
	expectedMaps := make(map[string]MapSchema, len(schema.Maps))
	for _, item := range schema.Maps {
		expectedMaps[item.Name] = item
	}
	if err := s.scanMaps(ctx, expectedMaps, &actual); err != nil {
		return reconcile.ActualState{}, err
	}
	expectedPrograms := make(map[string]struct{}, len(schema.Programs))
	for _, name := range schema.Programs {
		expectedPrograms[name] = struct{}{}
	}
	if err := s.scanPrograms(ctx, expectedPrograms, &actual); err != nil {
		return reconcile.ActualState{}, err
	}
	return actual, nil
}

func (s *PinScanner) scanMaps(ctx context.Context, expected map[string]MapSchema, actual *reconcile.ActualState) error {
	names, err := s.backend.List(filepath.Join(s.pinRoot, "maps"))
	if err != nil {
		return fmt.Errorf("list pinned Maps: %w", err)
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		schema, ok := expected[name]
		path := filepath.Join(s.pinRoot, "maps", name)
		if !ok {
			actual.Orphans = append(actual.Orphans, reconcile.OwnedObject{Kind: "map-pin", Identity: path})
			continue
		}
		state, err := s.backend.InspectMap(path, schema)
		if err != nil {
			return fmt.Errorf("inspect pinned Map %s: %w", name, err)
		}
		actual.Maps[name] = state
	}
	return nil
}

func (s *PinScanner) scanPrograms(ctx context.Context, expected map[string]struct{}, actual *reconcile.ActualState) error {
	names, err := s.backend.List(filepath.Join(s.pinRoot, "programs"))
	if err != nil {
		return fmt.Errorf("list pinned programs: %w", err)
	}
	for _, name := range names {
		if err := ctx.Err(); err != nil {
			return err
		}
		path := filepath.Join(s.pinRoot, "programs", name)
		if _, ok := expected[name]; !ok {
			actual.Orphans = append(actual.Orphans, reconcile.OwnedObject{Kind: "program-pin", Identity: path})
			continue
		}
		state, err := s.backend.InspectProgram(path, name)
		if err != nil {
			return fmt.Errorf("inspect pinned program %s: %w", name, err)
		}
		actual.Programs[name] = state
	}
	return nil
}

type ciliumPinBackend struct{}

func (ciliumPinBackend) List(path string) ([]string, error) {
	entries, err := os.ReadDir(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names, nil
}

func (ciliumPinBackend) InspectMap(path string, expected MapSchema) (reconcile.MapState, error) {
	object, err := ebpf.LoadPinnedMap(path, nil)
	if err != nil {
		return reconcile.MapState{}, err
	}
	defer object.Close()
	info, err := object.Info()
	if err != nil {
		return reconcile.MapState{}, err
	}
	got := MapDescriptor{Type: info.Type, KeySize: info.KeySize, ValueSize: info.ValueSize, MaxEntries: info.MaxEntries, Flags: info.Flags}
	if err := validateDescriptor(got, expected); err != nil {
		return reconcile.MapState{}, err
	}
	id, ok := info.ID()
	if !ok {
		return reconcile.MapState{}, fmt.Errorf("kernel did not provide a Map ID")
	}
	return reconcile.MapState{ID: uint32(id), Name: expected.Name, KeySize: info.KeySize, ValueSize: info.ValueSize, MaxEntries: info.MaxEntries}, nil
}

func (ciliumPinBackend) InspectProgram(path, name string) (reconcile.ProgramState, error) {
	object, err := ebpf.LoadPinnedProgram(path, nil)
	if err != nil {
		return reconcile.ProgramState{}, err
	}
	defer object.Close()
	info, err := object.Info()
	if err != nil {
		return reconcile.ProgramState{}, err
	}
	id, ok := info.ID()
	if !ok {
		return reconcile.ProgramState{}, fmt.Errorf("kernel did not provide a program ID")
	}
	programName := info.Name
	if programName == "" {
		programName = name
	}
	return reconcile.ProgramState{ID: uint32(id), Name: programName, Tag: info.Tag}, nil
}
