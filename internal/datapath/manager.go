package datapath

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"

	"github.com/cilium/ebpf"
)

type MapSchema struct {
	Name       string
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type CollectionSchema struct {
	Programs []string
	Maps     []MapSchema
}

type MapDescriptor struct {
	Type       ebpf.MapType
	KeySize    uint32
	ValueSize  uint32
	MaxEntries uint32
	Flags      uint32
}

type Manager struct{ pinRoot string }

func NewManager(pinRoot string) (*Manager, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	return &Manager{pinRoot: filepath.Clean(pinRoot)}, nil
}

func (m *Manager) LoadCollection(r io.ReaderAt, schema CollectionSchema) (*ebpf.CollectionSpec, error) {
	spec, err := ebpf.LoadCollectionSpecFromReader(r)
	if err != nil {
		return nil, fmt.Errorf("load BPF collection spec: %w", err)
	}
	if err := ValidateCollectionSpec(spec, schema); err != nil {
		return nil, err
	}
	return spec, nil
}

func (m *Manager) MapPinPath(name string) (string, error) {
	return m.pinPath("maps", name)
}

func (m *Manager) ProgramPinPath(name string) (string, error) {
	return m.pinPath("programs", name)
}

func (m *Manager) pinPath(kind, name string) (string, error) {
	if name == "" || filepath.Base(name) != name {
		return "", fmt.Errorf("invalid BPF %s name: %q", kind, name)
	}
	return filepath.Join(m.pinRoot, kind, name), nil
}

func ValidateCollectionSpec(spec *ebpf.CollectionSpec, schema CollectionSchema) error {
	if spec == nil {
		return fmt.Errorf("BPF collection spec is nil")
	}
	expectedPrograms := append([]string(nil), schema.Programs...)
	actualPrograms := make([]string, 0, len(spec.Programs))
	for name := range spec.Programs {
		actualPrograms = append(actualPrograms, name)
	}
	if err := compareNames("program", expectedPrograms, actualPrograms); err != nil {
		return err
	}
	expectedMaps := make(map[string]MapSchema, len(schema.Maps))
	for _, expected := range schema.Maps {
		if _, exists := expectedMaps[expected.Name]; exists || expected.Name == "" {
			return fmt.Errorf("invalid or duplicate Map schema name: %q", expected.Name)
		}
		expectedMaps[expected.Name] = expected
	}
	if len(spec.Maps) != len(expectedMaps) {
		return fmt.Errorf("BPF Map count mismatch: got %d want %d", len(spec.Maps), len(expectedMaps))
	}
	for name, expected := range expectedMaps {
		actual, ok := spec.Maps[name]
		if !ok {
			return fmt.Errorf("missing BPF Map: %s", name)
		}
		if err := validateMap(actual, expected); err != nil {
			return err
		}
	}
	return nil
}

func validateMap(actual *ebpf.MapSpec, expected MapSchema) error {
	got := MapDescriptor{Type: actual.Type, KeySize: actual.KeySize, ValueSize: actual.ValueSize, MaxEntries: actual.MaxEntries, Flags: actual.Flags}
	if got != (MapDescriptor{Type: expected.Type, KeySize: expected.KeySize, ValueSize: expected.ValueSize, MaxEntries: expected.MaxEntries, Flags: expected.Flags}) {
		return fmt.Errorf("BPF Map schema mismatch for %s: got=%+v want=%+v", expected.Name, got, expected)
	}
	return nil
}

func compareNames(kind string, expected, actual []string) error {
	sort.Strings(expected)
	sort.Strings(actual)
	if len(expected) != len(actual) {
		return fmt.Errorf("BPF %s count mismatch: got %v want %v", kind, actual, expected)
	}
	for i := range expected {
		if expected[i] != actual[i] {
			return fmt.Errorf("BPF %s names mismatch: got %v want %v", kind, actual, expected)
		}
	}
	return nil
}

func V1Schema() CollectionSchema {
	return CollectionSchema{
		Programs: []string{"tc_init_e", "tc_init_in", "tc_masq", "tc_restore"},
		Maps: []MapSchema{
			{Name: "egressip_cache", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 4, MaxEntries: 4096},
			{Name: "egress_cache", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 68, MaxEntries: 1024},
			{Name: "ingress_cache", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 16, MaxEntries: 1024},
			{Name: "policy_cache", Type: ebpf.LRUHash, KeySize: 16, ValueSize: 4, MaxEntries: 4096},
			{Name: "devmap", Type: ebpf.LRUHash, KeySize: 4, ValueSize: 12, MaxEntries: 8},
			{Name: "control_map", Type: ebpf.Array, KeySize: 4, ValueSize: 40, MaxEntries: 1},
			{Name: "policy_lock_map", Type: ebpf.Array, KeySize: 4, ValueSize: 4, MaxEntries: 1},
			{Name: "stats_map", Type: ebpf.PerCPUArray, KeySize: 4, ValueSize: 8, MaxEntries: 14},
		},
	}
}
