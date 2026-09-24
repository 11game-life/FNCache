package datapath

import (
	"strings"
	"testing"

	"github.com/cilium/ebpf"
)

func TestValidateV1CollectionSpec(t *testing.T) {
	schema := V1Schema()
	spec := collectionFor(schema)
	if err := ValidateCollectionSpec(spec, schema); err != nil {
		t.Fatal(err)
	}
}

func TestValidateRejectsMapSchemaMismatch(t *testing.T) {
	schema := V1Schema()
	spec := collectionFor(schema)
	spec.Maps["control_map"].ValueSize++
	if err := ValidateCollectionSpec(spec, schema); err == nil || !strings.Contains(err.Error(), "control_map") {
		t.Fatalf("expected control_map schema error: %v", err)
	}
}

func TestValidateRejectsMissingProgramAndMap(t *testing.T) {
	schema := V1Schema()
	spec := collectionFor(schema)
	delete(spec.Programs, "tc_restore")
	if err := ValidateCollectionSpec(spec, schema); err == nil {
		t.Fatal("expected program name error")
	}
	spec = collectionFor(schema)
	delete(spec.Maps, "control_map")
	if err := ValidateCollectionSpec(spec, schema); err == nil {
		t.Fatal("expected Map name error")
	}
}

func TestManagerPinPathsRejectTraversal(t *testing.T) {
	manager, err := NewManager("/sys/fs/bpf/oncache/v1")
	if err != nil {
		t.Fatal(err)
	}
	if path, err := manager.MapPinPath("../control_map"); err == nil || path != "" {
		t.Fatalf("expected traversal rejection: path=%q err=%v", path, err)
	}
	path, err := manager.ProgramPinPath("tc_masq")
	if err != nil || path != "/sys/fs/bpf/oncache/v1/programs/tc_masq" {
		t.Fatalf("unexpected program pin path: %q err=%v", path, err)
	}
}

func collectionFor(schema CollectionSchema) *ebpf.CollectionSpec {
	spec := &ebpf.CollectionSpec{Programs: map[string]*ebpf.ProgramSpec{}, Maps: map[string]*ebpf.MapSpec{}}
	for _, name := range schema.Programs {
		spec.Programs[name] = &ebpf.ProgramSpec{Name: name}
	}
	for _, mapSchema := range schema.Maps {
		spec.Maps[mapSchema.Name] = &ebpf.MapSpec{Name: mapSchema.Name, Type: mapSchema.Type, KeySize: mapSchema.KeySize, ValueSize: mapSchema.ValueSize, MaxEntries: mapSchema.MaxEntries, Flags: mapSchema.Flags}
	}
	return spec
}
