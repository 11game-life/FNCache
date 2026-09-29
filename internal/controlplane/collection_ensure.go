package controlplane

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cilium/ebpf"
)

type collectionHandle interface {
	Unpin() error
	Close() error
}

type collectionOps struct {
	loadCollection func(io.ReaderAt, datapath.CollectionSchema) (*ebpf.CollectionSpec, error)
	loadAndPin     func(*ebpf.CollectionSpec, datapath.CollectionSchema) (collectionHandle, error)
}

type collectionOpsFactory func(string) (collectionOps, error)
type controlInitializer func(context.Context, string) error
type legacyPinCleanup func(context.Context, string, map[uint32]struct{}) error

type CollectionEnsurer struct {
	elfPath       string
	pinRoot       string
	newOps        collectionOpsFactory
	initializeCtl controlInitializer
	cleanupLegacy legacyPinCleanup
}

func NewCollectionEnsurer(elfPath, pinRoot string) (*CollectionEnsurer, error) {
	return newCollectionEnsurer(elfPath, pinRoot, func(root string) (collectionOps, error) {
		manager, err := datapath.NewManager(root)
		if err != nil {
			return collectionOps{}, err
		}
		return collectionOps{
			loadCollection: manager.LoadCollection,
			loadAndPin: func(spec *ebpf.CollectionSpec, schema datapath.CollectionSchema) (collectionHandle, error) {
				return manager.LoadAndPin(spec, schema)
			},
		}, nil
	}, initializeControlMap, func(ctx context.Context, root string, activeProgramIDs map[uint32]struct{}) error {
		manager, err := datapath.NewManager(root)
		if err != nil {
			return err
		}
		return manager.CleanupLegacyProgramPins(ctx, activeProgramIDs)
	})
}

func newCollectionEnsurer(elfPath, pinRoot string, factory collectionOpsFactory, initialize controlInitializer, cleanup ...legacyPinCleanup) (*CollectionEnsurer, error) {
	if elfPath == "" || !filepath.IsAbs(elfPath) {
		return nil, fmt.Errorf("BPF ELF path must be an absolute file path")
	}
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("BPF pin root must be a dedicated absolute directory")
	}
	if factory == nil || initialize == nil {
		return nil, fmt.Errorf("collection dependencies are required")
	}
	if len(cleanup) > 1 {
		return nil, fmt.Errorf("at most one legacy pin cleanup function is allowed")
	}
	var cleanupLegacy legacyPinCleanup
	if len(cleanup) == 1 {
		cleanupLegacy = cleanup[0]
	}
	return &CollectionEnsurer{elfPath: filepath.Clean(elfPath), pinRoot: filepath.Clean(pinRoot), newOps: factory, initializeCtl: initialize, cleanupLegacy: cleanupLegacy}, nil
}

func (e *CollectionEnsurer) EnsureCollection(ctx context.Context, desired reconcile.DesiredState, actual reconcile.ActualState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	if e.cleanupLegacy != nil {
		if err := e.cleanupLegacy(ctx, e.pinRoot, activeLegacyProgramIDs(actual)); err != nil {
			return false, fmt.Errorf("cleanup legacy BPF program pins: %w", err)
		}
	}
	if collectionReady(actual) {
		return false, nil
	}
	file, err := os.Open(e.elfPath)
	if err != nil {
		return false, fmt.Errorf("open BPF ELF: %w", err)
	}
	defer file.Close()
	ops, err := e.newOps(e.pinRoot)
	if err != nil {
		return false, fmt.Errorf("create BPF collection manager: %w", err)
	}
	schema := datapath.V1Schema()
	spec, err := ops.loadCollection(file, schema)
	if err != nil {
		return false, fmt.Errorf("load BPF collection: %w", err)
	}
	loaded, err := ops.loadAndPin(spec, schema)
	if err != nil {
		return false, fmt.Errorf("pin BPF collection: %w", err)
	}
	if err := e.initializeCtl(ctx, e.pinRoot); err != nil {
		_ = loaded.Unpin()
		_ = loaded.Close()
		return false, fmt.Errorf("initialize control Map: %w", err)
	}
	if err := loaded.Close(); err != nil {
		return false, fmt.Errorf("close BPF collection: %w", err)
	}
	return true, nil
}

func activeLegacyProgramIDs(actual reconcile.ActualState) map[uint32]struct{} {
	canonicalIDs := make(map[uint32]struct{}, len(actual.Programs))
	for _, program := range actual.Programs {
		if program.ID != 0 {
			canonicalIDs[program.ID] = struct{}{}
		}
	}
	active := make(map[uint32]struct{})
	for _, attachment := range actual.Attachments {
		_, canonical := canonicalIDs[attachment.ProgramID]
		if attachment.ProgramID != 0 && (datapath.IsLegacyProgramName(attachment.Program) || !canonical) {
			active[attachment.ProgramID] = struct{}{}
		}
	}
	return active
}

func collectionReady(actual reconcile.ActualState) bool {
	schema := datapath.V1Schema()
	if len(actual.Programs) != len(schema.Programs) || len(actual.Maps) != len(schema.Maps) {
		return false
	}
	for _, name := range schema.Programs {
		program, ok := actual.Programs[name]
		if !ok || program.ID == 0 {
			return false
		}
	}
	for _, expected := range schema.Maps {
		state, ok := actual.Maps[expected.Name]
		if !ok || state.ID == 0 || state.KeySize != expected.KeySize || state.ValueSize != expected.ValueSize || state.MaxEntries != expected.MaxEntries {
			return false
		}
	}
	return true
}

func initializeControlMap(ctx context.Context, pinRoot string) error {
	writer, err := datapath.NewControlWriter(pinRoot)
	if err != nil {
		return err
	}
	return writer.Initialize(ctx)
}
