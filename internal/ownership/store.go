package ownership

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

const schemaVersion uint32 = 1

type OwnershipStore interface {
	Load(context.Context) (reconcile.OwnershipState, error)
	Commit(context.Context, reconcile.OwnershipState) error
	Remove(context.Context) error
}

type Store struct{ path string }

func NewStore(path string) (*Store, error) {
	if path == "" || !filepath.IsAbs(path) || filepath.Clean(path) == string(filepath.Separator) {
		return nil, fmt.Errorf("ownership state path must be a dedicated absolute file")
	}
	return &Store{path: filepath.Clean(path)}, nil
}

func (s *Store) Load(ctx context.Context) (reconcile.OwnershipState, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.OwnershipState{}, err
	}
	data, err := os.ReadFile(s.path)
	if err != nil {
		return reconcile.OwnershipState{}, err
	}
	var state reconcile.OwnershipState
	if err := json.Unmarshal(data, &state); err != nil {
		return reconcile.OwnershipState{}, fmt.Errorf("decode ownership state: %w", err)
	}
	if err := validateState(state); err != nil {
		return reconcile.OwnershipState{}, err
	}
	return state, nil
}

func (s *Store) Commit(ctx context.Context, state reconcile.OwnershipState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := validateState(state); err != nil {
		return err
	}
	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create ownership state directory: %w", err)
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return fmt.Errorf("encode ownership state: %w", err)
	}
	data = append(data, '\n')
	tmp, err := os.CreateTemp(dir, ".state-*.tmp")
	if err != nil {
		return fmt.Errorf("create ownership state temporary file: %w", err)
	}
	tmpName := tmp.Name()
	defer os.Remove(tmpName)
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("set ownership state permissions: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write ownership state: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("sync ownership state: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close ownership state: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, s.path); err != nil {
		return fmt.Errorf("replace ownership state: %w", err)
	}
	return syncDirectory(dir)
}

func (s *Store) Remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	err := os.Remove(s.path)
	if os.IsNotExist(err) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("remove ownership state: %w", err)
	}
	return syncDirectory(filepath.Dir(s.path))
}

func validateState(state reconcile.OwnershipState) error {
	if state.SchemaVersion != schemaVersion {
		return fmt.Errorf("unsupported ownership schema version: %d", state.SchemaVersion)
	}
	if state.InstallationID == "" || state.NodeUID == "" {
		return fmt.Errorf("ownership state installationID and nodeUID are required")
	}
	return nil
}

func syncDirectory(path string) error {
	dir, err := os.Open(path)
	if err != nil {
		return fmt.Errorf("open ownership state directory: %w", err)
	}
	defer dir.Close()
	if err := dir.Sync(); err != nil {
		return fmt.Errorf("sync ownership state directory: %w", err)
	}
	return nil
}
