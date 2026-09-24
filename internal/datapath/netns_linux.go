//go:build linux

package datapath

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"golang.org/x/sys/unix"
)

type NetNSRef struct {
	Path  string
	Inode uint64
}

type netnsOps interface {
	Open(string, int, uint32) (int, error)
	Close(int) error
	Fstat(int, *unix.Stat_t) error
	Setns(int, int) error
}

type linuxNetnsOps struct{}

func (linuxNetnsOps) Open(path string, flags int, mode uint32) (int, error) {
	return unix.Open(path, flags, mode)
}
func (linuxNetnsOps) Close(fd int) error                    { return unix.Close(fd) }
func (linuxNetnsOps) Fstat(fd int, stat *unix.Stat_t) error { return unix.Fstat(fd, stat) }
func (linuxNetnsOps) Setns(fd, nstype int) error            { return unix.Setns(fd, nstype) }

type NetNSManager struct {
	ops netnsOps
}

func NewNetNSManager() *NetNSManager { return &NetNSManager{ops: linuxNetnsOps{}} }

func newNetNSManager(ops netnsOps) *NetNSManager { return &NetNSManager{ops: ops} }

func (m *NetNSManager) WithNetNS(ctx context.Context, ref NetNSRef, fn func(context.Context) error) error {
	if err := validateNetNSRef(ref); err != nil {
		return err
	}
	if fn == nil {
		return fmt.Errorf("netns callback is required")
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		err := m.withLocked(ctx, ref, fn)
		if isNetNSSafetyError(err) {
			result <- err
			runtime.Goexit()
		}
		runtime.UnlockOSThread()
		result <- err
	}()
	return <-result
}

func (m *NetNSManager) withLocked(ctx context.Context, ref NetNSRef, fn func(context.Context) error) (err error) {
	const flags = unix.O_RDONLY | unix.O_CLOEXEC
	originalFD, err := m.ops.Open("/proc/self/ns/net", flags, 0)
	if err != nil {
		return fmt.Errorf("open current netns: %w", err)
	}
	defer func() { _ = m.ops.Close(originalFD) }()
	targetFD, err := m.ops.Open(ref.Path, flags, 0)
	if err != nil {
		return fmt.Errorf("open target netns: %w", err)
	}
	defer func() { _ = m.ops.Close(targetFD) }()
	var stat unix.Stat_t
	if err := m.ops.Fstat(targetFD, &stat); err != nil {
		return fmt.Errorf("inspect target netns: %w", err)
	}
	if uint64(stat.Ino) != ref.Inode {
		return fmt.Errorf("target netns inode mismatch: got %d want %d", stat.Ino, ref.Inode)
	}
	if err := m.ops.Setns(targetFD, unix.CLONE_NEWNET); err != nil {
		return fmt.Errorf("enter target netns: %w", err)
	}
	defer func() {
		if restoreErr := m.ops.Setns(originalFD, unix.CLONE_NEWNET); restoreErr != nil {
			err = reconcile.NewClassifiedError(reconcile.ErrorSafetyViolation, reconcile.ReasonNetNSRestoreFailed, 0, fmt.Errorf("restore original netns: %w", restoreErr))
		}
	}()
	if err := ctx.Err(); err != nil {
		return err
	}
	return fn(ctx)
}

func validateNetNSRef(ref NetNSRef) error {
	if ref.Path == "" || !filepath.IsAbs(ref.Path) || filepath.Clean(ref.Path) == string(filepath.Separator) {
		return fmt.Errorf("netns path must be a dedicated absolute path")
	}
	if ref.Inode == 0 {
		return fmt.Errorf("netns inode is required")
	}
	return nil
}

func isNetNSSafetyError(err error) bool {
	var classified *reconcile.ClassifiedError
	return errors.As(err, &classified) && classified.Class() == reconcile.ErrorSafetyViolation
}
