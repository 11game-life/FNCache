//go:build linux

package datapath

import (
	"context"
	"errors"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"golang.org/x/sys/unix"
)

type fakeNetnsOps struct {
	setnsCalls []int
	closed     []int
	restoreErr error
}

func (f *fakeNetnsOps) Open(path string, _ int, _ uint32) (int, error) {
	if path == "/proc/self/ns/net" {
		return 1, nil
	}
	return 2, nil
}
func (f *fakeNetnsOps) Close(fd int) error { f.closed = append(f.closed, fd); return nil }
func (f *fakeNetnsOps) Fstat(fd int, stat *unix.Stat_t) error {
	if fd == 2 {
		stat.Ino = 42
	}
	return nil
}
func (f *fakeNetnsOps) Setns(fd, _ int) error {
	f.setnsCalls = append(f.setnsCalls, fd)
	if fd == 1 {
		return f.restoreErr
	}
	return nil
}

func testNetNSRef() NetNSRef { return NetNSRef{Path: "/proc/1/ns/net", Inode: 42} }

func TestWithNetNSRestoresAfterCallback(t *testing.T) {
	ops := &fakeNetnsOps{}
	manager := newNetNSManager(ops)
	called := false
	if err := manager.WithNetNS(context.Background(), testNetNSRef(), func(context.Context) error { called = true; return nil }); err != nil {
		t.Fatal(err)
	}
	if !called || len(ops.setnsCalls) != 2 || ops.setnsCalls[0] != 2 || ops.setnsCalls[1] != 1 || len(ops.closed) != 2 {
		t.Fatalf("unexpected netns lifecycle: called=%v setns=%v closed=%v", called, ops.setnsCalls, ops.closed)
	}
}

func TestWithNetNSRestoresAfterCallbackError(t *testing.T) {
	ops := &fakeNetnsOps{}
	manager := newNetNSManager(ops)
	want := errors.New("callback failed")
	err := manager.WithNetNS(context.Background(), testNetNSRef(), func(context.Context) error { return want })
	if !errors.Is(err, want) || len(ops.setnsCalls) != 2 {
		t.Fatalf("callback error or restore was lost: err=%v setns=%v", err, ops.setnsCalls)
	}
}

func TestWithNetNSRejectsIdentityMismatch(t *testing.T) {
	ops := &fakeNetnsOps{}
	manager := newNetNSManager(ops)
	ref := testNetNSRef()
	ref.Inode++
	if err := manager.WithNetNS(context.Background(), ref, func(context.Context) error { return nil }); err == nil || len(ops.setnsCalls) != 0 {
		t.Fatalf("mismatched netns was entered: err=%v setns=%v", err, ops.setnsCalls)
	}
}

func TestWithNetNSReportsRestoreSafetyFailure(t *testing.T) {
	ops := &fakeNetnsOps{restoreErr: errors.New("restore failed")}
	manager := newNetNSManager(ops)
	err := manager.WithNetNS(context.Background(), testNetNSRef(), func(context.Context) error { return nil })
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) || classified.ReasonCode() != reconcile.ReasonNetNSRestoreFailed || len(ops.setnsCalls) != 2 {
		t.Fatalf("restore failure was not classified: err=%v setns=%v", err, ops.setnsCalls)
	}
}

func TestWithNetNSHonorsCancellationBeforeWorker(t *testing.T) {
	ops := &fakeNetnsOps{}
	manager := newNetNSManager(ops)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := manager.WithNetNS(ctx, testNetNSRef(), func(context.Context) error { return nil }); !errors.Is(err, context.Canceled) || len(ops.setnsCalls) != 0 {
		t.Fatalf("cancellation was not honored: err=%v setns=%v", err, ops.setnsCalls)
	}
}
