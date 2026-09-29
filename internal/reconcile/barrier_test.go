package reconcile

import (
	"context"
	"testing"
	"time"
)

func barrierKey(kind ReconcileKind, uid string) ReconcileKey {
	return ReconcileKey{Kind: kind, UID: uid}
}

func TestCoordinationBarrierGlobalExcludesEndpoints(t *testing.T) {
	barrier := NewCoordinationBarrier()
	globalEntered, releaseGlobal := make(chan struct{}), make(chan struct{})
	globalDone := make(chan error, 1)
	go func() {
		globalDone <- barrier.Execute(context.Background(), barrierKey(ReconcileGlobal, ""), func() error {
			close(globalEntered)
			<-releaseGlobal
			return nil
		})
	}()
	<-globalEntered
	endpointEntered := make(chan struct{}, 1)
	endpointDone := make(chan error, 1)
	go func() {
		endpointDone <- barrier.Execute(context.Background(), barrierKey(ReconcileLocalEndpoint, "pod-1"), func() error { endpointEntered <- struct{}{}; return nil })
	}()
	select {
	case <-endpointEntered:
		t.Fatal("Endpoint entered while Global was active")
	case <-time.After(10 * time.Millisecond):
	}
	close(releaseGlobal)
	if err := <-globalDone; err != nil {
		t.Fatal(err)
	}
	if err := <-endpointDone; err != nil {
		t.Fatal(err)
	}
}

func TestCoordinationBarrierSerializesSameUIDButAllowsDifferentUID(t *testing.T) {
	barrier := NewCoordinationBarrier()
	firstEntered, releaseFirst := make(chan struct{}), make(chan struct{})
	go func() {
		_ = barrier.Execute(context.Background(), barrierKey(ReconcileLocalEndpoint, "pod-1"), func() error { close(firstEntered); <-releaseFirst; return nil })
	}()
	<-firstEntered
	secondEntered := make(chan struct{}, 1)
	go func() {
		_ = barrier.Execute(context.Background(), barrierKey(ReconcileRemoteEndpoint, "pod-1"), func() error { secondEntered <- struct{}{}; return nil })
	}()
	differentEntered := make(chan struct{}, 1)
	go func() {
		_ = barrier.Execute(context.Background(), barrierKey(ReconcileRemoteEndpoint, "pod-2"), func() error { differentEntered <- struct{}{}; return nil })
	}()
	select {
	case <-secondEntered:
		t.Fatal("same UID entered concurrently")
	case <-differentEntered:
	case <-time.After(time.Second):
		t.Fatal("different UID did not enter")
	}
	close(releaseFirst)
	select {
	case <-secondEntered:
	case <-time.After(time.Second):
		t.Fatal("same UID did not enter after release")
	}
}

func TestCoordinationBarrierHonorsCancellation(t *testing.T) {
	barrier := NewCoordinationBarrier()
	entered, release := make(chan struct{}), make(chan struct{})
	go func() {
		_ = barrier.Execute(context.Background(), barrierKey(ReconcileGlobal, ""), func() error { close(entered); <-release; return nil })
	}()
	<-entered
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := barrier.Execute(ctx, barrierKey(ReconcileLocalEndpoint, "pod-2"), func() error { return nil }); err != context.Canceled {
		t.Fatalf("barrier cancellation error = %v", err)
	}
	close(release)
}
