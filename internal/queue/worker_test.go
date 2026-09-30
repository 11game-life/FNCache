package queue

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func workerKey() reconcile.ReconcileKey {
	return reconcile.ReconcileKey{Kind: reconcile.ReconcileLocalEndpoint, Namespace: "default", Name: "web", UID: "pod-1"}
}

func TestWorkerRetriesAndForgets(t *testing.T) {
	q, err := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	if err != nil {
		t.Fatal(err)
	}
	var calls atomic.Int32
	done := make(chan struct{}, 1)
	worker, err := NewWorker(q, func(context.Context, reconcile.ReconcileKey) error {
		if calls.Add(1) == 1 {
			return reconcile.NewClassifiedError(reconcile.ErrorRetryable, "RETRY", 0, errors.New("temporary"))
		}
		done <- struct{}{}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Run(ctx)
	q.Add(workerKey())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not retry")
	}
	if q.NumRequeues(workerKey()) != 0 {
		t.Fatalf("requeues after success = %d", q.NumRequeues(workerKey()))
	}
	q.ShutDown()
}

func TestWorkerDoesNotRetryStale(t *testing.T) {
	q, _ := New(Config{BaseDelay: time.Millisecond, MaxDelay: 10 * time.Millisecond})
	var calls atomic.Int32
	worker, _ := NewWorker(q, func(context.Context, reconcile.ReconcileKey) error {
		calls.Add(1)
		return reconcile.NewClassifiedError(reconcile.ErrorStale, "STALE", 0, nil)
	})
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Run(ctx)
	q.Add(workerKey())
	time.Sleep(20 * time.Millisecond)
	if calls.Load() != 1 || q.NumRequeues(workerKey()) != 0 {
		t.Fatalf("stale item was retried: calls=%d requeues=%d", calls.Load(), q.NumRequeues(workerKey()))
	}
	q.ShutDown()
}

func TestWorkerContextStopsQueue(t *testing.T) {
	q, _ := New(DefaultConfig())
	worker, _ := NewWorker(q, func(context.Context, reconcile.ReconcileKey) error { return nil })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { worker.Run(ctx); close(done) }()
	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("worker did not stop after context cancellation")
	}
}

func TestWorkerUsesExecutionBarrier(t *testing.T) {
	q, _ := New(DefaultConfig())
	barrier := reconcile.NewCoordinationBarrier()
	done := make(chan struct{}, 1)
	worker, err := NewWorkerWithBarrier(q, func(context.Context, reconcile.ReconcileKey) error { done <- struct{}{}; return nil }, barrier)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go worker.Run(ctx)
	q.Add(workerKey())
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("barrier worker did not process item")
	}
	q.ShutDown()
}
