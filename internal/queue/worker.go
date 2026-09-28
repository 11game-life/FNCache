package queue

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type Handler func(context.Context, reconcile.ReconcileKey) error

type Worker struct {
	queue   *Queue
	handler Handler
}

func NewWorker(queue *Queue, handler Handler) (*Worker, error) {
	if queue == nil || handler == nil {
		return nil, fmt.Errorf("queue and handler are required")
	}
	return &Worker{queue: queue, handler: handler}, nil
}

func (w *Worker) Run(ctx context.Context) {
	stopWatcher := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			w.queue.ShutDown()
		case <-stopWatcher:
		}
	}()
	defer close(stopWatcher)

	for {
		key, shutdown := w.queue.Get()
		if shutdown {
			return
		}
		err := w.handler(ctx, key)
		switch {
		case err == nil || ctx.Err() != nil:
			w.queue.Forget(key)
		case retryDecision(err).retry:
			if delay := retryDecision(err).after; delay > 0 {
				w.queue.AddAfter(key, delay)
			} else {
				w.queue.AddRateLimited(key)
			}
		default:
			w.queue.Forget(key)
		}
		w.queue.Done(key)
	}
}

type retryResult struct {
	retry bool
	after time.Duration
}

func retryDecision(err error) retryResult {
	var classified *reconcile.ClassifiedError
	if !errors.As(err, &classified) {
		return retryResult{retry: true}
	}
	switch classified.Class() {
	case reconcile.ErrorRetryable, reconcile.ErrorInternal:
		return retryResult{retry: true, after: classified.RetryAfter()}
	default:
		return retryResult{}
	}
}
