package reconcile

import (
	"context"
	"fmt"
	"sync"
)

type CoordinationBarrier struct {
	mu              sync.Mutex
	changed         chan struct{}
	globalActive    bool
	globalWaiters   int
	activeEndpoints int
	resources       map[string]*barrierResource
}

type barrierResource struct {
	sem  chan struct{}
	refs int
}

func NewCoordinationBarrier() *CoordinationBarrier {
	return &CoordinationBarrier{changed: make(chan struct{}), resources: make(map[string]*barrierResource)}
}

func (b *CoordinationBarrier) Execute(ctx context.Context, key ReconcileKey, fn func() error) error {
	if ctx == nil || fn == nil {
		return fmt.Errorf("barrier context and function are required")
	}
	if key.Kind == ReconcileGlobal {
		if err := b.acquireGlobal(ctx); err != nil {
			return err
		}
		defer b.releaseGlobal()
		return fn()
	}
	release, err := b.acquireEndpoint(ctx, resourceKey(key))
	if err != nil {
		return err
	}
	defer release()
	return fn()
}

func (b *CoordinationBarrier) acquireGlobal(ctx context.Context) error {
	b.mu.Lock()
	b.globalWaiters++
	for b.globalActive || b.activeEndpoints != 0 {
		wait := b.changed
		b.mu.Unlock()
		select {
		case <-wait:
			b.mu.Lock()
		case <-ctx.Done():
			b.mu.Lock()
			b.globalWaiters--
			b.signalLocked()
			b.mu.Unlock()
			return ctx.Err()
		}
	}
	b.globalWaiters--
	b.globalActive = true
	b.mu.Unlock()
	return nil
}

func (b *CoordinationBarrier) releaseGlobal() {
	b.mu.Lock()
	b.globalActive = false
	b.signalLocked()
	b.mu.Unlock()
}

func (b *CoordinationBarrier) acquireEndpoint(ctx context.Context, key string) (func(), error) {
	b.mu.Lock()
	for b.globalActive || b.globalWaiters != 0 {
		wait := b.changed
		b.mu.Unlock()
		select {
		case <-wait:
			b.mu.Lock()
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	b.activeEndpoints++
	resource := b.resources[key]
	if resource == nil {
		resource = &barrierResource{sem: make(chan struct{}, 1)}
		resource.sem <- struct{}{}
		b.resources[key] = resource
	}
	resource.refs++
	b.mu.Unlock()
	select {
	case <-resource.sem:
		return func() { b.releaseEndpoint(key, resource, true) }, nil
	case <-ctx.Done():
		b.releaseEndpoint(key, resource, false)
		return nil, ctx.Err()
	}
}

func (b *CoordinationBarrier) releaseEndpoint(key string, resource *barrierResource, acquired bool) {
	if acquired {
		resource.sem <- struct{}{}
	}
	b.mu.Lock()
	b.activeEndpoints--
	resource.refs--
	if resource.refs == 0 {
		delete(b.resources, key)
	}
	b.signalLocked()
	b.mu.Unlock()
}

func (b *CoordinationBarrier) signalLocked() {
	close(b.changed)
	b.changed = make(chan struct{})
}

func resourceKey(key ReconcileKey) string {
	if key.UID != "" {
		return "uid:" + key.UID
	}
	return "queue:" + key.QueueKey()
}
