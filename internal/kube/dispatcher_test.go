package kube

import (
	"context"
	"testing"
	"time"

	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/cat-cc-Lcos/FNCache/internal/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestEventDispatcherEnqueuesInformerAndMigrationEvents(t *testing.T) {
	client := fake.NewSimpleClientset(informerPod(), informerNode())
	store := NewSnapshotStore()
	source, err := NewInformerSource(client, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	classifier, _ := NewEventClassifier("node-a")
	target, _ := queue.New(queue.DefaultConfig())
	dispatcher, err := NewEventDispatcher(source, classifier, target)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Run(ctx)
	syncCtx, syncCancel := context.WithTimeout(context.Background(), time.Second)
	defer syncCancel()
	if err := source.WaitForSync(syncCtx); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return target.Len() == 2 })
	keys := drainDispatchQueue(target)
	if !hasKind(keys, reconcile.ReconcileLocalEndpoint) || !hasKind(keys, reconcile.ReconcileGlobal) {
		t.Fatalf("initial event keys = %#v", keys)
	}
	oldPod := informerPod()
	newPod := oldPod.DeepCopy()
	newPod.Spec.NodeName = "node-b"
	dispatcher.updatePod(oldPod, newPod)
	waitFor(t, func() bool { return target.Len() == 2 })
	keys = drainDispatchQueue(target)
	if len(keys) != 2 || !hasKind(keys, reconcile.ReconcileLocalEndpoint) || !hasKind(keys, reconcile.ReconcileRemoteEndpoint) {
		t.Fatalf("migration event keys = %#v", keys)
	}
}

func TestEventDispatcherHandlesTombstone(t *testing.T) {
	source, err := NewInformerSource(fake.NewSimpleClientset(), NewSnapshotStore(), 0)
	if err != nil {
		t.Fatal(err)
	}
	classifier, _ := NewEventClassifier("node-a")
	target, _ := queue.New(queue.DefaultConfig())
	dispatcher, err := NewEventDispatcher(source, classifier, target)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.deletePod(cache.DeletedFinalStateUnknown{Key: "default/web", Obj: informerPod()})
	if target.Len() != 1 {
		t.Fatalf("tombstone queue length = %d", target.Len())
	}
	key, shutdown := target.Get()
	if shutdown || key.Kind != reconcile.ReconcileLocalEndpoint {
		t.Fatalf("tombstone key = %#v shutdown=%v", key, shutdown)
	}
	target.Forget(key)
	target.Done(key)
	target.ShutDown()
}

func drainDispatchQueue(target *queue.Queue) []reconcile.ReconcileKey {
	keys := make([]reconcile.ReconcileKey, 0, target.Len())
	for target.Len() > 0 {
		key, shutdown := target.Get()
		if shutdown {
			break
		}
		keys = append(keys, key)
		target.Forget(key)
		target.Done(key)
	}
	return keys
}

func hasKind(keys []reconcile.ReconcileKey, want reconcile.ReconcileKind) bool {
	for _, key := range keys {
		if key.Kind == want {
			return true
		}
	}
	return false
}
