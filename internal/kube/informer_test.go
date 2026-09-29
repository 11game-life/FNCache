package kube

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/kubernetes/fake"
	"k8s.io/client-go/tools/cache"

	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

func informerPod() *corev1.Pod {
	return &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Name: "web", Namespace: "default", UID: types.UID("pod-1"), ResourceVersion: "1"}, Spec: corev1.PodSpec{NodeName: "node-a"}, Status: corev1.PodStatus{Phase: corev1.PodRunning, PodIP: "10.42.0.2"}}
}

func informerNode() *corev1.Node {
	return &corev1.Node{ObjectMeta: metav1.ObjectMeta{Name: "node-a", UID: types.UID("node-1"), ResourceVersion: "1"}, Spec: corev1.NodeSpec{PodCIDR: "10.42.0.0/24"}, Status: corev1.NodeStatus{Addresses: []corev1.NodeAddress{{Type: corev1.NodeInternalIP, Address: "192.0.2.10"}}}}
}

func TestInformerSourceSyncAndLifecycle(t *testing.T) {
	client := fake.NewSimpleClientset(informerPod(), informerNode())
	store := NewSnapshotStore()
	source, err := NewInformerSource(client, store, 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Run(ctx)
	syncCtx, syncCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer syncCancel()
	if err := source.WaitForSync(syncCtx); err != nil {
		t.Fatal(err)
	}
	snapshot := store.Snapshot()
	if len(snapshot.Pods) != 1 || len(snapshot.Nodes) != 1 {
		t.Fatalf("initial snapshot = %#v", snapshot)
	}
	if snapshot.Pods["pod-1"].PodIPv4 != netip.MustParseAddr("10.42.0.2") || snapshot.Nodes["node-a"].PodCIDR.String() != "10.42.0.0/24" || snapshot.Nodes["node-a"].InternalIPv4 != netip.MustParseAddr("192.0.2.10") {
		t.Fatalf("initial object conversion failed: %#v", snapshot)
	}

	created := informerPod()
	created.Name, created.UID, created.ResourceVersion, created.Status.PodIP = "new", types.UID("pod-2"), "2", "10.42.0.3"
	if _, err := client.CoreV1().Pods("default").Create(ctx, created, metav1.CreateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(store.Snapshot().Pods) == 2 })
	created.ResourceVersion, created.Status.PodIP = "3", "10.42.0.4"
	if _, err := client.CoreV1().Pods("default").Update(ctx, created, metav1.UpdateOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return store.Snapshot().Pods["pod-2"].PodIPv4 == netip.MustParseAddr("10.42.0.4") })
	if err := client.CoreV1().Pods("default").Delete(ctx, created.Name, metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(store.Snapshot().Pods) == 1 })
	if err := client.CoreV1().Nodes().Delete(ctx, "node-a", metav1.DeleteOptions{}); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return len(store.Snapshot().Nodes) == 0 })
}

func TestInformerSourceWaitForSyncHonorsCancellation(t *testing.T) {
	source, err := NewInformerSource(fake.NewSimpleClientset(), NewSnapshotStore(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := source.WaitForSync(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("WaitForSync error = %v, want context.Canceled", err)
	}
}

func TestInformerSourceTombstoneDelete(t *testing.T) {
	store := NewSnapshotStore()
	pod := informerPod()
	if err := store.UpsertPod(resolverPodSnapshot(pod)); err != nil {
		t.Fatal(err)
	}
	source, err := NewInformerSource(fake.NewSimpleClientset(), store, 0)
	if err != nil {
		t.Fatal(err)
	}
	source.deletePod(cache.DeletedFinalStateUnknown{Key: "default/web", Obj: pod})
	if _, ok := store.GetPod("pod-1"); ok {
		t.Fatal("tombstone delete left Pod snapshot")
	}
}

func TestInformerSourceRejectsIPv6PodAtSync(t *testing.T) {
	pod := informerPod()
	pod.Status.PodIP = "2001:db8::2"
	source, err := NewInformerSource(fake.NewSimpleClientset(pod), NewSnapshotStore(), 0)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go source.Run(ctx)
	syncCtx, syncCancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer syncCancel()
	if err := source.WaitForSync(syncCtx); err == nil {
		t.Fatal("IPv6 Pod unexpectedly passed initial snapshot sync")
	}
}

func resolverPodSnapshot(pod *corev1.Pod) resolver.PodSnapshot {
	snapshot, err := podSnapshot(pod)
	if err != nil {
		panic(err)
	}
	return snapshot
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if condition() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("condition did not become true")
}
