package kube

import (
	"net/netip"
	"testing"
	"time"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

func desiredPod(uid, node string, ip netip.Addr) resolver.PodSnapshot {
	return resolver.PodSnapshot{Identity: resolver.PodIdentity{Namespace: "default", Name: uid, UID: uid}, NodeName: node, PodIPv4: ip, Phase: "Running"}
}

func desiredEndpoint(uid string) resolver.Endpoint {
	return resolver.Endpoint{Pod: resolver.PodIdentity{Namespace: "default", Name: uid, UID: uid}, Node: resolver.NodeIdentity{Name: "node-a"}, PodIPv4: netip.MustParseAddr("10.42.0.2"), NetNSInode: 42, PeerLink: resolver.LinkIdentity{NetNSInode: 42, IfIndex: 2, MAC: []byte{1, 2, 3}}, HostLink: resolver.LinkIdentity{IfIndex: 3, MAC: []byte{4, 5, 6}}}
}

func TestBuildDesiredStateSeparatesPodsAndResolvedEndpoints(t *testing.T) {
	deleting := desiredPod("pod-deleting", "node-a", netip.MustParseAddr("10.42.0.5"))
	deleting.Deleting = true
	pending := desiredPod("pod-pending", "node-a", netip.Addr{})
	pending.Phase = "Pending"
	snapshot := Snapshot{Nodes: map[string]NodeSnapshot{"node-a": {Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}}}, Pods: map[string]resolver.PodSnapshot{
		"pod-local":   desiredPod("pod-local", "node-a", netip.MustParseAddr("10.42.0.2")),
		"pod-pending": pending, "pod-host": func() resolver.PodSnapshot {
			p := desiredPod("pod-host", "node-a", netip.MustParseAddr("10.42.0.3"))
			p.HostNetwork = true
			return p
		}(),
		"pod-deleting": deleting, "pod-remote": desiredPod("pod-remote", "node-b", netip.MustParseAddr("10.42.1.2")),
	}}
	base := reconcile.DesiredState{Generation: 7, Enabled: true, RemoteEndpoints: map[netip.Addr]reconcile.RemoteEndpoint{netip.MustParseAddr("10.42.9.9"): {}}}
	resolved := map[string]resolver.Endpoint{"pod-local": desiredEndpoint("pod-local"), "pod-remote": desiredEndpoint("pod-remote")}
	desired, err := BuildDesiredState(snapshot, base, "node-a", resolved)
	if err != nil {
		t.Fatal(err)
	}
	if len(desired.LocalPods) != 2 || desired.LocalPods["pod-local"].Identity.UID == "" || desired.LocalPods["pod-pending"].Identity.UID == "" {
		t.Fatalf("unexpected local Pods: %#v", desired.LocalPods)
	}
	if len(desired.LocalEndpoints) != 1 || desired.LocalEndpoints["pod-local"].Pod.UID != "pod-local" {
		t.Fatalf("unexpected local endpoints: %#v", desired.LocalEndpoints)
	}
	if len(desired.RemoteEndpoints) != 0 {
		t.Fatalf("remote endpoints were guessed: %#v", desired.RemoteEndpoints)
	}
	resolved["pod-local"].PeerLink.MAC[0] = 99
	if desired.LocalEndpoints["pod-local"].PeerLink.MAC[0] == 99 {
		t.Fatal("desired endpoint shares mutable MAC storage with input")
	}
}

func TestBuildDesiredStateRejectsMissingNodeAndInvalidEndpoint(t *testing.T) {
	snapshot := Snapshot{Nodes: map[string]NodeSnapshot{}, Pods: map[string]resolver.PodSnapshot{}}
	if _, err := BuildDesiredState(snapshot, reconcile.DesiredState{}, "node-a", nil); err == nil {
		t.Fatal("missing local Node was accepted")
	}
	snapshot.Nodes["node-a"] = NodeSnapshot{Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}}
	snapshot.Pods["pod-a"] = desiredPod("pod-a", "node-a", netip.MustParseAddr("10.42.0.2"))
	invalid := desiredEndpoint("pod-a")
	invalid.ObservedAt = time.Time{}
	invalid.HostLink.IfIndex = 0
	if _, err := BuildDesiredState(snapshot, reconcile.DesiredState{}, "node-a", map[string]resolver.Endpoint{"pod-a": invalid}); err == nil {
		t.Fatal("invalid resolved endpoint was accepted")
	}
}

func TestBuildDesiredStateRejectsEndpointUIDMismatch(t *testing.T) {
	snapshot := Snapshot{Nodes: map[string]NodeSnapshot{"node-a": {Identity: resolver.NodeIdentity{Name: "node-a", UID: "node-1"}}}, Pods: map[string]resolver.PodSnapshot{"pod-a": desiredPod("pod-a", "node-a", netip.MustParseAddr("10.42.0.2"))}}
	if _, err := BuildDesiredState(snapshot, reconcile.DesiredState{}, "node-a", map[string]resolver.Endpoint{"pod-a": desiredEndpoint("pod-b")}); err == nil {
		t.Fatal("endpoint UID mismatch was accepted")
	}
}
