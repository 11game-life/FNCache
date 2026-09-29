package agent

import (
	"context"
	"fmt"
	"sort"
	"sync/atomic"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type DynamicObserver struct {
	config     config.AgentConfiguration
	store      *kube.SnapshotStore
	sources    controlplane.Sources
	generation atomic.Uint64
}

func NewDynamicObserver(cfg config.AgentConfiguration, store *kube.SnapshotStore, sources controlplane.Sources) (*DynamicObserver, error) {
	if store == nil || sources.Preflight == nil || sources.Flannel == nil || sources.Endpoints == nil || sources.Pins == nil || sources.TC == nil || sources.Rules == nil {
		return nil, fmt.Errorf("dynamic observer sources are required")
	}
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &DynamicObserver{config: cfg, store: store, sources: sources}, nil
}

func (o *DynamicObserver) Desired(ctx context.Context) (reconcile.DesiredState, error) {
	snapshot := o.store.Snapshot()
	observer, err := o.buildObserver(ctx, snapshot)
	if err != nil {
		return reconcile.DesiredState{}, err
	}
	desired, err := observer.Discover(ctx)
	if err != nil {
		return reconcile.DesiredState{}, err
	}
	return kube.BuildDesiredState(snapshot, desired, o.config.NodeName, desired.LocalEndpoints)
}

func (o *DynamicObserver) Scan(ctx context.Context) (reconcile.ActualState, error) {
	snapshot := o.store.Snapshot()
	observer, err := o.buildObserver(ctx, snapshot)
	if err != nil {
		return reconcile.ActualState{}, err
	}
	return observer.Scan(ctx)
}

func (o *DynamicObserver) buildObserver(ctx context.Context, snapshot kube.Snapshot) (*controlplane.Observer, error) {
	node, ok := snapshot.Nodes[o.config.NodeName]
	if !ok || node.Identity.UID == "" {
		return nil, fmt.Errorf("local Node %q is missing from Snapshot", o.config.NodeName)
	}
	flannelRequest := flannel.DiscoveryRequest{
		VXLANLinkName: o.config.Overlay.VXLANLinkName, UnderlayDevice: o.config.Overlay.Device,
		MissMask: o.config.Markers.MissMask, EstablishedMask: o.config.Markers.EstablishedMask, IPTablesBackend: "iptables-nft",
	}
	flannelConfig, err := o.sources.Flannel.Discover(ctx, flannelRequest)
	if err != nil {
		return nil, fmt.Errorf("discover Flannel for dynamic observer: %w", err)
	}
	if err := flannelConfig.Validate(); err != nil {
		return nil, fmt.Errorf("validate Flannel for dynamic observer: %w", err)
	}
	localPods := localPodsFromSnapshot(snapshot, o.config.NodeName)
	endpoints, err := o.sources.Endpoints.Scan(ctx, localPods)
	if err != nil {
		return nil, fmt.Errorf("scan local endpoints for dynamic observer: %w", err)
	}
	links := mergeEndpointLinks([]resolver.LinkIdentity{flannelConfig.UnderlayLink}, endpoints.Endpoints)
	observer, err := controlplane.NewObserver(o.sources, controlplane.ObservationInput{
		Generation:       o.generation.Add(1),
		PreflightRequest: discovery.PreflightRequest{Node: node.Identity, PinRoot: o.config.PinRoot, StateDir: o.config.StateDir, RuntimeURI: o.config.RuntimeEndpoint, Overlay: o.config.Overlay.Type},
		FlannelRequest:   flannelRequest,
		MarkerRule:       flannel.MarkerRuleSpec{Chain: o.config.Markers.Chain, Comment: o.config.Markers.Comment},
		Pods:             localPods, TCLinks: links,
	})
	if err != nil {
		return nil, err
	}
	return observer, nil
}

func localPodsFromSnapshot(snapshot kube.Snapshot, nodeName string) []resolver.PodSnapshot {
	pods := make([]resolver.PodSnapshot, 0)
	for _, pod := range snapshot.Pods {
		if pod.NodeName == nodeName {
			pods = append(pods, pod)
		}
	}
	sort.Slice(pods, func(i, j int) bool { return pods[i].Identity.UID < pods[j].Identity.UID })
	return pods
}
