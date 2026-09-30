package controlplane

import (
	"context"
	"fmt"
	"net/netip"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type PreflightSource interface {
	Check(context.Context, discovery.PreflightRequest) (discovery.CapabilityReport, error)
}

type FlannelSource interface {
	Discover(context.Context, flannel.DiscoveryRequest) (flannel.FlannelConfig, error)
}

type EndpointSource interface {
	Scan(context.Context, []resolver.PodSnapshot) (resolver.EndpointScanResult, error)
}

type PinSource interface {
	Scan(context.Context) (reconcile.ActualState, error)
}

type TCSource interface {
	Scan(context.Context, []resolver.LinkIdentity) (reconcile.ActualState, error)
}

type RuleSource interface {
	Scan(context.Context, flannel.MarkerRuleSpec) (reconcile.RuleState, error)
}

type Sources struct {
	Preflight PreflightSource
	Flannel   FlannelSource
	Endpoints EndpointSource
	Pins      PinSource
	TC        TCSource
	Rules     RuleSource
}

type ObservationInput struct {
	Generation       uint64
	PreflightRequest discovery.PreflightRequest
	FlannelRequest   flannel.DiscoveryRequest
	MarkerRule       flannel.MarkerRuleSpec
	Pods             []resolver.PodSnapshot
	TCLinks          []resolver.LinkIdentity
	BaseTCLinks      []resolver.LinkIdentity
}

type Observer struct {
	sources Sources
	input   ObservationInput
}

func NewObserver(sources Sources, input ObservationInput) (*Observer, error) {
	missing := make([]string, 0, 6)
	if sources.Preflight == nil {
		missing = append(missing, "preflight")
	}
	if sources.Flannel == nil {
		missing = append(missing, "flannel")
	}
	if sources.Endpoints == nil {
		missing = append(missing, "endpoints")
	}
	if sources.Pins == nil {
		missing = append(missing, "pins")
	}
	if sources.TC == nil {
		missing = append(missing, "tc")
	}
	if sources.Rules == nil {
		missing = append(missing, "rules")
	}
	if len(missing) != 0 {
		return nil, fmt.Errorf("observation sources are required: %s", strings.Join(missing, ", "))
	}
	input.Pods = append([]resolver.PodSnapshot(nil), input.Pods...)
	input.TCLinks = append([]resolver.LinkIdentity(nil), input.TCLinks...)
	baseTCLinks := input.BaseTCLinks
	if baseTCLinks == nil {
		baseTCLinks = input.TCLinks
	}
	input.BaseTCLinks = append([]resolver.LinkIdentity(nil), baseTCLinks...)
	return &Observer{sources: sources, input: input}, nil
}

func (o *Observer) Discover(ctx context.Context) (reconcile.DesiredState, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.DesiredState{}, err
	}
	report, err := o.sources.Preflight.Check(ctx, o.input.PreflightRequest)
	if err != nil {
		return reconcile.DesiredState{}, fmt.Errorf("discover preflight: %w", err)
	}
	desired := reconcile.DesiredState{
		Generation:      o.input.Generation,
		Enabled:         report.Supported,
		Capability:      report,
		LocalEndpoints:  make(map[string]resolver.Endpoint),
		RemoteEndpoints: make(map[netip.Addr]reconcile.RemoteEndpoint),
	}
	if !report.Supported {
		return desired, nil
	}

	config, err := o.sources.Flannel.Discover(ctx, o.input.FlannelRequest)
	if err != nil {
		return reconcile.DesiredState{}, fmt.Errorf("discover Flannel: %w", err)
	}
	if err := config.Validate(); err != nil {
		return reconcile.DesiredState{}, fmt.Errorf("validate Flannel: %w", err)
	}
	endpoints, err := o.sources.Endpoints.Scan(ctx, o.input.Pods)
	if err != nil {
		return reconcile.DesiredState{}, fmt.Errorf("scan endpoints: %w", err)
	}
	o.input.TCLinks = resolver.MergeEndpointLinks(o.input.BaseTCLinks, endpoints.Endpoints)
	for uid, endpoint := range endpoints.Endpoints {
		desired.LocalEndpoints[uid] = endpoint
	}
	desired.Flannel = flannelState(config)
	desired.Datapath = reconcile.DatapathSpec{
		ABI:                reconcile.BPFABIVersion,
		PinRoot:            o.input.PreflightRequest.PinRoot,
		Generation:         o.input.Generation,
		VXLANVNI:           config.VNI,
		VXLANUDPPort:       config.UDPPort,
		UnderlayIfIndex:    config.UnderlayLink.IfIndex,
		UnderlayIPv4:       config.UnderlayIPv4,
		OverlayFingerprint: config.Fingerprint,
	}
	return desired, nil
}

func (o *Observer) Scan(ctx context.Context) (reconcile.ActualState, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.ActualState{}, err
	}
	actual, err := o.sources.Pins.Scan(ctx)
	if err != nil {
		return reconcile.ActualState{}, fmt.Errorf("scan BPF pins: %w", err)
	}
	tc, err := o.sources.TC.Scan(ctx, o.input.TCLinks)
	if err != nil {
		return reconcile.ActualState{}, fmt.Errorf("scan TC: %w", err)
	}
	actual.Attachments = append(actual.Attachments, tc.Attachments...)
	actual.Conflicts = append(actual.Conflicts, tc.Conflicts...)
	if actual.ScannedAt.IsZero() {
		actual.ScannedAt = tc.ScannedAt
	}
	actual.FlannelRule, err = o.sources.Rules.Scan(ctx, o.input.MarkerRule)
	if err != nil {
		return reconcile.ActualState{}, fmt.Errorf("scan Flannel rule: %w", err)
	}
	return actual, nil
}

func flannelState(config flannel.FlannelConfig) reconcile.FlannelState {
	return reconcile.FlannelState{
		BackendType:     config.BackendType,
		VXLANLink:       config.VXLANLink,
		UnderlayLink:    config.UnderlayLink,
		UnderlayIPv4:    config.UnderlayIPv4,
		PodCIDR:         config.PodCIDR,
		VNI:             config.VNI,
		UDPPort:         config.UDPPort,
		MTU:             config.MTU,
		MissMask:        config.MissMask,
		EstablishedMask: config.EstablishedMask,
		IPTablesBackend: config.IPTablesBackend,
		Fingerprint:     config.Fingerprint,
	}
}
