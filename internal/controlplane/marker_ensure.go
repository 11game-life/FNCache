package controlplane

import (
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type FlannelMarkerEnsurer struct {
	manager *flannel.MarkerRuleManager
	spec    flannel.MarkerRuleSpec
}

func NewFlannelMarkerEnsurer(manager *flannel.MarkerRuleManager, spec flannel.MarkerRuleSpec) (*FlannelMarkerEnsurer, error) {
	if manager == nil {
		return nil, fmt.Errorf("Flannel marker manager is required")
	}
	if spec.Chain == "" || spec.Comment == "" {
		return nil, fmt.Errorf("Flannel marker rule identity is required")
	}
	return &FlannelMarkerEnsurer{manager: manager, spec: spec}, nil
}

func (e *FlannelMarkerEnsurer) EnsureMarker(ctx context.Context, desired reconcile.DesiredState) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, err
	}
	if !desired.Enabled {
		return false, nil
	}
	if err := validateMarkerFlannelState(desired.Flannel); err != nil {
		return false, err
	}
	state, changed, err := e.manager.Ensure(ctx, e.spec)
	if err != nil {
		return false, fmt.Errorf("ensure Flannel marker: %w", err)
	}
	if !state.Present {
		return false, fmt.Errorf("Flannel marker was not present after ensure")
	}
	return changed, nil
}

func validateMarkerFlannelState(state reconcile.FlannelState) error {
	if state.BackendType != "vxlan" {
		return fmt.Errorf("unsupported Flannel backend for marker: %q", state.BackendType)
	}
	if state.MissMask != 0x04 || state.EstablishedMask != 0x08 {
		return fmt.Errorf("Flannel marker masks are not reserved for ONCache")
	}
	if state.IPTablesBackend != "iptables-nft" {
		return fmt.Errorf("unsupported iptables backend for marker: %q", state.IPTablesBackend)
	}
	return nil
}
