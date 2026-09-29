package controlplane

import (
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type EndpointMapRemover interface {
	Delete(context.Context, string, []byte) (bool, error)
	Clear(context.Context, string) (int, error)
}

type EndpointFilterRemover interface {
	RemoveFilter(context.Context, datapath.TCFilterSpec) error
}

type EndpointRemover struct {
	maps EndpointMapRemover
	tc   EndpointFilterRemover
}

func NewEndpointRemover(maps EndpointMapRemover, tc EndpointFilterRemover) (*EndpointRemover, error) {
	if maps == nil || tc == nil {
		return nil, fmt.Errorf("endpoint Map and TC removers are required")
	}
	return &EndpointRemover{maps: maps, tc: tc}, nil
}

func (r *EndpointRemover) Remove(ctx context.Context, owned reconcile.OwnedEndpoint, actual reconcile.ActualState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !owned.PodIPv4.IsValid() || !owned.PodIPv4.Is4() || owned.NetNSInode == 0 || owned.PeerIfIndex <= 0 || owned.HostIfIndex <= 0 {
		return fmt.Errorf("owned endpoint identity is incomplete")
	}
	ip := owned.PodIPv4.As4()
	for _, name := range []string{"ingress_cache", "egressip_cache"} {
		if _, err := r.maps.Delete(ctx, name, ip[:]); err != nil {
			return fmt.Errorf("invalidate %s: %w", name, err)
		}
	}
	if _, err := r.maps.Clear(ctx, "policy_cache"); err != nil {
		return fmt.Errorf("invalidate policy_cache: %w", err)
	}
	if err := r.removeFilter(ctx, actual, "tc_init_in", owned.PeerIfIndex, owned.NetNSInode); err != nil {
		return err
	}
	return r.removeFilter(ctx, actual, "tc_masq", owned.HostIfIndex, 0)
}

func (r *EndpointRemover) removeFilter(ctx context.Context, actual reconcile.ActualState, program string, ifindex int, netnsInode uint64) error {
	identity, err := datapath.NewFixedFilter(resolver.LinkIdentity{IfIndex: ifindex, NetNSInode: netnsInode}, program, 1, true)
	if err != nil {
		return err
	}
	var found *reconcile.AttachmentState
	for index := range actual.Attachments {
		attachment := actual.Attachments[index]
		if attachment.Link.IfIndex != ifindex || attachment.Link.NetNSInode != netnsInode || attachment.Hook != string(identity.Hook) || attachment.Priority != identity.Priority || attachment.Handle != identity.Handle {
			continue
		}
		if found != nil || attachment.Program != program || attachment.ProgramID == 0 {
			return reconcile.NewClassifiedError(reconcile.ErrorConflict, reconcile.ReasonTCForeignConflict, 0, fmt.Errorf("endpoint filter identity conflict on %s/%d", program, ifindex))
		}
		found = &attachment
	}
	if found == nil {
		return nil
	}
	spec, err := datapath.NewFixedFilter(found.Link, program, found.ProgramID, true)
	if err != nil {
		return err
	}
	if err := r.tc.RemoveFilter(ctx, spec); err != nil {
		return fmt.Errorf("remove endpoint filter %s: %w", program, err)
	}
	return nil
}
