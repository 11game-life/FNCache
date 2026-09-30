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

func (r *EndpointRemover) Remove(ctx context.Context, owned reconcile.OwnedEndpoint, actual reconcile.ActualState, desired reconcile.DesiredState) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	if !owned.PodIPv4.IsValid() || !owned.PodIPv4.Is4() || owned.NetNSInode == 0 || owned.PeerIfIndex <= 0 || owned.HostIfIndex <= 0 {
		return fmt.Errorf("owned endpoint identity is incomplete")
	}
	ipProtected := false
	for uid, endpoint := range desired.LocalEndpoints {
		if uid == owned.PodUID {
			continue
		}
		if endpoint.PodIPv4 == owned.PodIPv4 {
			ipProtected = true
		}
	}
	peerProtected := desiredClaimsEndpointLink(desired, actual, owned, "tc_init_in", owned.PeerIfIndex, owned.NetNSInode)
	hostProtected := desiredClaimsEndpointLink(desired, actual, owned, "tc_masq", owned.HostIfIndex, 0)
	if !ipProtected {
		ip := owned.PodIPv4.As4()
		for _, name := range []string{"ingress_cache", "egressip_cache"} {
			if _, err := r.maps.Delete(ctx, name, ip[:]); err != nil {
				return fmt.Errorf("invalidate %s: %w", name, err)
			}
		}
	}
	if _, err := r.maps.Clear(ctx, "policy_cache"); err != nil {
		return fmt.Errorf("invalidate policy_cache: %w", err)
	}
	if !peerProtected {
		if err := r.removeFilter(ctx, actual, "tc_init_in", owned.PeerIfIndex, owned.NetNSInode); err != nil {
			return err
		}
	}
	if !hostProtected {
		if err := r.removeFilter(ctx, actual, "tc_masq", owned.HostIfIndex, 0); err != nil {
			return err
		}
	}
	return nil
}

func desiredClaimsEndpointLink(desired reconcile.DesiredState, actual reconcile.ActualState, owned reconcile.OwnedEndpoint, program string, ifindex int, netnsInode uint64) bool {
	for uid, endpoint := range desired.LocalEndpoints {
		if uid == owned.PodUID {
			continue
		}
		link := endpoint.HostLink
		if program == "tc_init_in" {
			link = endpoint.PeerLink
		}
		if link.IfIndex != ifindex || link.NetNSInode != netnsInode {
			continue
		}
		identity, err := datapath.NewFixedFilter(link, program, 1, true)
		if err != nil {
			continue
		}
		for _, attachment := range actual.Attachments {
			if attachment.Program == program && attachment.Hook == string(identity.Hook) && attachment.Priority == identity.Priority && attachment.Handle == identity.Handle && sameLinkIdentity(attachment.Link, link) {
				return true
			}
		}
	}
	return false
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
