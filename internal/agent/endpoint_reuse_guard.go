package agent

import (
	"context"
	"errors"
	"fmt"
	"net/netip"

	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type EndpointReuseGuard struct {
	resolver  resolver.EndpointResolver
	localNode string
}

func NewEndpointReuseGuard(endpointResolver resolver.EndpointResolver, localNode string) (*EndpointReuseGuard, error) {
	if endpointResolver == nil || localNode == "" {
		return nil, fmt.Errorf("endpoint resolver and local node are required")
	}
	return &EndpointReuseGuard{resolver: endpointResolver, localNode: localNode}, nil
}

func (g *EndpointReuseGuard) Check(ctx context.Context, snapshot kube.Snapshot, deletedUID string, owned reconcile.OwnedEndpoint) error {
	if hasPodIPReuse(snapshot, deletedUID, owned.PodIPv4) {
		return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonPodIPReusePending, 0, nil)
	}
	for uid, pod := range snapshot.Pods {
		if uid == deletedUID || pod.NodeName != g.localNode || pod.HostNetwork || pod.Deleting {
			continue
		}
		endpoint, err := g.resolver.Resolve(ctx, pod)
		if err != nil {
			if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
				return err
			}
			if errors.Is(err, resolver.ErrEndpointNotReady) || errors.Is(err, resolver.ErrStaleObject) || errors.Is(err, resolver.ErrUnsupported) {
				return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointIdentityReuse, 0, err)
			}
			return fmt.Errorf("resolve Pod %s for endpoint reuse check: %w", uid, err)
		}
		if endpoint.Pod.UID != uid || sameOwnedLinkIdentity(endpoint, owned) {
			return reconcile.NewClassifiedError(reconcile.ErrorRetryable, reconcile.ReasonEndpointIdentityReuse, 0, nil)
		}
	}
	return nil
}

func sameOwnedLinkIdentity(endpoint resolver.Endpoint, owned reconcile.OwnedEndpoint) bool {
	samePeer := endpoint.NetNSInode == owned.NetNSInode && endpoint.PeerLink.IfIndex == owned.PeerIfIndex
	sameHost := endpoint.HostLink.IfIndex == owned.HostIfIndex
	return samePeer || sameHost
}

func hasPodIPReuse(snapshot kube.Snapshot, deletedUID string, podIP netip.Addr) bool {
	if !podIP.IsValid() || !podIP.Is4() {
		return false
	}
	for uid, pod := range snapshot.Pods {
		if uid != deletedUID && !pod.Deleting && pod.PodIPv4 == podIP {
			return true
		}
	}
	return false
}
