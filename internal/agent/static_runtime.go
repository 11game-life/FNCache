package agent

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/ownership"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type StaticRuntimeConfig struct {
	ELFPath            string
	PinRoot            string
	StatePath          string
	InstallationID     string
	ELFBuildID         string
	Generation         uint64
	HeartbeatNS        uint64
	HeartbeatTimeoutNS uint64
	Flags              uint32
	Preflight          discovery.PreflightRequest
	Flannel            flannel.DiscoveryRequest
	Marker             flannel.MarkerRuleSpec
	Pods               []resolver.PodSnapshot
	TCLinks            []resolver.LinkIdentity
}

type StaticRuntime struct {
	config          StaticRuntimeConfig
	cri             io.Closer
	endpointScanner *resolver.EndpointScanner
	pins            *datapath.PinScanner
	tcScanner       *datapath.TCScanner
	sources         controlplane.Sources
	control         *runtimeControl
	collection      *controlplane.CollectionEnsurer
	marker          *controlplane.FlannelMarkerEnsurer
	base            *controlplane.BaseEnsurer
	endpoint        *controlplane.EndpointEnsurer
	maps            *controlplane.MapEnsurer
	publisher       *controlplane.Publisher
}

func NewStaticRuntime(ctx context.Context, config StaticRuntimeConfig) (*StaticRuntime, error) {
	if err := validateStaticRuntimeConfig(config); err != nil {
		return nil, err
	}
	sandbox, cri, err := resolver.DialContainerdCRI(ctx, config.Preflight.RuntimeURI)
	if err != nil {
		return nil, err
	}
	ok := false
	defer func() {
		if !ok {
			_ = cri.Close()
		}
	}()

	netns := datapath.NewNetNSManager()
	endpointResolver, err := resolver.NewLinuxEndpointResolver(sandbox, func(ctx context.Context, info resolver.SandboxInfo, fn func(context.Context) error) error {
		return netns.WithNetNS(ctx, datapath.NetNSRef{Path: info.NetNSPath, Inode: info.NetNSInode}, fn)
	})
	if err != nil {
		return nil, err
	}
	endpointScanner, err := resolver.NewEndpointScanner(endpointResolver)
	if err != nil {
		return nil, err
	}
	pins, err := datapath.NewPinScanner(config.PinRoot)
	if err != nil {
		return nil, err
	}
	tcBackend, err := datapath.NewLinuxTCBackend(config.PinRoot)
	if err != nil {
		return nil, err
	}
	tc, err := datapath.NewTCManager(tcBackend)
	if err != nil {
		return nil, err
	}
	tcScanner, err := datapath.NewTCScanner(tc)
	if err != nil {
		return nil, err
	}
	controlWriter, err := datapath.NewControlWriter(config.PinRoot)
	if err != nil {
		return nil, err
	}
	collection, err := controlplane.NewCollectionEnsurer(config.ELFPath, config.PinRoot)
	if err != nil {
		return nil, err
	}
	markerManager := flannel.NewMarkerRuleManager(nil)
	marker, err := controlplane.NewFlannelMarkerEnsurer(markerManager, config.Marker)
	if err != nil {
		return nil, err
	}
	base, err := controlplane.NewBaseEnsurer(tc)
	if err != nil {
		return nil, err
	}
	endpoint, err := controlplane.NewEndpointEnsurer(tc)
	if err != nil {
		return nil, err
	}
	mapWriter, err := datapath.NewMapWriter(config.PinRoot)
	if err != nil {
		return nil, err
	}
	maps, err := controlplane.NewMapEnsurer(mapWriter)
	if err != nil {
		return nil, err
	}
	store, err := ownership.NewStore(config.StatePath)
	if err != nil {
		return nil, err
	}
	publisher, err := controlplane.NewPublisher(store, controlWriter, controlplane.PublishConfig{
		InstallationID: config.InstallationID, NodeUID: config.Preflight.Node.UID, ELFBuildID: config.ELFBuildID,
		HeartbeatNS: config.HeartbeatNS, HeartbeatTimeoutNS: config.HeartbeatTimeoutNS, Flags: config.Flags,
	})
	if err != nil {
		return nil, err
	}
	preflight := discovery.NewPreflight(discovery.NewLinuxProbe("/"))
	flannelSource := flannel.NewDiscovery(nil)
	ruleScanner := flannel.NewRuleScanner(nil)
	runtime := &StaticRuntime{
		config: config, cri: cri, endpointScanner: endpointScanner, pins: pins, tcScanner: tcScanner,
		sources: controlplane.Sources{Preflight: preflight, Flannel: flannelSource, Endpoints: endpointScanner, Pins: pins, TC: tcScanner, Rules: ruleScanner},
		control: &runtimeControl{pinRoot: config.PinRoot, writer: controlWriter}, collection: collection, marker: marker,
		base: base, endpoint: endpoint, maps: maps, publisher: publisher,
	}
	ok = true
	return runtime, nil
}

func (r *StaticRuntime) RunOnce(ctx context.Context) (reconcile.ReconcileResult, error) {
	if err := ctx.Err(); err != nil {
		return reconcile.ReconcileResult{}, err
	}
	endpoints, err := r.endpointScanner.Scan(ctx, r.config.Pods)
	if err != nil {
		return reconcile.ReconcileResult{}, fmt.Errorf("prepare endpoint links: %w", err)
	}
	links := mergeEndpointLinks(r.config.TCLinks, endpoints.Endpoints)
	observer, err := controlplane.NewObserver(r.sources, controlplane.ObservationInput{
		Generation: r.config.Generation, PreflightRequest: r.config.Preflight, FlannelRequest: r.config.Flannel,
		MarkerRule: r.config.Marker, Pods: r.config.Pods, TCLinks: links,
	})
	if err != nil {
		return reconcile.ReconcileResult{}, err
	}
	backend, err := controlplane.NewFirstPassBackend(controlplane.FirstPassBackendConfig{
		Observer: observer, Control: r.control, Collection: r.collection, Marker: r.marker,
		Base: r.base, Endpoint: r.endpoint, Maps: r.maps, Publisher: r.publisher,
	})
	if err != nil {
		return reconcile.ReconcileResult{}, err
	}
	coordinator, err := reconcile.NewCoordinator(backend)
	if err != nil {
		return reconcile.ReconcileResult{}, err
	}
	return coordinator.FullReconcile(ctx)
}

func (r *StaticRuntime) Close() error {
	if r == nil || r.cri == nil {
		return nil
	}
	err := r.cri.Close()
	r.cri = nil
	return err
}

type runtimeControl struct {
	pinRoot string
	writer  *datapath.ControlWriter
}

func (c *runtimeControl) Disable(ctx context.Context) error {
	path := filepath.Join(c.pinRoot, "maps", "control_map")
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	return c.writer.Disable(ctx)
}

func (c *runtimeControl) Publish(ctx context.Context, generation, heartbeatNS, heartbeatTimeoutNS uint64, flags uint32) error {
	return c.writer.Publish(ctx, generation, heartbeatNS, heartbeatTimeoutNS, flags)
}

func validateStaticRuntimeConfig(config StaticRuntimeConfig) error {
	if config.ELFPath == "" || !filepath.IsAbs(config.ELFPath) {
		return fmt.Errorf("ELFPath must be an absolute file path")
	}
	if config.PinRoot == "" || !filepath.IsAbs(config.PinRoot) || filepath.Clean(config.PinRoot) == string(filepath.Separator) {
		return fmt.Errorf("PinRoot must be a dedicated absolute directory")
	}
	if config.Preflight.PinRoot != config.PinRoot {
		return fmt.Errorf("preflight PinRoot must match runtime PinRoot")
	}
	if config.StatePath == "" || !filepath.IsAbs(config.StatePath) || filepath.Clean(config.StatePath) == string(filepath.Separator) {
		return fmt.Errorf("StatePath must be a dedicated absolute file")
	}
	if config.Preflight.Node.Name == "" || config.Preflight.Node.UID == "" || config.Preflight.RuntimeURI == "" {
		return fmt.Errorf("node identity and runtime endpoint are required")
	}
	if config.InstallationID == "" || config.ELFBuildID == "" || config.HeartbeatNS == 0 || config.HeartbeatTimeoutNS == 0 {
		return fmt.Errorf("installation, ELF build and heartbeat values are required")
	}
	if len(config.TCLinks) == 0 {
		return fmt.Errorf("at least one TC link is required")
	}
	if config.Marker.Chain == "" || config.Marker.Comment == "" {
		return fmt.Errorf("marker identity is required")
	}
	return nil
}

func mergeEndpointLinks(base []resolver.LinkIdentity, endpoints map[string]resolver.Endpoint) []resolver.LinkIdentity {
	result := append([]resolver.LinkIdentity(nil), base...)
	seen := make(map[[2]uint64]struct{}, len(result))
	for _, link := range result {
		seen[[2]uint64{link.NetNSInode, uint64(link.IfIndex)}] = struct{}{}
	}
	uids := make([]string, 0, len(endpoints))
	for uid := range endpoints {
		uids = append(uids, uid)
	}
	sort.Strings(uids)
	for _, uid := range uids {
		endpoint := endpoints[uid]
		for _, link := range []resolver.LinkIdentity{endpoint.PeerLink, endpoint.HostLink} {
			key := [2]uint64{link.NetNSInode, uint64(link.IfIndex)}
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			result = append(result, link)
		}
	}
	return result
}
