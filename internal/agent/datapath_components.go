package agent

import (
	"context"
	"fmt"
	"io"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
	"github.com/cat-cc-Lcos/FNCache/internal/overlay/flannel"
	"github.com/cat-cc-Lcos/FNCache/internal/ownership"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type datapathComponentConfig struct {
	ELFPath            string
	PinRoot            string
	StatePath          string
	InstallationID     string
	ELFBuildID         string
	HeartbeatNS        uint64
	HeartbeatTimeoutNS uint64
	Flags              uint32
	Preflight          discovery.PreflightRequest
	Flannel            flannel.DiscoveryRequest
	Marker             flannel.MarkerRuleSpec
}

type datapathComponents struct {
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

func newDatapathComponents(ctx context.Context, config datapathComponentConfig) (*datapathComponents, error) {
	if err := validateDatapathComponentConfig(config); err != nil {
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
	tc, err := datapath.NewTCManagerWithNetNS(tcBackend, netns)
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
	marker, err := controlplane.NewFlannelMarkerEnsurer(flannel.NewMarkerRuleManager(nil), config.Marker)
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
	components := &datapathComponents{
		cri: cri, endpointScanner: endpointScanner, pins: pins, tcScanner: tcScanner,
		sources: controlplane.Sources{Preflight: discovery.NewPreflight(discovery.NewLinuxProbe("/")), Flannel: flannel.NewDiscovery(nil), Endpoints: endpointScanner, Pins: pins, TC: tcScanner, Rules: flannel.NewRuleScanner(nil)},
		control: &runtimeControl{pinRoot: config.PinRoot, writer: controlWriter}, collection: collection, marker: marker,
		base: base, endpoint: endpoint, maps: maps, publisher: publisher,
	}
	ok = true
	return components, nil
}

func validateDatapathComponentConfig(config datapathComponentConfig) error {
	if config.ELFPath == "" || !filepath.IsAbs(config.ELFPath) || config.PinRoot == "" || !filepath.IsAbs(config.PinRoot) || config.StatePath == "" || !filepath.IsAbs(config.StatePath) {
		return fmt.Errorf("datapath paths must be absolute")
	}
	if config.InstallationID == "" || config.ELFBuildID == "" || config.Preflight.Node.Name == "" || config.Preflight.Node.UID == "" || config.Preflight.RuntimeURI == "" {
		return fmt.Errorf("datapath installation, build and node identity are required")
	}
	if config.HeartbeatNS == 0 || config.HeartbeatTimeoutNS == 0 || config.Marker.Chain == "" || config.Marker.Comment == "" {
		return fmt.Errorf("datapath heartbeat and marker identity are required")
	}
	return nil
}
