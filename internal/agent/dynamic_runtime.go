package agent

import (
	"context"
	"fmt"
	"time"

	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"

	"github.com/cat-cc-Lcos/FNCache/internal/config"
	"github.com/cat-cc-Lcos/FNCache/internal/kube"
	"github.com/cat-cc-Lcos/FNCache/internal/queue"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type DynamicRuntime struct {
	store     *kube.SnapshotStore
	source    *kube.InformerSource
	bootstrap *KubeBootstrap
	resync    *kube.ResyncScheduler
	queue     *queue.Queue
	barrier   *reconcile.CoordinationBarrier
}

func NewDynamicRuntime(configPath string) (*DynamicRuntime, error) {
	cfg, err := config.Load(configPath)
	if err != nil {
		return nil, fmt.Errorf("load agent configuration: %w", err)
	}
	clusterConfig, err := rest.InClusterConfig()
	if err != nil {
		return nil, fmt.Errorf("load in-cluster Kubernetes configuration: %w", err)
	}
	client, err := kubernetes.NewForConfig(clusterConfig)
	if err != nil {
		return nil, fmt.Errorf("create Kubernetes client: %w", err)
	}
	return newDynamicRuntime(cfg, client)
}

func newDynamicRuntime(cfg config.AgentConfiguration, client kubernetes.Interface) (*DynamicRuntime, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if client == nil {
		return nil, fmt.Errorf("Kubernetes client is required")
	}
	store := kube.NewSnapshotStore()
	interval := time.Duration(cfg.Kube.ResyncInterval)
	source, err := kube.NewInformerSource(client, store, interval)
	if err != nil {
		return nil, err
	}
	target, err := queue.New(queue.DefaultConfig())
	if err != nil {
		return nil, fmt.Errorf("create coordination queue: %w", err)
	}
	classifier, err := kube.NewEventClassifier(cfg.NodeName)
	if err != nil {
		return nil, err
	}
	if _, err := kube.NewEventDispatcher(source, classifier, target); err != nil {
		return nil, err
	}
	bootstrap, err := NewKubeBootstrap(source, store)
	if err != nil {
		return nil, err
	}
	resync, err := kube.NewResyncScheduler(store, cfg.NodeName, target, interval)
	if err != nil {
		return nil, err
	}
	return &DynamicRuntime{store: store, source: source, bootstrap: bootstrap, resync: resync, queue: target, barrier: reconcile.NewCoordinationBarrier()}, nil
}

func (r *DynamicRuntime) Run(ctx context.Context) error {
	if err := r.bootstrap.Start(ctx); err != nil {
		return err
	}
	go r.resync.Run(ctx)
	<-ctx.Done()
	r.queue.ShutDown()
	return nil
}

func (r *DynamicRuntime) State() KubeBootstrapState { return r.bootstrap.State() }
