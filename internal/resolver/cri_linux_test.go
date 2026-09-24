//go:build linux

package resolver

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc"
	runtimeapi "k8s.io/cri-api/pkg/apis/runtime/v1"
)

type fakeCRIClient struct {
	listResponse   *runtimeapi.ListPodSandboxResponse
	statusResponse map[string]*runtimeapi.PodSandboxStatusResponse
	listErr        error
	statusErr      error
	listCalls      int
}

func (f *fakeCRIClient) ListPodSandbox(_ context.Context, _ *runtimeapi.ListPodSandboxRequest, _ ...grpc.CallOption) (*runtimeapi.ListPodSandboxResponse, error) {
	f.listCalls++
	return f.listResponse, f.listErr
}
func (f *fakeCRIClient) PodSandboxStatus(_ context.Context, request *runtimeapi.PodSandboxStatusRequest, _opts ...grpc.CallOption) (*runtimeapi.PodSandboxStatusResponse, error) {
	if f.statusErr != nil {
		return nil, f.statusErr
	}
	return f.statusResponse[request.GetPodSandboxId()], nil
}

func testPod() PodIdentity { return PodIdentity{Namespace: "default", Name: "web", UID: "uid-1"} }

func testSandbox(state runtimeapi.PodSandboxState) *runtimeapi.PodSandbox {
	return &runtimeapi.PodSandbox{Id: "sandbox-1", State: state, Metadata: &runtimeapi.PodSandboxMetadata{Name: "web", Namespace: "default", Uid: "uid-1"}}
}

func testResolver(client CRIRuntimeClient) *CRISandboxResolver {
	resolver, _ := newCRISandboxResolver(client, func(string) (uint64, error) { return 42, nil })
	return resolver
}

func TestResolveSandboxReturnsNetNSIdentity(t *testing.T) {
	sandbox := testSandbox(runtimeapi.PodSandboxState_SANDBOX_READY)
	client := &fakeCRIClient{listResponse: &runtimeapi.ListPodSandboxResponse{Items: []*runtimeapi.PodSandbox{sandbox}}, statusResponse: map[string]*runtimeapi.PodSandboxStatusResponse{
		"sandbox-1": {Status: &runtimeapi.PodSandboxStatus{Id: "sandbox-1", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: sandbox.Metadata}, Info: map[string]string{"sandboxPid": "123"}},
	}}
	info, err := testResolver(client).ResolveSandbox(context.Background(), testPod())
	if err != nil || info.ID != "sandbox-1" || info.PID != 123 || info.NetNSPath != "/proc/123/ns/net" || info.NetNSInode != 42 {
		t.Fatalf("unexpected sandbox identity: info=%+v err=%v", info, err)
	}
}

func TestResolveSandboxRejectsMissingOrStaleSandbox(t *testing.T) {
	client := &fakeCRIClient{listResponse: &runtimeapi.ListPodSandboxResponse{Items: []*runtimeapi.PodSandbox{testSandbox(runtimeapi.PodSandboxState_SANDBOX_READY)}}}
	client.listResponse.Items[0].Metadata.Uid = "other"
	if _, err := testResolver(client).ResolveSandbox(context.Background(), testPod()); !errors.Is(err, ErrEndpointNotReady) {
		t.Fatalf("expected not-ready error: %v", err)
	}
	client.listResponse.Items[0].Metadata.Uid = "uid-1"
	client.statusResponse = map[string]*runtimeapi.PodSandboxStatusResponse{"sandbox-1": {Status: &runtimeapi.PodSandboxStatus{Id: "sandbox-1", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: &runtimeapi.PodSandboxMetadata{Name: "other", Namespace: "default", Uid: "uid-1"}}}}
	if _, err := testResolver(client).ResolveSandbox(context.Background(), testPod()); !errors.Is(err, ErrStaleObject) {
		t.Fatalf("expected stale error: %v", err)
	}
}

func TestResolveSandboxRejectsUnsupportedPID(t *testing.T) {
	sandbox := testSandbox(runtimeapi.PodSandboxState_SANDBOX_READY)
	client := &fakeCRIClient{listResponse: &runtimeapi.ListPodSandboxResponse{Items: []*runtimeapi.PodSandbox{sandbox}}, statusResponse: map[string]*runtimeapi.PodSandboxStatusResponse{
		"sandbox-1": {Status: &runtimeapi.PodSandboxStatus{Id: "sandbox-1", State: runtimeapi.PodSandboxState_SANDBOX_READY, Metadata: sandbox.Metadata}},
	}}
	if _, err := testResolver(client).ResolveSandbox(context.Background(), testPod()); !errors.Is(err, ErrUnsupported) {
		t.Fatalf("expected unsupported runtime error: %v", err)
	}
}

func TestResolveSandboxHonorsCancellation(t *testing.T) {
	client := &fakeCRIClient{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := testResolver(client).ResolveSandbox(ctx, testPod()); !errors.Is(err, context.Canceled) || client.listCalls != 0 {
		t.Fatalf("expected cancellation before CRI call: err=%v calls=%d", err, client.listCalls)
	}
}

func TestUnixSocketPath(t *testing.T) {
	if path, err := unixSocketPath("unix:///run/containerd/containerd.sock"); err != nil || path != "/run/containerd/containerd.sock" {
		t.Fatalf("unexpected socket path: %q err=%v", path, err)
	}
	if _, err := unixSocketPath("tcp://127.0.0.1:1"); err == nil {
		t.Fatal("expected non-unix endpoint rejection")
	}
}
