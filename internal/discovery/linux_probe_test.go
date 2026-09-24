package discovery_test

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/discovery"
)

func TestLinuxProbeReportsBasicCapabilities(t *testing.T) {
	probe, request, cleanup := probeFixture(t, true, true, true)
	defer cleanup()
	snapshot, err := probe.Probe(context.Background(), request)
	if err != nil {
		t.Fatal(err)
	}
	if snapshot.KernelRelease != "5.15.0-test" || snapshot.Architecture != runtime.GOARCH || !snapshot.HasBTF || !snapshot.BPFFSMounted {
		t.Fatalf("unexpected host snapshot: %+v", snapshot)
	}
	for _, check := range snapshot.Checks {
		if !check.Supported {
			t.Fatalf("basic check failed: %+v", check)
		}
	}
}

func TestLinuxProbeReportsMissingCapabilities(t *testing.T) {
	tests := []struct {
		name   string
		mount  bool
		btf    bool
		cri    bool
		reason string
	}{
		{name: "bpffs", btf: true, cri: true, reason: "BPFFS_NOT_MOUNTED"},
		{name: "btf", mount: true, cri: true, reason: "BTF_MISSING"},
		{name: "cri", mount: true, btf: true, reason: "CRI_SOCKET_UNAVAILABLE"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			probe, request, cleanup := probeFixture(t, tc.mount, tc.btf, tc.cri)
			defer cleanup()
			snapshot, err := probe.Probe(context.Background(), request)
			if err != nil {
				t.Fatal(err)
			}
			for _, check := range snapshot.Checks {
				if check.ReasonCode == tc.reason && check.Supported {
					t.Fatalf("expected unsupported check: %+v", check)
				}
			}
		})
	}
}

func probeFixture(t *testing.T, mount, btf, cri bool) (*discovery.LinuxProbe, discovery.PreflightRequest, func()) {
	t.Helper()
	root := t.TempDir()
	for _, dir := range []string{"proc/sys/kernel", "sys/fs/bpf", "sys/kernel/btf", "run"} {
		if err := os.MkdirAll(filepath.Join(root, dir), 0755); err != nil {
			t.Fatal(err)
		}
	}
	writeFile(t, filepath.Join(root, "proc/sys/kernel/osrelease"), "5.15.0-test\n")
	mounts := "none /sys/fs/other tmpfs rw 0 0\n"
	if mount {
		mounts = "none /sys/fs/bpf bpf rw 0 0\n"
	}
	writeFile(t, filepath.Join(root, "proc/mounts"), mounts)
	if btf {
		writeFile(t, filepath.Join(root, "sys/kernel/btf/vmlinux"), "BTF")
	}
	var listener net.Listener
	if cri {
		var err error
		listener, err = net.Listen("unix", filepath.Join(root, "run/containerd.sock"))
		if err != nil {
			t.Fatal(err)
		}
	}
	cleanup := func() {
		if listener != nil {
			_ = listener.Close()
		}
	}
	return discovery.NewLinuxProbe(root), discovery.PreflightRequest{RuntimeURI: "unix:///run/containerd.sock"}, cleanup
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0600); err != nil {
		t.Fatal(err)
	}
}
