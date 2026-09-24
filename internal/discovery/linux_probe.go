package discovery

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

type LinuxProbe struct {
	root     string
	dialUnix func(context.Context, string) (net.Conn, error)
}

func NewLinuxProbe(root string) *LinuxProbe {
	if root == "" {
		root = string(filepath.Separator)
	}
	return &LinuxProbe{
		root: filepath.Clean(root),
		dialUnix: func(ctx context.Context, path string) (net.Conn, error) {
			return (&net.Dialer{Timeout: 250 * time.Millisecond}).DialContext(ctx, "unix", path)
		},
	}
}

func (p *LinuxProbe) Probe(ctx context.Context, req PreflightRequest) (ProbeSnapshot, error) {
	if err := ctx.Err(); err != nil {
		return ProbeSnapshot{}, err
	}
	release, err := os.ReadFile(p.path("/proc/sys/kernel/osrelease"))
	if err != nil {
		return ProbeSnapshot{}, fmt.Errorf("read kernel release: %w", err)
	}
	if strings.TrimSpace(string(release)) == "" {
		return ProbeSnapshot{}, fmt.Errorf("kernel release is empty")
	}
	bpffs := p.checkBPFFS()
	btf := p.checkBTF()
	cri := p.checkCRI(ctx, req.RuntimeURI)
	return ProbeSnapshot{
		KernelRelease: strings.TrimSpace(string(release)), Architecture: runtime.GOARCH,
		HasBTF: btf.Supported, BPFFSMounted: bpffs.Supported,
		Checks:  []ProbeCheck{bpffs, btf, cri},
		Runtime: RuntimeInfo{Name: "containerd", Endpoint: req.RuntimeURI},
		Overlay: OverlayInfo{Type: req.Overlay},
	}, nil
}

func (p *LinuxProbe) checkBPFFS() ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "BPFFS_NOT_MOUNTED"}
	info, err := os.Stat(p.path("/sys/fs/bpf"))
	if err != nil || !info.IsDir() {
		result.Detail = "bpffs mount directory is unavailable"
		return ProbeCheck{Name: "bpffs", ProbeResult: result}
	}
	data, err := os.ReadFile(p.path("/proc/mounts"))
	if err != nil {
		result.ReasonCode = "BPFFS_MOUNT_INFO_UNAVAILABLE"
		result.Detail = err.Error()
		return ProbeCheck{Name: "bpffs", ProbeResult: result}
	}
	for _, line := range strings.Split(string(data), "\n") {
		fields := strings.Fields(line)
		if len(fields) >= 3 && fields[1] == "/sys/fs/bpf" && fields[2] == "bpf" {
			result.Supported = true
			result.ReasonCode = ""
			return ProbeCheck{Name: "bpffs", ProbeResult: result}
		}
	}
	result.Detail = "bpffs is not mounted at /sys/fs/bpf"
	return ProbeCheck{Name: "bpffs", ProbeResult: result}
}

func (p *LinuxProbe) checkBTF() ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "BTF_MISSING"}
	info, err := os.Stat(p.path("/sys/kernel/btf/vmlinux"))
	if err == nil && !info.IsDir() {
		result.Supported = true
		result.ReasonCode = ""
	} else if err != nil {
		result.Detail = err.Error()
	} else {
		result.Detail = "vmlinux BTF path is a directory"
	}
	return ProbeCheck{Name: "btf", ProbeResult: result}
}

func (p *LinuxProbe) checkCRI(ctx context.Context, uri string) ProbeCheck {
	result := ProbeResult{Required: true, ReasonCode: "CRI_SOCKET_UNAVAILABLE"}
	path, err := unixSocketPath(uri)
	if err != nil {
		result.ReasonCode = "CRI_URI_INVALID"
		result.Detail = err.Error()
		return ProbeCheck{Name: "cri", ProbeResult: result}
	}
	conn, err := p.dialUnix(ctx, p.path(path))
	if err != nil {
		result.Detail = err.Error()
		return ProbeCheck{Name: "cri", ProbeResult: result}
	}
	_ = conn.Close()
	result.Supported = true
	result.ReasonCode = ""
	return ProbeCheck{Name: "cri", ProbeResult: result}
}

func (p *LinuxProbe) path(path string) string {
	return filepath.Join(p.root, strings.TrimPrefix(path, string(filepath.Separator)))
}

func unixSocketPath(uri string) (string, error) {
	const prefix = "unix://"
	if !strings.HasPrefix(uri, prefix) {
		return "", fmt.Errorf("runtime endpoint must use unix://")
	}
	path := strings.TrimPrefix(uri, prefix)
	if !filepath.IsAbs(path) {
		return "", fmt.Errorf("runtime socket path must be absolute")
	}
	return path, nil
}
