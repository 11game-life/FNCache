//go:build linux && integration

package integration_test

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/controlplane"
	"github.com/cat-cc-Lcos/FNCache/internal/datapath"
	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

func TestM2NetnsTCEnsureRestartAndConflict(t *testing.T) {
	requireIntegrationEnvironment(t)
	elf := os.Getenv("ONCACHE_BPF_ELF")
	if elf == "" {
		t.Fatal("ONCACHE_BPF_ELF is required")
	}
	if _, err := os.Stat(elf); err != nil {
		t.Fatalf("BPF ELF is unavailable: %v", err)
	}

	lab := newNetNSLab(t)
	pinRoot := filepath.Join("/sys/fs/bpf/oncache", fmt.Sprintf("m2-integration-%d", os.Getpid()))
	if _, err := os.Stat(pinRoot); err == nil {
		t.Fatalf("integration pin root already exists: %s", pinRoot)
	}
	defer os.RemoveAll(pinRoot)

	loaded, actual := loadPinnedCollection(t, elf, pinRoot)
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = loaded.Close()
		}
	})

	backend, err := datapath.NewLinuxTCBackend(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	tc, err := datapath.NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	base, err := controlplane.NewBaseEnsurer(tc)
	if err != nil {
		t.Fatal(err)
	}
	var firstCount int
	if err := lab.withNetNS(func(ctx context.Context) error {
		underlay, err := linkIdentity(lab.underlay, lab.netnsInode)
		if err != nil {
			return err
		}
		desired := baseDesired(underlay)
		changed, err := base.EnsureBase(ctx, desired, actual)
		if err != nil || !changed {
			return fmt.Errorf("first base ensure: changed=%v err=%w", changed, err)
		}
		scanner, err := datapath.NewTCScanner(tc)
		if err != nil {
			return err
		}
		observed, err := scanner.Scan(ctx, []resolver.LinkIdentity{underlay})
		if err != nil {
			return err
		}
		firstCount = len(observed.Attachments)
		if firstCount != 2 {
			return fmt.Errorf("expected two base filters, got %d", firstCount)
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	pinScanner, err := datapath.NewPinScanner(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	actualState, err := pinScanner.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	backend, err = datapath.NewLinuxTCBackend(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	tc, err = datapath.NewTCManager(backend)
	if err != nil {
		t.Fatal(err)
	}
	base, err = controlplane.NewBaseEnsurer(tc)
	if err != nil {
		t.Fatal(err)
	}
	if err := lab.withNetNS(func(ctx context.Context) error {
		underlay, err := linkIdentity(lab.underlay, lab.netnsInode)
		if err != nil {
			return err
		}
		scanner, err := datapath.NewTCScanner(tc)
		if err != nil {
			return err
		}
		before, err := scanner.Scan(ctx, []resolver.LinkIdentity{underlay})
		if err != nil {
			return err
		}
		actualState.Attachments = before.Attachments
		changed, err := base.EnsureBase(ctx, baseDesired(underlay), actualState)
		if err != nil || changed {
			return fmt.Errorf("restart base ensure was not idempotent: changed=%v err=%w", changed, err)
		}
		after, err := scanner.Scan(ctx, []resolver.LinkIdentity{underlay})
		if err != nil {
			return err
		}
		if len(after.Attachments) != firstCount {
			return fmt.Errorf("restart changed attachment count: before=%d after=%d", firstCount, len(after.Attachments))
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}

	if err := lab.withNetNS(func(ctx context.Context) error {
		link, err := linkIdentity(lab.vxlan, lab.netnsInode)
		if err != nil {
			return err
		}
		backend, err := datapath.NewLinuxTCBackend(pinRoot)
		if err != nil {
			return err
		}
		tc, err := datapath.NewTCManager(backend)
		if err != nil {
			return err
		}
		if _, err := tc.EnsureClsact(ctx, link); err != nil {
			return err
		}
		program, err := ebpf.LoadPinnedProgram(filepath.Join(pinRoot, "programs", "tc_init_e"), nil)
		if err != nil {
			return err
		}
		filter := &netlink.BpfFilter{
			FilterAttrs: netlink.FilterAttrs{LinkIndex: link.IfIndex, Parent: netlink.HANDLE_MIN_EGRESS, Priority: 1000, Handle: 0x900, Protocol: unix.ETH_P_ALL},
			Fd:          program.FD(), Name: "external-m2", DirectAction: true,
		}
		if err := netlink.FilterAdd(filter); err != nil {
			_ = program.Close()
			return err
		}
		_ = program.Close()
		base, err := controlplane.NewBaseEnsurer(tc)
		if err != nil {
			return err
		}
		_, err = base.EnsureBase(ctx, baseDesired(link), actualState)
		var classified *reconcile.ClassifiedError
		if !errors.As(err, &classified) || classified.Class() != reconcile.ErrorConflict {
			return fmt.Errorf("expected external TC conflict, got %v", err)
		}
		filters, err := tc.ListFilters(ctx, link)
		if err != nil {
			return err
		}
		for _, filter := range filters {
			if filter.Handle == 0x900 {
				return nil
			}
		}
		return fmt.Errorf("external TC filter was not preserved")
	}); err != nil {
		t.Fatal(err)
	}
	if err := loaded.Close(); err != nil {
		t.Fatal(err)
	}
	closed = true
}

type netNSLab struct {
	name, hostLink, underlay, vxlan, path string
	netnsInode                            uint64
}

func newNetNSLab(t *testing.T) *netNSLab {
	t.Helper()
	suffix := strconv.Itoa(os.Getpid())
	lab := &netNSLab{name: "ocm2-" + suffix, hostLink: "ocm2h-" + suffix, underlay: "ocm2u-" + suffix, vxlan: "flannel.1"}
	if err := run("ip", "netns", "add", lab.name); err != nil {
		t.Fatal(err)
	}
	lab.path = filepath.Join("/var/run/netns", lab.name)
	stat := unix.Stat_t{}
	if err := unix.Stat(lab.path, &stat); err != nil {
		t.Fatalf("stat netns: %v", err)
	}
	lab.netnsInode = uint64(stat.Ino)
	t.Cleanup(func() {
		_ = run("ip", "netns", "del", lab.name)
		_ = run("ip", "link", "del", lab.hostLink)
	})
	peer := "ocm2p-" + suffix
	if err := run("ip", "link", "add", lab.hostLink, "type", "veth", "peer", "name", peer); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", peer, "netns", lab.name); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "addr", "add", "192.0.2.1/24", "dev", lab.hostLink); err != nil {
		t.Fatal(err)
	}
	if err := run("ip", "link", "set", lab.hostLink, "up"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", "lo", "up"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", "dev", peer, "name", lab.underlay); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "addr", "add", "192.0.2.2/24", "dev", lab.underlay); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", lab.underlay, "up"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "add", lab.vxlan, "type", "vxlan", "id", "1", "dev", lab.underlay, "local", "192.0.2.2", "dstport", "8472"); err != nil {
		t.Fatal(err)
	}
	if err := runNetNS(lab.name, "ip", "link", "set", lab.vxlan, "up"); err != nil {
		t.Fatal(err)
	}
	return lab
}

func (l *netNSLab) withNetNS(fn func(context.Context) error) error {
	manager := datapath.NewNetNSManager()
	return manager.WithNetNS(context.Background(), datapath.NetNSRef{Path: l.path, Inode: l.netnsInode}, fn)
}

func loadPinnedCollection(t *testing.T, elf, pinRoot string) (*datapath.LoadedCollection, reconcile.ActualState) {
	t.Helper()
	file, err := os.Open(elf)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	manager, err := datapath.NewManager(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := manager.LoadCollection(file, datapath.V1Schema())
	if err != nil {
		t.Fatal(err)
	}
	loaded, err := manager.LoadAndPin(spec, datapath.V1Schema())
	if err != nil {
		t.Fatal(err)
	}
	control, err := ebpf.LoadPinnedMap(filepath.Join(pinRoot, "maps", "control_map"), nil)
	if err != nil {
		t.Fatal(err)
	}
	value := datapath.ControlV1{ABIVersion: 1, HeartbeatTimeoutNS: 500}
	if err := control.Update(uint32(0), &value, ebpf.UpdateAny); err != nil {
		control.Close()
		t.Fatal(err)
	}
	if err := control.Close(); err != nil {
		t.Fatal(err)
	}
	scanner, err := datapath.NewPinScanner(pinRoot)
	if err != nil {
		t.Fatal(err)
	}
	actual, err := scanner.Scan(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	return loaded, actual
}

func baseDesired(link resolver.LinkIdentity) reconcile.DesiredState {
	return reconcile.DesiredState{Enabled: true, Flannel: reconcile.FlannelState{UnderlayLink: link, UnderlayIPv4: netip.MustParseAddr("192.0.2.2")}}
}

func linkIdentity(name string, netnsInode uint64) (resolver.LinkIdentity, error) {
	link, err := netlink.LinkByName(name)
	if err != nil {
		return resolver.LinkIdentity{}, err
	}
	attrs := link.Attrs()
	if attrs == nil || attrs.Index <= 0 {
		return resolver.LinkIdentity{}, fmt.Errorf("link identity is incomplete: %s", name)
	}
	return resolver.LinkIdentity{NetNSInode: netnsInode, IfIndex: attrs.Index, IfName: attrs.Name, MAC: append([]byte(nil), attrs.HardwareAddr...)}, nil
}

func requireIntegrationEnvironment(t *testing.T) {
	t.Helper()
	if os.Getenv("ONCACHE_M2_INTEGRATION") != "1" {
		t.Skip("set ONCACHE_M2_INTEGRATION=1 to run privileged integration tests")
	}
	if os.Geteuid() != 0 {
		t.Fatal("M2 integration tests require root")
	}
	if _, err := exec.LookPath("ip"); err != nil {
		t.Fatal(err)
	}
	if _, err := exec.LookPath("tc"); err != nil {
		t.Fatal(err)
	}
	if err := exec.Command("systemd-detect-virt", "--vm").Run(); err != nil {
		t.Fatal("refusing privileged integration test outside a verified VM")
	}
}

func run(name string, args ...string) error {
	_, err := command(name, args...)
	return err
}

func runNetNS(namespace string, args ...string) error {
	_, err := runNetNSOutput(namespace, args...)
	return err
}

func runNetNSOutput(namespace string, args ...string) ([]byte, error) {
	commandArgs := append([]string{"netns", "exec", namespace}, args...)
	return command("ip", commandArgs...)
}

func command(name string, args ...string) ([]byte, error) {
	output, err := exec.Command(name, args...).CombinedOutput()
	if err != nil {
		return output, fmt.Errorf("%s %s: %w: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(output)))
	}
	return output, nil
}
