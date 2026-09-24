//go:build linux

package datapath

import (
	"context"
	"fmt"
	"path/filepath"

	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
	"github.com/cilium/ebpf"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

type kernelQdisc struct {
	LinkIndex      int
	Handle, Parent uint32
	Kind           string
}
type kernelFilter struct {
	LinkIndex      int
	Parent, Handle uint32
	Priority       uint16
	Kind, Program  string
	ProgramID      uint32
	DirectAction   bool
	FD             int
}
type tcNetlinkAPI interface {
	listQdiscs(int) ([]kernelQdisc, error)
	addQdisc(kernelQdisc) error
	listFilters(int, uint32) ([]kernelFilter, error)
	addFilter(kernelFilter) error
	deleteFilter(kernelFilter) error
}
type tcProgram interface {
	FD() int
	ProgramID() (uint32, error)
	Close() error
}
type tcProgramLoader interface {
	Load(string) (tcProgram, error)
}
type linuxTCBackend struct {
	pinRoot string
	api     tcNetlinkAPI
	loader  tcProgramLoader
}

func NewLinuxTCBackend(pinRoot string) (TCBackend, error) {
	return newLinuxTCBackend(pinRoot, netlinkTCAPI{}, ebpfTCProgramLoader{})
}
func newLinuxTCBackend(pinRoot string, api tcNetlinkAPI, loader tcProgramLoader) (TCBackend, error) {
	if pinRoot == "" || !filepath.IsAbs(pinRoot) || filepath.Clean(pinRoot) == string(filepath.Separator) {
		return nil, fmt.Errorf("TC pin root must be a dedicated absolute directory")
	}
	if api == nil || loader == nil {
		return nil, fmt.Errorf("TC backend dependencies are required")
	}
	return &linuxTCBackend{pinRoot: filepath.Clean(pinRoot), api: api, loader: loader}, nil
}
func (b *linuxTCBackend) EnsureClsact(ctx context.Context, link resolver.LinkIdentity) (TCQdiscState, error) {
	if err := validateLink(link); err != nil {
		return TCQdiscState{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCQdiscState{}, err
	}
	qdiscs, err := b.api.listQdiscs(link.IfIndex)
	if err != nil {
		return TCQdiscState{}, fmt.Errorf("list qdiscs: %w", err)
	}
	if hasClsact(qdiscs) {
		return TCQdiscState{Link: link, Exists: true}, nil
	}
	qdisc := kernelQdisc{LinkIndex: link.IfIndex, Handle: netlink.MakeHandle(0xffff, 0), Parent: netlink.HANDLE_CLSACT, Kind: "clsact"}
	if err := b.api.addQdisc(qdisc); err != nil {
		qdiscs, listErr := b.api.listQdiscs(link.IfIndex)
		if listErr == nil && hasClsact(qdiscs) {
			return TCQdiscState{Link: link, Exists: true}, nil
		}
		return TCQdiscState{}, fmt.Errorf("add clsact: %w", err)
	}
	return TCQdiscState{Link: link, Exists: true, CreatedByOncache: true}, nil
}
func (b *linuxTCBackend) ListFilters(ctx context.Context, link resolver.LinkIdentity) ([]TCFilterState, error) {
	if err := validateLink(link); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	var result []TCFilterState
	for _, direction := range []struct {
		hook   TCHook
		parent uint32
	}{
		{hook: HookIngress, parent: netlink.HANDLE_MIN_INGRESS},
		{hook: HookEgress, parent: netlink.HANDLE_MIN_EGRESS},
	} {
		filters, err := b.api.listFilters(link.IfIndex, direction.parent)
		if err != nil {
			return nil, fmt.Errorf("list %s filters: %w", direction.hook, err)
		}
		for _, filter := range filters {
			result = append(result, TCFilterState{
				Link: link, Hook: direction.hook, Program: filter.Program, ProgramID: filter.ProgramID,
				Priority: filter.Priority, Handle: filter.Handle, DirectAction: filter.DirectAction,
			})
		}
	}
	return result, nil
}

func (b *linuxTCBackend) AttachFilter(ctx context.Context, spec TCFilterSpec) (TCFilterState, error) {
	if err := validateFilterSpec(spec); err != nil {
		return TCFilterState{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCFilterState{}, err
	}
	program, err := b.loader.Load(filepath.Join(b.pinRoot, "programs", spec.Program))
	if err != nil {
		return TCFilterState{}, fmt.Errorf("load pinned program %s: %w", spec.Program, err)
	}
	defer program.Close()
	programID, err := program.ProgramID()
	if err != nil {
		return TCFilterState{}, fmt.Errorf("inspect pinned program %s: %w", spec.Program, err)
	}
	if programID != spec.ProgramID {
		return TCFilterState{}, fmt.Errorf("pinned program %s ID mismatch: got %d want %d", spec.Program, programID, spec.ProgramID)
	}
	parent, err := parentForHook(spec.Hook)
	if err != nil {
		return TCFilterState{}, err
	}
	filter := kernelFilter{LinkIndex: spec.Link.IfIndex, Parent: parent, Priority: spec.Priority, Handle: spec.Handle, Kind: "bpf", Program: spec.Program, ProgramID: spec.ProgramID, DirectAction: spec.DirectAction, FD: program.FD()}
	if err := b.api.addFilter(filter); err != nil {
		return TCFilterState{}, fmt.Errorf("add BPF filter: %w", err)
	}
	return TCFilterState{Link: spec.Link, Hook: spec.Hook, Program: spec.Program, ProgramID: spec.ProgramID, Priority: spec.Priority, Handle: spec.Handle, DirectAction: spec.DirectAction}, nil
}

func (b *linuxTCBackend) RemoveFilter(ctx context.Context, spec TCFilterSpec) error {
	if err := validateFilterSpec(spec); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	parent, err := parentForHook(spec.Hook)
	if err != nil {
		return err
	}
	if err := b.api.deleteFilter(kernelFilter{LinkIndex: spec.Link.IfIndex, Parent: parent, Priority: spec.Priority, Handle: spec.Handle, Kind: "bpf", Program: spec.Program, ProgramID: spec.ProgramID, FD: -1}); err != nil {
		return fmt.Errorf("delete BPF filter: %w", err)
	}
	return nil
}

func hasClsact(qdiscs []kernelQdisc) bool {
	for _, qdisc := range qdiscs {
		if qdisc.Kind == "clsact" && qdisc.Parent == netlink.HANDLE_CLSACT {
			return true
		}
	}
	return false
}

func parentForHook(hook TCHook) (uint32, error) {
	switch hook {
	case HookIngress:
		return netlink.HANDLE_MIN_INGRESS, nil
	case HookEgress:
		return netlink.HANDLE_MIN_EGRESS, nil
	default:
		return 0, fmt.Errorf("unsupported TC hook: %s", hook)
	}
}

type netlinkTCAPI struct{}

func (netlinkTCAPI) listQdiscs(ifindex int) ([]kernelQdisc, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil, err
	}
	qdiscs, err := netlink.QdiscList(link)
	if err != nil {
		return nil, err
	}
	result := make([]kernelQdisc, 0, len(qdiscs))
	for _, qdisc := range qdiscs {
		attrs := qdisc.Attrs()
		if attrs != nil {
			result = append(result, kernelQdisc{LinkIndex: attrs.LinkIndex, Handle: attrs.Handle, Parent: attrs.Parent, Kind: qdisc.Type()})
		}
	}
	return result, nil
}

func (netlinkTCAPI) addQdisc(qdisc kernelQdisc) error {
	return netlink.QdiscAdd(&netlink.Clsact{QdiscAttrs: netlink.QdiscAttrs{LinkIndex: qdisc.LinkIndex, Handle: qdisc.Handle, Parent: qdisc.Parent}})
}

func (netlinkTCAPI) listFilters(ifindex int, parent uint32) ([]kernelFilter, error) {
	link, err := netlink.LinkByIndex(ifindex)
	if err != nil {
		return nil, err
	}
	filters, err := netlink.FilterList(link, parent)
	if err != nil {
		return nil, err
	}
	result := make([]kernelFilter, 0, len(filters))
	for _, filter := range filters {
		attrs := filter.Attrs()
		if attrs == nil {
			continue
		}
		state := kernelFilter{LinkIndex: attrs.LinkIndex, Parent: attrs.Parent, Priority: attrs.Priority, Handle: attrs.Handle, Kind: filter.Type()}
		if bpf, ok := filter.(*netlink.BpfFilter); ok {
			state.Program = bpf.Name
			if bpf.Id > 0 {
				state.ProgramID = uint32(bpf.Id)
			}
			state.DirectAction = bpf.DirectAction
		}
		result = append(result, state)
	}
	return result, nil
}

func (netlinkTCAPI) addFilter(filter kernelFilter) error {
	return netlink.FilterAdd(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: filter.LinkIndex, Parent: filter.Parent, Priority: filter.Priority, Handle: filter.Handle, Protocol: unix.ETH_P_ALL}, Fd: filter.FD, Name: filter.Program, DirectAction: filter.DirectAction})
}

func (netlinkTCAPI) deleteFilter(filter kernelFilter) error {
	return netlink.FilterDel(&netlink.BpfFilter{FilterAttrs: netlink.FilterAttrs{LinkIndex: filter.LinkIndex, Parent: filter.Parent, Priority: filter.Priority, Handle: filter.Handle, Protocol: unix.ETH_P_ALL}, Fd: -1})
}

type ebpfTCProgramLoader struct{}

func (ebpfTCProgramLoader) Load(path string) (tcProgram, error) {
	program, err := ebpf.LoadPinnedProgram(path, nil)
	if err != nil {
		return nil, err
	}
	return &ebpfTCProgram{program: program}, nil
}

type ebpfTCProgram struct {
	program *ebpf.Program
}

func (p *ebpfTCProgram) FD() int { return p.program.FD() }

func (p *ebpfTCProgram) ProgramID() (uint32, error) {
	info, err := p.program.Info()
	if err != nil {
		return 0, err
	}
	id, ok := info.ID()
	if !ok {
		return 0, fmt.Errorf("kernel did not provide a program ID")
	}
	return uint32(id), nil
}

func (p *ebpfTCProgram) Close() error { return p.program.Close() }
