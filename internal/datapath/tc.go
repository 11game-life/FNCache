package datapath

import (
	"context"
	"fmt"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type TCHook string

const (
	HookIngress     TCHook = "ingress"
	HookEgress      TCHook = "egress"
	FixedTCPriority        = uint16(1000)
)

type TCFilterSpec struct {
	Link         resolver.LinkIdentity
	Hook         TCHook
	Program      string
	ProgramID    uint32
	Priority     uint16
	Handle       uint32
	DirectAction bool
}

type TCFilterState struct {
	Link         resolver.LinkIdentity
	Hook         TCHook
	Program      string
	ProgramID    uint32
	Priority     uint16
	Handle       uint32
	DirectAction bool
}

type TCQdiscState struct {
	Link             resolver.LinkIdentity
	Exists           bool
	CreatedByOncache bool
}

type TCBackend interface {
	EnsureClsact(context.Context, resolver.LinkIdentity) (TCQdiscState, error)
	ListFilters(context.Context, resolver.LinkIdentity) ([]TCFilterState, error)
	AttachFilter(context.Context, TCFilterSpec) (TCFilterState, error)
	RemoveFilter(context.Context, TCFilterSpec) error
}

type TCManager struct {
	backend TCBackend
}

type fixedAttachment struct {
	hook   TCHook
	handle uint32
}

var fixedAttachments = map[string]fixedAttachment{
	"tc_init_e":  {hook: HookEgress, handle: 0x100},
	"tc_restore": {hook: HookIngress, handle: 0x101},
	"tc_masq":    {hook: HookIngress, handle: 0x200},
	"tc_init_in": {hook: HookIngress, handle: 0x201},
}

func NewTCManager(backend TCBackend) (*TCManager, error) {
	if backend == nil {
		return nil, fmt.Errorf("TC backend is required")
	}
	return &TCManager{backend: backend}, nil
}

func NewFixedFilter(link resolver.LinkIdentity, program string, programID uint32, directAction bool) (TCFilterSpec, error) {
	fixed, ok := fixedAttachments[program]
	if !ok {
		return TCFilterSpec{}, fmt.Errorf("unsupported ONCache TC program: %s", program)
	}
	spec := TCFilterSpec{
		Link:         link,
		Hook:         fixed.hook,
		Program:      program,
		ProgramID:    programID,
		Priority:     FixedTCPriority,
		Handle:       fixed.handle,
		DirectAction: directAction,
	}
	if err := validateFilterSpec(spec); err != nil {
		return TCFilterSpec{}, err
	}
	return spec, nil
}

func (m *TCManager) EnsureClsact(ctx context.Context, link resolver.LinkIdentity) (TCQdiscState, error) {
	if err := validateLink(link); err != nil {
		return TCQdiscState{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCQdiscState{}, err
	}
	return m.backend.EnsureClsact(ctx, link)
}

func (m *TCManager) EnsureFilter(ctx context.Context, spec TCFilterSpec) (TCFilterState, error) {
	if err := validateFilterSpec(spec); err != nil {
		return TCFilterState{}, err
	}
	if err := ctx.Err(); err != nil {
		return TCFilterState{}, err
	}
	qdisc, err := m.EnsureClsact(ctx, spec.Link)
	if err != nil {
		return TCFilterState{}, err
	}
	if !qdisc.Exists || !sameLink(qdisc.Link, spec.Link) {
		return TCFilterState{}, safetyError("TC backend did not establish the requested clsact")
	}
	filters, err := m.backend.ListFilters(ctx, spec.Link)
	if err != nil {
		return TCFilterState{}, fmt.Errorf("list TC filters: %w", err)
	}
	for _, current := range filters {
		if current.Hook != spec.Hook || current.Priority != spec.Priority {
			continue
		}
		if current.Handle == spec.Handle {
			if sameFilter(current, spec) {
				return current, nil
			}
			return TCFilterState{}, foreignConflict("fixed TC handle is occupied by another filter")
		}
		if !isFixedAttachment(current) {
			return TCFilterState{}, foreignConflict("fixed TC priority is occupied by another filter")
		}
	}
	state, err := m.backend.AttachFilter(ctx, spec)
	if err != nil {
		return TCFilterState{}, fmt.Errorf("attach TC filter: %w", err)
	}
	if !sameFilter(state, spec) {
		return TCFilterState{}, safetyError("TC backend returned an unexpected filter identity")
	}
	return state, nil
}

func (m *TCManager) RemoveFilter(ctx context.Context, spec TCFilterSpec) error {
	if err := validateFilterSpec(spec); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	filters, err := m.backend.ListFilters(ctx, spec.Link)
	if err != nil {
		return fmt.Errorf("list TC filters: %w", err)
	}
	for _, current := range filters {
		if current.Hook != spec.Hook || current.Priority != spec.Priority || current.Handle != spec.Handle {
			continue
		}
		if !sameFilter(current, spec) {
			return foreignConflict("refusing to remove a filter with a different program identity")
		}
		return m.backend.RemoveFilter(ctx, spec)
	}
	return nil
}

func (m *TCManager) ListFilters(ctx context.Context, link resolver.LinkIdentity) ([]TCFilterState, error) {
	if err := validateLink(link); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return m.backend.ListFilters(ctx, link)
}

func validateFilterSpec(spec TCFilterSpec) error {
	if err := validateLink(spec.Link); err != nil {
		return err
	}
	if spec.ProgramID == 0 {
		return fmt.Errorf("TC program ID is required")
	}
	fixed, ok := fixedAttachments[spec.Program]
	if !ok {
		return fmt.Errorf("unsupported ONCache TC program: %s", spec.Program)
	}
	if spec.Hook != fixed.hook || spec.Priority != FixedTCPriority || spec.Handle != fixed.handle {
		return fmt.Errorf("invalid fixed TC identity for program %s", spec.Program)
	}
	return nil
}

func validateLink(link resolver.LinkIdentity) error {
	if link.IfIndex <= 0 {
		return fmt.Errorf("TC link ifindex is required")
	}
	return nil
}

func sameFilter(current TCFilterState, expected TCFilterSpec) bool {
	return sameLink(current.Link, expected.Link) && current.Hook == expected.Hook &&
		current.ProgramID == expected.ProgramID && current.Priority == expected.Priority &&
		current.Handle == expected.Handle && current.DirectAction == expected.DirectAction
}

func isFixedAttachment(filter TCFilterState) bool {
	fixed, ok := fixedAttachments[filter.Program]
	return ok && fixed.hook == filter.Hook && fixed.handle == filter.Handle
}

func sameLink(current, expected resolver.LinkIdentity) bool {
	return current.NetNSInode == expected.NetNSInode && current.IfIndex == expected.IfIndex
}

func foreignConflict(message string) error {
	return reconcile.NewClassifiedError(reconcile.ErrorConflict, reconcile.ReasonTCForeignConflict, 0, fmt.Errorf("%s", message))
}

func safetyError(message string) error {
	return reconcile.NewClassifiedError(reconcile.ErrorSafetyViolation, "TC_BACKEND_IDENTITY_MISMATCH", 0, fmt.Errorf("%s", message))
}
