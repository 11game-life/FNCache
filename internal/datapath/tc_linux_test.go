//go:build linux

package datapath

import (
	"context"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/resolver"
)

type fakeTCNetlinkAPI struct {
	qdiscs                               []kernelQdisc
	filters                              []kernelFilter
	qdiscAdds, filterAdds, filterDeletes int
}

func (f *fakeTCNetlinkAPI) listQdiscs(int) ([]kernelQdisc, error) {
	return append([]kernelQdisc(nil), f.qdiscs...), nil
}
func (f *fakeTCNetlinkAPI) addQdisc(qdisc kernelQdisc) error {
	f.qdiscAdds++
	f.qdiscs = append(f.qdiscs, qdisc)
	return nil
}
func (f *fakeTCNetlinkAPI) listFilters(_ int, parent uint32) ([]kernelFilter, error) {
	result := make([]kernelFilter, 0)
	for _, filter := range f.filters {
		if filter.Parent == parent {
			result = append(result, filter)
		}
	}
	return result, nil
}
func (f *fakeTCNetlinkAPI) addFilter(filter kernelFilter) error {
	f.filters = append(f.filters, filter)
	return nil
}
func (f *fakeTCNetlinkAPI) deleteFilter(filter kernelFilter) error {
	f.filterDeletes++
	for i, current := range f.filters {
		if current.Parent == filter.Parent && current.Priority == filter.Priority && current.Handle == filter.Handle {
			f.filters = append(f.filters[:i], f.filters[i+1:]...)
			break
		}
	}
	return nil
}

type fakeTCProgram struct {
	fd     int
	id     uint32
	closed bool
}

func (p *fakeTCProgram) FD() int                    { return p.fd }
func (p *fakeTCProgram) ProgramID() (uint32, error) { return p.id, nil }
func (p *fakeTCProgram) Close() error               { p.closed = true; return nil }

type fakeTCProgramLoader struct {
	program tcProgram
	path    string
}

func (l *fakeTCProgramLoader) Load(path string) (tcProgram, error) {
	l.path = path
	return l.program, nil
}

func linuxTestLink() resolver.LinkIdentity { return resolver.LinkIdentity{IfIndex: 4, NetNSInode: 9} }

func TestLinuxTCBackendCreatesAndReusesClsact(t *testing.T) {
	api := &fakeTCNetlinkAPI{}
	backend, err := newLinuxTCBackend(t.TempDir(), api, &fakeTCProgramLoader{})
	if err != nil {
		t.Fatal(err)
	}
	link := linuxTestLink()
	first, err := backend.EnsureClsact(context.Background(), link)
	if err != nil || !first.CreatedByOncache || api.qdiscAdds != 1 {
		t.Fatalf("unexpected first clsact result: state=%+v err=%v api=%+v", first, err, api)
	}
	second, err := backend.EnsureClsact(context.Background(), link)
	if err != nil || second.CreatedByOncache || api.qdiscAdds != 1 {
		t.Fatalf("clsact was not reused: state=%+v err=%v api=%+v", second, err, api)
	}
}

func TestLinuxTCBackendAttachesPinnedProgram(t *testing.T) {
	program := &fakeTCProgram{fd: 17, id: 10}
	loader := &fakeTCProgramLoader{program: program}
	api := &fakeTCNetlinkAPI{}
	backend, err := newLinuxTCBackend("/sys/fs/bpf/oncache/v1", api, loader)
	if err != nil {
		t.Fatal(err)
	}
	spec, err := NewFixedFilter(linuxTestLink(), "tc_init_e", 10, true)
	if err != nil {
		t.Fatal(err)
	}
	state, err := backend.AttachFilter(context.Background(), spec)
	if err != nil || state.ProgramID != 10 || len(api.filters) != 1 || api.filters[0].Parent != 0xfffffff3 || api.filters[0].FD != 17 || !program.closed {
		t.Fatalf("unexpected attach: state=%+v err=%v api=%+v closed=%v", state, err, api, program.closed)
	}
	if loader.path != "/sys/fs/bpf/oncache/v1/programs/tc_init_e" {
		t.Fatalf("unexpected pinned program path: %s", loader.path)
	}
	program.id = 11
	if _, err := backend.AttachFilter(context.Background(), spec); err == nil || len(api.filters) != 1 || !program.closed {
		t.Fatalf("mismatched program was attached: err=%v api=%+v closed=%v", err, api, program.closed)
	}
}

func TestLinuxTCBackendListsBothHooksAndDeletesByIdentity(t *testing.T) {
	link := linuxTestLink()
	api := &fakeTCNetlinkAPI{filters: []kernelFilter{
		{LinkIndex: link.IfIndex, Parent: 0xfffffff2, Priority: FixedTCPriority, Handle: 0x201, Kind: "bpf", Program: "tc_init_in", ProgramID: 10, DirectAction: true},
	}}
	backend, _ := newLinuxTCBackend(t.TempDir(), api, &fakeTCProgramLoader{})
	filters, err := backend.ListFilters(context.Background(), link)
	if err != nil || len(filters) != 1 || filters[0].Hook != HookIngress || filters[0].ProgramID != 10 {
		t.Fatalf("unexpected filter listing: filters=%+v err=%v", filters, err)
	}
	spec, _ := NewFixedFilter(link, "tc_init_in", 10, true)
	if err := backend.RemoveFilter(context.Background(), spec); err != nil || api.filterDeletes != 1 || len(api.filters) != 0 {
		t.Fatalf("filter was not deleted: err=%v api=%+v", err, api)
	}
}
