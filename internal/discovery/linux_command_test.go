package discovery

import "testing"

func TestLinuxCommandParsers(t *testing.T) {
	output := []byte("bpf_map_lookup_elem bpf_spin_unlock direct_action")
	if !hasHelper(output, "bpf_map_lookup_elem") || hasHelper(output, "bpf_map_update_elem") || !hasDirectAction(output) {
		t.Fatal("helper or direct-action parser returned an unexpected result")
	}
	if !validRouteOutput([]byte(`[{"dst":"default"}]`)) || validRouteOutput([]byte("[]")) {
		t.Fatal("route parser returned an unexpected result")
	}
}

func TestLinuxConflictParsers(t *testing.T) {
	if !hasReservedTOSConflict([]byte("-A ONCACHE -m tos --set-tos 0x08")) {
		t.Fatal("TOS conflict was not detected")
	}
	if !hasFixedTCConflict([]byte(`[{"pref":1000,"handle":256}]`)) {
		t.Fatal("TC conflict was not detected")
	}
	if !hasPinnedObject([]byte(`{"pinned":"/sys/fs/bpf/oncache/v1/maps/control_map"}`), "/sys/fs/bpf/oncache/v1") {
		t.Fatal("pin conflict was not detected")
	}
	if hasReservedTOSConflict([]byte("-A ONCACHE -j ACCEPT")) || hasFixedTCConflict([]byte("[]")) {
		t.Fatal("false conflict detected")
	}
}
