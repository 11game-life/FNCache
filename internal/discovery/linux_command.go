package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"strings"
)

type CommandRunner func(context.Context, string, ...string) ([]byte, error)

func defaultCommandRunner(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

var requiredBPFHelpers = []string{
	"bpf_map_lookup_elem", "bpf_map_update_elem", "bpf_get_hash_recalc",
	"bpf_skb_adjust_room", "bpf_skb_store_bytes", "bpf_spin_lock", "bpf_spin_unlock",
}

func hasHelper(output []byte, helper string) bool {
	for _, field := range strings.Fields(string(output)) {
		if strings.Trim(field, "[](){}:,\"'") == helper {
			return true
		}
	}
	return false
}

func hasDirectAction(output []byte) bool {
	text := strings.ToLower(string(output))
	if strings.Contains(text, "direct_action") || strings.Contains(text, "direct-action") {
		return true
	}
	return strings.Contains(text, "config_net_cls_act is set to y") &&
		strings.Contains(text, "ebpf program_type sched_cls is available")
}

func validRouteOutput(output []byte) bool {
	var routes []json.RawMessage
	return json.Unmarshal(bytes.TrimSpace(output), &routes) == nil && len(routes) > 0
}

func hasReservedTOSConflict(output []byte) bool {
	for _, line := range strings.Split(strings.ToLower(string(output)), "\n") {
		if isOncacheMarkerRule(line) {
			continue
		}
		if !strings.Contains(line, "set-tos") && !strings.Contains(line, "set-dscp") && !strings.Contains(line, "set-xmark") {
			continue
		}
		if strings.Contains(line, "0x04") || strings.Contains(line, "0x08") {
			return true
		}
	}
	return false
}

func isOncacheMarkerRule(line string) bool {
	normalized := strings.Join(strings.Fields(line), " ")
	return strings.HasPrefix(normalized, "-a oncache ") &&
		strings.Contains(normalized, "-m comment --comment \"oncache:") &&
		strings.Contains(normalized, "--tos 0x04/0x04") &&
		strings.Contains(normalized, "--set-tos 0x08/0x08")
}

func hasFixedTCConflict(output []byte) bool {
	text := strings.ToLower(string(output))
	for _, marker := range []string{
		"\"pref\":1000", "\"pref\": 1000", "pref 1000",
		"\"handle\":256", "\"handle\": 256", "handle 0x100",
		"\"handle\":257", "\"handle\": 257", "handle 0x101",
		"\"handle\":512", "\"handle\": 512", "handle 0x200",
		"\"handle\":513", "\"handle\": 513", "handle 0x201",
	} {
		if strings.Contains(text, marker) {
			return true
		}
	}
	return false
}

func hasPinnedObject(output []byte, pinRoot string) bool {
	return pinRoot != "" && strings.Contains(string(output), pinRoot)
}
