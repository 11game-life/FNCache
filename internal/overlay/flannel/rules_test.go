package flannel

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

func TestRuleScannerFindsMarkerRule(t *testing.T) {
	var command string
	scanner := NewRuleScanner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		command = name + " " + strings.Join(args, " ")
		return []byte(`-A ONCACHE -m comment --comment "oncache:install-a" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`), nil
	})
	state, err := scanner.Scan(context.Background(), MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"})
	if err != nil || !state.Present || state.Identity != "ONCACHE/oncache:install-a" || state.Fingerprint == "" || command != "iptables-nft -t mangle -S" {
		t.Fatalf("unexpected marker state: state=%+v err=%v command=%q", state, err, command)
	}
}

func TestMarkerRuleManagerCreatesAndReusesRule(t *testing.T) {
	spec := MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}
	output := ""
	var commands []string
	manager := NewMarkerRuleManager(func(_ context.Context, name string, args ...string) ([]byte, error) {
		commands = append(commands, name+" "+strings.Join(args, " "))
		if strings.Contains(strings.Join(args, " "), " -S") {
			return []byte(output), nil
		}
		switch {
		case strings.Contains(strings.Join(args, " "), " -N "):
			output = "-N ONCACHE\n"
		case strings.Contains(strings.Join(args, " "), " -A "):
			output += markerRuleLine(spec) + "\n"
		}
		return nil, nil
	})
	state, changed, err := manager.Ensure(context.Background(), spec)
	if err != nil || !changed || !state.Present || len(commands) != 4 {
		t.Fatalf("unexpected create result: state=%+v changed=%v err=%v commands=%v", state, changed, err, commands)
	}
	_, changed, err = manager.Ensure(context.Background(), spec)
	if err != nil || changed {
		t.Fatalf("equivalent rule was not idempotent: changed=%v err=%v", changed, err)
	}
}

func TestMarkerRuleManagerReplacesOwnedDrift(t *testing.T) {
	spec := MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}
	output := "-N ONCACHE\n-A ONCACHE -m comment --comment \"oncache:install-a\" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x01/0x01\n"
	replaced := false
	manager := NewMarkerRuleManager(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, " -R ") {
			replaced = true
			output = "-N ONCACHE\n" + markerRuleLine(spec) + "\n"
		}
		return []byte(output), nil
	})
	state, changed, err := manager.Ensure(context.Background(), spec)
	if err != nil || !changed || !replaced || state.Fingerprint != ruleFingerprint(markerRuleLine(spec)) {
		t.Fatalf("owned drift was not replaced: state=%+v changed=%v replaced=%v err=%v", state, changed, replaced, err)
	}
}

func TestMarkerRuleManagerRejectsForeignOrDuplicateIdentity(t *testing.T) {
	spec := MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}
	for name, output := range map[string]string{
		"foreign chain": "-A OTHER -m comment --comment \"oncache:install-a\" -j ACCEPT\n",
		"duplicate":     "-A ONCACHE -m comment --comment \"oncache:install-a\" -j ACCEPT\n-A ONCACHE -m comment --comment \"oncache:install-a\" -j ACCEPT\n",
	} {
		t.Run(name, func(t *testing.T) {
			manager := NewMarkerRuleManager(func(context.Context, string, ...string) ([]byte, error) { return []byte(output), nil })
			if _, _, err := manager.Ensure(context.Background(), spec); err == nil {
				t.Fatal("marker conflict was accepted")
			}
		})
	}
}

func TestMarkerRuleManagerRemoveRechecksFingerprint(t *testing.T) {
	spec := MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}
	output := markerRuleLine(spec) + "\n"
	deleted := false
	manager := NewMarkerRuleManager(func(_ context.Context, _ string, args ...string) ([]byte, error) {
		if strings.Contains(strings.Join(args, " "), " -D ") {
			deleted = true
		}
		return []byte(output), nil
	})
	err := manager.Remove(context.Background(), reconcile.OwnedRule{Identity: "ONCACHE/oncache:install-a", Fingerprint: "wrong"})
	if err == nil || deleted {
		t.Fatalf("foreign replacement was removed: err=%v deleted=%v", err, deleted)
	}
}

func TestRuleScannerReportsMissingRule(t *testing.T) {
	scanner := NewRuleScanner(func(context.Context, string, ...string) ([]byte, error) { return []byte("-A OTHER -j ACCEPT\n"), nil })
	state, err := scanner.Scan(context.Background(), MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"})
	if err != nil || state.Present || state.Identity != "ONCACHE/oncache:install-a" || state.Fingerprint != "" {
		t.Fatalf("unexpected missing marker state: state=%+v err=%v", state, err)
	}
}

func TestRuleScannerRejectsWrongChainAndDuplicate(t *testing.T) {
	for name, output := range map[string]string{
		"wrong chain": "-A OTHER --comment oncache:install-a -j ACCEPT\n",
		"duplicate":   "-A ONCACHE --comment oncache:install-a -j ACCEPT\n-A ONCACHE --comment oncache:install-a -j ACCEPT\n",
	} {
		scanner := NewRuleScanner(func(context.Context, string, ...string) ([]byte, error) { return []byte(output), nil })
		if _, err := scanner.Scan(context.Background(), MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}); err == nil {
			t.Fatalf("%s rule was accepted", name)
		}
	}
}

func TestRuleScannerPropagatesCommandErrorAndCancellation(t *testing.T) {
	want := errors.New("iptables failed")
	scanner := NewRuleScanner(func(context.Context, string, ...string) ([]byte, error) { return nil, want })
	if _, err := scanner.Scan(context.Background(), MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}); !errors.Is(err, want) {
		t.Fatalf("expected command error: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := scanner.Scan(ctx, MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"}); !errors.Is(err, context.Canceled) {
		t.Fatalf("expected cancellation: %v", err)
	}
}

func TestRuleFingerprintNormalizesWhitespace(t *testing.T) {
	if ruleFingerprint("-A ONCACHE   -j ACCEPT") != ruleFingerprint("-A ONCACHE -j ACCEPT") {
		t.Fatal("equivalent rule whitespace produced different fingerprints")
	}
}
