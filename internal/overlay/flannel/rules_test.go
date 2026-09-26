package flannel

import (
	"context"
	"errors"
	"strings"
	"testing"
)

func TestRuleScannerFindsMarkerRule(t *testing.T) {
	var command string
	scanner := NewRuleScanner(func(_ context.Context, name string, args ...string) ([]byte, error) {
		command = name + " " + strings.Join(args, " ")
		return []byte(`-A ONCACHE -m comment --comment "oncache:install-a" -m conntrack --ctstate ESTABLISHED -m tos --tos 0x04/0x04 -j TOS --set-tos 0x08/0x08`), nil
	})
	state, err := scanner.Scan(context.Background(), MarkerRuleSpec{Chain: "ONCACHE", Comment: "oncache:install-a"})
	if err != nil || !state.Present || state.Identity != "ONCACHE/oncache:install-a" || state.Fingerprint == "" || command != "iptables -t mangle -S" {
		t.Fatalf("unexpected marker state: state=%+v err=%v command=%q", state, err, command)
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
