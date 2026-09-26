package flannel

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strconv"
	"strings"

	"github.com/cat-cc-Lcos/FNCache/internal/reconcile"
)

type MarkerRuleSpec struct {
	Chain   string
	Comment string
}

type RuleScanner struct {
	run CommandRunner
}

func NewRuleScanner(run CommandRunner) *RuleScanner {
	discovery := NewDiscovery(run)
	return &RuleScanner{run: discovery.run}
}

func (s *RuleScanner) Scan(ctx context.Context, spec MarkerRuleSpec) (reconcile.RuleState, error) {
	if err := validateMarkerRuleSpec(spec); err != nil {
		return reconcile.RuleState{}, err
	}
	state := reconcile.RuleState{Identity: spec.Chain + "/" + spec.Comment}
	if err := ctx.Err(); err != nil {
		return state, err
	}
	output, err := s.run(ctx, "iptables", "-t", "mangle", "-S")
	if err != nil {
		return reconcile.RuleState{}, fmt.Errorf("scan Flannel marker rules: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return reconcile.RuleState{}, err
	}
	var match string
	for _, line := range strings.Split(string(output), "\n") {
		chain, ok := ruleChain(line)
		if !ok || !ruleHasComment(line, spec.Comment) {
			continue
		}
		if chain != spec.Chain {
			return reconcile.RuleState{}, fmt.Errorf("marker comment found in chain %q, want %q", chain, spec.Chain)
		}
		if match != "" {
			return reconcile.RuleState{}, fmt.Errorf("marker rule comment is duplicated in chain %q", spec.Chain)
		}
		match = strings.TrimSpace(line)
	}
	if match == "" {
		return state, nil
	}
	state.Present = true
	state.Fingerprint = ruleFingerprint(match)
	return state, nil
}

func validateMarkerRuleSpec(spec MarkerRuleSpec) error {
	if strings.TrimSpace(spec.Chain) == "" || strings.ContainsAny(spec.Chain, " \t\r\n") {
		return fmt.Errorf("marker rule chain is invalid")
	}
	if spec.Comment == "" || strings.ContainsAny(spec.Comment, "\"\r\n") {
		return fmt.Errorf("marker rule comment is invalid")
	}
	return nil
}

func ruleChain(line string) (string, bool) {
	fields := strings.Fields(line)
	if len(fields) < 2 || fields[0] != "-A" {
		return "", false
	}
	return fields[1], true
}

func ruleHasComment(line, comment string) bool {
	return strings.Contains(line, "--comment "+strconv.Quote(comment)) || strings.Contains(line, "--comment "+comment)
}

func ruleFingerprint(line string) string {
	normalized := strings.Join(strings.Fields(line), " ")
	sum := sha256.Sum256([]byte(normalized))
	return hex.EncodeToString(sum[:])
}
