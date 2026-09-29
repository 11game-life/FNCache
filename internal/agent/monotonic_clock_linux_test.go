//go:build linux

package agent

import "testing"

func TestMonotonicNowNSIsNonZeroAndIncreasing(t *testing.T) {
	first, err := monotonicNowNS()
	if err != nil || first == 0 {
		t.Fatalf("first monotonic timestamp = %d, err=%v", first, err)
	}
	second, err := monotonicNowNS()
	if err != nil || second < first {
		t.Fatalf("monotonic timestamps regressed: first=%d second=%d err=%v", first, second, err)
	}
}
