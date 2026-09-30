//go:build linux

package agent

import "golang.org/x/sys/unix"

func monotonicNowNS() (uint64, error) {
	var timestamp unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &timestamp); err != nil {
		return 0, err
	}
	return uint64(timestamp.Nano()), nil
}
