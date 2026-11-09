//go:build linux || darwin || freebsd || openbsd || netbsd || dragonfly

package recovery

import (
	"fmt"
	"os"
	"syscall"
)

func fileOwner(info os.FileInfo) (int, int, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return 0, 0, fmt.Errorf("file ownership unavailable")
	}
	return int(stat.Uid), int(stat.Gid), nil
}

func tryLock(f *os.File) error {
	return syscall.Flock(int(f.Fd()), syscall.LOCK_EX|syscall.LOCK_NB)
}
