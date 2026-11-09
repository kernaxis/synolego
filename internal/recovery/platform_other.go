//go:build !linux && !darwin && !freebsd && !openbsd && !netbsd && !dragonfly

package recovery

import (
	"errors"
	"os"
)

func fileOwner(os.FileInfo) (int, int, error) {
	return 0, 0, errors.New("DSM deployment recovery requires a Unix filesystem")
}

func tryLock(*os.File) error {
	return errors.New("DSM deployment locking requires a Unix platform")
}
