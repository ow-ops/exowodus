//go:build !windows

package archive

import (
	"os"

	"golang.org/x/sys/unix"
)

func lockExportFile(file *os.File) error {
	return unix.Flock(int(file.Fd()), unix.LOCK_EX|unix.LOCK_NB)
}
