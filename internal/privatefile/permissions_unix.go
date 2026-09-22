//go:build !windows

// Package privatefile restricts secret files to their owning identity.
package privatefile

import (
	"errors"
	"os"
)

func Protect(path string) error { return os.Chmod(path, 0o600) }

func CheckDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("directory is writable by other users")
	}
	return nil
}
