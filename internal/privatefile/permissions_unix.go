//go:build !windows

package privatefile

import (
	"errors"
	"os"
	"path/filepath"
)

func checkDirectory(_ string, info os.FileInfo, _ bool) error {
	// A directory entry can be replaced by anyone who can write its parent.
	if info.Mode().Perm()&0o022 != 0 && info.Mode()&os.ModeSticky == 0 {
		return errors.New("directory is writable by other users")
	}
	return nil
}

// CheckFile retains the Unix behavior; Protect applies the private file mode.
func CheckFile(_ string) error { return nil }

// ResolveExistingPath resolves aliases in an existing path.
func ResolveExistingPath(path string) (string, error) { return filepath.EvalSymlinks(path) }

func Protect(path string) error { return os.Chmod(path, 0o600) }
