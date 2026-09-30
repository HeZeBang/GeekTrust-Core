// Package privatefile checks credential paths and protects files containing secrets.
package privatefile

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
)

// CheckParents checks the nearest existing directory and every ancestor.
func CheckParents(path string) error {
	dir := filepath.Dir(path)
	nearest := true
	for {
		info, err := os.Stat(dir)
		if err == nil {
			if !info.IsDir() {
				return fmt.Errorf("parent %s is not a directory", dir)
			}
			if err := checkDirectory(dir, info, nearest); err != nil {
				return fmt.Errorf("directory ancestor %s: %w", dir, err)
			}
			nearest = false
		} else if !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("inspect directory: %w", err)
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}
