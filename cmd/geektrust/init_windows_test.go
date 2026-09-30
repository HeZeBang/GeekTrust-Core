package main

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestCmdInitWindowsDirectoryPermissions(t *testing.T) {
	dir := t.TempDir()
	info, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm()&0o022 == 0 {
		t.Fatal("expected synthetic Windows write bits on a writable directory")
	}
	// Missing nested directories also exercise the existing ancestor checks.
	configPath := filepath.Join(dir, "nested", "config.toml")
	if err := cmdInit(context.Background(), configPath, []string{
		"--keystore", filepath.Join(dir, "key.keystore"),
		"--state-file", filepath.Join(dir, "state.enc"),
	}); err != nil {
		t.Fatalf("init rejected a Windows directory: %v", err)
	}
	if _, err := os.Stat(configPath); err != nil {
		t.Fatalf("config was not created: %v", err)
	}
	if err := validateInitDirectory("config", filepath.Join(configPath, "child.toml")); err == nil {
		t.Fatal("a regular file was accepted as a parent directory")
	}
}
