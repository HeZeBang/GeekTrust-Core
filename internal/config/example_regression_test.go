package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestExampleLogLevelIsTopLevel(t *testing.T) {
	b, err := os.ReadFile("../../config.example.toml")
	if err != nil {
		t.Fatal(err)
	}
	s := strings.ReplaceAll(string(b), "REPLACE_WITH_32_UPPERCASE_HEX", "0123456789ABCDEF0123456789ABCDEF")
	s = strings.Replace(s, `log_level = "info"`, `log_level = "debug"`, 1)
	path := filepath.Join(t.TempDir(), "config.toml")
	if err := os.WriteFile(path, []byte(s), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.LogLevel != "debug" {
		t.Fatalf("template log level=%s, want debug", cfg.LogLevel)
	}
}
