package privatefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(path, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := Protect(path); err != nil {
		t.Fatal(err)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	sddl := sd.String()
	if !strings.HasPrefix(sddl, "D:P") || strings.Count(sddl, "(A;") != 2 || strings.Contains(sddl, ";ID;") {
		t.Fatalf("unexpected file ACL: %s", sddl)
	}
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestDirectoryProtection(t *testing.T) {
	path := t.TempDir()
	if err := Protect(path); err != nil {
		t.Fatal(err)
	}
	if err := CheckDirectory(path); err != nil {
		sd, _ := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		u, _ := windows.GetCurrentProcessToken().GetTokenUser()
		t.Fatalf("protected directory rejected: %v; descriptor=%s; identity=%s", err, sd.String(), u.User.Sid.String())
	}
}

func TestRejectWorldWritableDirectory(t *testing.T) {
	path := t.TempDir()
	defer Protect(path)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;WD)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
	if CheckDirectory(path) == nil {
		t.Fatal("world-writable directory accepted")
	}
}
