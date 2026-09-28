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

func TestWindowsInitACLPolicy(t *testing.T) {
	const userID = "S-1-5-21-1-2-3-1001"
	user, err := windows.StringToSid(userID)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name, acl string
		kind      windowsInitObject
		reject    bool
	}{
		{"private parent", "(A;OICI;FA;;;" + userID + ")(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", windowsInitParent, false},
		{"private file", "(A;;FA;;;" + userID + ")", windowsInitFile, false},
		{"ancestor sibling creation", "(A;;0x4;;;AU)(A;;FR;;;BU)", windowsInitAncestor, false},
		{"ancestor inherited only modify", "(A;OICIIO;FA;;;AU)", windowsInitAncestor, false},
		{"parent creation by others", "(A;;0x4;;;AU)", windowsInitParent, true},
		{"parent file creation by others", "(A;;0x2;;;WD)", windowsInitParent, true},
		{"parent list only", "(A;;FR;;;BU)", windowsInitParent, false},
		{"ancestor delete children", "(A;;0x40;;;WD)", windowsInitAncestor, true},
		{"ancestor delete self", "(A;;SD;;;WD)", windowsInitAncestor, true},
		{"ancestor change ACL", "(A;;WD;;;AU)", windowsInitAncestor, true},
		{"ancestor change owner", "(A;;WO;;;AU)", windowsInitAncestor, true},
		{"ancestor write attributes", "(A;;0x100;;;WD)", windowsInitAncestor, true},
		{"ancestor generic write", "(A;;GW;;;WD)", windowsInitAncestor, true},
		{"inherited read", "(A;OICI;FR;;;BU)", windowsInitParent, true},
		{"inherit only read", "(A;OIIO;FR;;;WD)", windowsInitParent, true},
		{"inherit only write", "(A;CIIO;FW;;;AU)", windowsInitParent, true},
		{"creator owner inheritance", "(A;OICIIO;GA;;;CO)", windowsInitParent, false},
		{"creator group inheritance", "(A;OICIIO;GA;;;CG)", windowsInitParent, true},
		{"existing file read", "(A;;FR;;;BU)", windowsInitFile, true},
		{"existing file write", "(A;;FW;;;AU)", windowsInitFile, true},
		{"existing file execute", "(A;;FX;;;BU)", windowsInitFile, true},
		{"unrecognized user write", "(A;;FA;;;S-1-5-21-1-2-3-1002)", windowsInitFile, true},
		{"deny cannot cancel broad allow in conservative policy", "(D;;FA;;;WD)(A;;FA;;;WD)", windowsInitFile, true},
		{"deny only", "(D;;FA;;;WD)", windowsInitFile, false},
		{"empty DACL", "", windowsInitFile, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString("O:" + userID + "D:P" + tt.acl)
			if err != nil {
				t.Fatal(err)
			}
			err = checkWindowsInitSecurity(sd, user, nil, tt.kind)
			if (err != nil) != tt.reject {
				t.Fatalf("reject=%v, error=%v", tt.reject, err)
			}
		})
	}
	for _, sddl := range []string{
		"O:" + userID + "D:NO_ACCESS_CONTROL",
		"O:S-1-5-21-1-2-3-1002D:P(A;;FA;;;" + userID + ")",
		"O:" + userID + "D:P(XA;;FR;;;WD;(@User.Title == \"Manager\"))",
	} {
		t.Run(sddl, func(t *testing.T) {
			sd, err := windows.SecurityDescriptorFromString(sddl)
			if err != nil {
				t.Fatal(err)
			}
			if err := checkWindowsInitSecurity(sd, user, nil, windowsInitFile); err == nil {
				t.Fatal("unsafe or unsupported descriptor accepted")
			}
		})
	}
}
