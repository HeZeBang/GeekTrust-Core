package privatefile

import (
	"errors"
	"golang.org/x/sys/windows"
	"unsafe"
)

// Protect replaces inherited permissions with access for the current identity
// and LocalSystem. Call before writing any secret bytes into a new file.
func Protect(path string) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;" + user.User.Sid.String() + ")")
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil)
}

// CheckDirectory rejects permissions that let another ordinary identity
// replace existing entries or change the directory's access rules. Permission
// to create a new child alone (as on a volume root) does not allow replacement.
func CheckDirectory(path string) error {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	acl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	if acl == nil {
		return errors.New("directory has unrestricted access")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	const replaceMask = 0x40 | 0x10000 | 0x40000 | 0x80000 | 0x10000000 // delete-child, delete, write-DACL, write-owner, generic-all
	for i := uint16(0); i < acl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(acl, uint32(i), &ace); err != nil {
			return err
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if uint32(ace.Mask)&replaceMask == 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		if sid == user.User.Sid.String() || sid == "S-1-5-18" || sid == "S-1-5-32-544" || sid == "S-1-3-0" || sid == "S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464" {
			continue
		}
		return errors.New("directory permits replacement by another identity")
	}
	return nil
}
