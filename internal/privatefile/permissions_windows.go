package privatefile

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

type windowsInitObject uint8

const (
	windowsInitAncestor windowsInitObject = iota
	windowsInitParent
	windowsInitFile
)

var windowsTrustedInstallerSID = sync.OnceValue(func() *windows.SID {
	// Resolve the local service identity once; failure does not grant trust.
	sid, _, _, _ := windows.LookupSID("", `NT SERVICE\TrustedInstaller`)
	return sid
})

// Resolve junctions as well as symbolic links using the opened target. Go's
// EvalSymlinks does not traverse junctions with the current winsymlink default.
// Keep the native extended path prefix for subsequent Windows file operations.
func ResolveExistingPath(path string) (string, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", err
	}
	handle, err := windows.CreateFile(pathPtr, 0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer windows.CloseHandle(handle)
	buffer := make([]uint16, 512)
	for {
		// Flags 0 request FILE_NAME_NORMALIZED | VOLUME_NAME_DOS.
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], uint32(len(buffer)), 0)
		if err != nil {
			return "", err
		}
		if n < uint32(len(buffer)) {
			return windows.UTF16ToString(buffer[:n]), nil
		}
		buffer = make([]uint16, n+1)
	}
}

// Directory write bits returned by os.Stat on Windows are synthesized from
// FILE_ATTRIBUTE_READONLY, not the DACL. Use the actual security descriptor.
func checkDirectory(dir string, _ os.FileInfo, nearest bool) error {
	kind := windowsInitAncestor
	if nearest {
		kind = windowsInitParent
	}
	return validateWindowsInitPath(dir, kind)
}

// CheckFile checks ownership and access to an existing credential or config file.
func CheckFile(path string) error { return validateWindowsInitPath(path, windowsInitFile) }

func validateWindowsInitPath(path string, kind windowsInitObject) error {
	return validateWindowsInitPathDepth(path, kind, 0)
}

func validateWindowsInitPathDepth(path string, kind windowsInitObject, depth int) error {
	if depth > 64 {
		return fmt.Errorf("too many Windows reparse targets")
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("read current user SID: %w", err)
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	// Inspect the link/junction itself as well as its resolved target (the
	// caller checks both paths), including DELETE access on the link itself.
	handle, err := windows.CreateFile(pathPtr, windows.READ_CONTROL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil, windows.OPEN_EXISTING, windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT, 0)
	if err != nil {
		return fmt.Errorf("open Windows security descriptor: %w", err)
	}
	defer windows.CloseHandle(handle)
	sd, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("read Windows ACL: %w", err)
	}
	// TrustedInstaller owns some system ancestors. Do not trust arbitrary
	// service accounts or groups merely because the current user belongs to them.
	if err := checkWindowsInitSecurity(sd, user.User.Sid, windowsTrustedInstallerSID(), kind); err != nil {
		return err
	}
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return fmt.Errorf("inspect Windows reparse attributes: %w", err)
	}
	if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT == 0 {
		return nil
	}
	// The final normalized path omits intermediate links in A -> B -> C.
	// Check each first-hop target and its ancestors too, or someone who can
	// replace B could redirect an otherwise protected A and C after validation.
	target, err := os.Readlink(path)
	if err != nil {
		return fmt.Errorf("inspect Windows reparse target: %w", err)
	}
	if !filepath.IsAbs(target) {
		target = filepath.Join(filepath.Dir(path), target)
	}
	if err := validateWindowsInitPathDepth(target, kind, depth+1); err != nil {
		return fmt.Errorf("reparse target %s: %w", target, err)
	}
	for dir := filepath.Dir(target); ; dir = filepath.Dir(dir) {
		if err := validateWindowsInitPathDepth(dir, windowsInitAncestor, depth+1); err != nil {
			return fmt.Errorf("reparse target ancestor %s: %w", dir, err)
		}
		if filepath.Dir(dir) == dir {
			return nil
		}
	}
}

func checkWindowsInitSecurity(sd *windows.SECURITY_DESCRIPTOR, user, installer *windows.SID, kind windowsInitObject) error {
	// ACL and ACE pointers refer into sd's backing allocation.
	defer runtime.KeepAlive(sd)
	trusted := func(sid *windows.SID) bool {
		return sid != nil && (sid.Equals(user) || sid.IsWellKnown(windows.WinLocalSystemSid) ||
			sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || (installer != nil && sid.Equals(installer)))
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("read Windows owner: %w", err)
	}
	if !trusted(owner) {
		return fmt.Errorf("Windows owner is not the current user, SYSTEM, Administrators or TrustedInstaller")
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("read Windows DACL: %w", err)
	}
	if dacl == nil {
		return fmt.Errorf("Windows DACL is null (unrestricted access)")
	}
	// Higher ancestors may allow users to create unrelated siblings (e.g.
	// C:\). That does not let them replace an existing protected child.
	const fileDeleteChild = 0x40 // FILE_DELETE_CHILD (WinNT.h)
	const replace = windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER |
		fileDeleteChild | windows.FILE_WRITE_ATTRIBUTES | windows.FILE_WRITE_EA |
		windows.GENERIC_ALL | windows.GENERIC_WRITE
	const write = replace | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA
	const private = write | windows.FILE_READ_DATA | windows.FILE_EXECUTE | windows.GENERIC_READ | windows.GENERIC_EXECUTE
	for i := uint32(0); i < uint32(dacl.AceCount); i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, i, &ace); err != nil {
			return fmt.Errorf("read Windows ACE: %w", err)
		}
		// Denies can only reduce access. Ignoring them is conservative: a
		// broad allow plus deny may be rejected, never silently accepted.
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return fmt.Errorf("unsupported Windows ACE type %d", ace.Header.AceType)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trusted(sid) {
			continue
		}
		mask := uint32(ace.Mask)
		flags := ace.Header.AceFlags
		if flags&windows.INHERIT_ONLY_ACE == 0 {
			dangerous := uint32(replace)
			if kind == windowsInitParent {
				dangerous = write
			} else if kind == windowsInitFile {
				dangerous = private
			}
			if mask&dangerous != 0 {
				return fmt.Errorf("Windows ACL grants unsafe access to %s (mask %#x)", sid.String(), mask)
			}
		}
		// Chmod(0600) does not protect Windows files. Reject inheritable
		// grants that would expose newly created files or missing directories.
		// CREATOR_OWNER becomes the creating user on those new objects.
		if kind == windowsInitParent && flags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0 &&
			!sid.IsWellKnown(windows.WinCreatorOwnerSid) && mask&private != 0 {
			return fmt.Errorf("Windows ACL would inherit unsafe access for %s (mask %#x)", sid.String(), mask)
		}
	}
	return nil
}

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
