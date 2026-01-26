package validation

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// MountValidation contains results of mount unit validation.
type MountValidation struct {
	Unit           string
	NameMismatch   bool   // Unit name doesn't match Where=
	ExpectedName   string // What the unit should be named
	WhatMissing    bool   // No What= specified
	WhereMissing   bool   // No Where= specified
	WhatValue      string
	WhereValue     string
	DeviceNotFound bool // What= device doesn't exist (if local)
	InvalidFSType  bool // Unknown filesystem type
	FSType         string
	Issues         []string
	Valid          bool
}

// ValidateMount checks mount unit configuration.
func ValidateMount(unit *types.UnitFile, fs FileSystem) MountValidation {
	result := MountValidation{
		Unit:  unit.Name,
		Valid: true,
	}

	if unit.Type != "mount" {
		return result
	}

	mountSection, hasMount := unit.Sections["Mount"]
	if !hasMount {
		result.Valid = false
		result.Issues = append(result.Issues, "Mount unit has no [Mount] section")
		return result
	}

	// Get What= and Where=
	result.WhatValue = getDirectiveValue(mountSection, "What")
	result.WhereValue = getDirectiveValue(mountSection, "Where")
	result.FSType = getDirectiveValue(mountSection, "Type")

	// Check required directives
	if result.WhatValue == "" {
		result.WhatMissing = true
		result.Valid = false
		result.Issues = append(result.Issues, "Mount unit missing required What= directive")
	}

	if result.WhereValue == "" {
		result.WhereMissing = true
		result.Valid = false
		result.Issues = append(result.Issues, "Mount unit missing required Where= directive")
	}

	// Check unit name matches Where= path
	if result.WhereValue != "" {
		expectedName := pathToMountUnitName(result.WhereValue)
		result.ExpectedName = expectedName
		if unit.Name != expectedName {
			result.NameMismatch = true
			result.Valid = false
			result.Issues = append(result.Issues,
				"Unit name doesn't match Where= path. Expected: "+expectedName)
		}
	}

	// Check if device exists (for local filesystems)
	if result.WhatValue != "" && !result.WhatMissing {
		// Skip network filesystems and special devices
		if !isNetworkFS(result.FSType) && !isSpecialDevice(result.WhatValue) {
			if !fs.Exists(result.WhatValue) {
				result.DeviceNotFound = true
				// Not necessarily invalid - device might be created later
			}
		}
	}

	// Validate filesystem type
	if result.FSType != "" {
		if !isValidFSType(result.FSType) {
			result.InvalidFSType = true
			result.Issues = append(result.Issues, "Unknown filesystem type: "+result.FSType)
		}
	}

	return result
}

// pathToMountUnitName converts a path to the systemd mount unit name.
// /home/user -> home-user.mount
// / -> -.mount
func pathToMountUnitName(path string) string {
	if path == "/" {
		return "-.mount"
	}

	// Clean and trim the path
	path = filepath.Clean(path)
	path = strings.TrimPrefix(path, "/")
	path = strings.TrimSuffix(path, "/")

	// Replace / with -
	name := strings.ReplaceAll(path, "/", "-")

	// Escape special characters
	name = escapeMountUnitName(name)

	return name + ".mount"
}

// escapeMountUnitName escapes characters that need escaping in unit names.
func escapeMountUnitName(s string) string {
	var result strings.Builder
	for _, c := range s {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '_' {
			result.WriteRune(c)
		} else {
			// Escape with \xHH format
			fmt.Fprintf(&result, "\\x%02x", byte(c))
		}
	}
	return result.String()
}

// isNetworkFS returns true if the filesystem type is network-based.
func isNetworkFS(fsType string) bool {
	networkTypes := map[string]bool{
		"nfs":        true,
		"nfs4":       true,
		"cifs":       true,
		"smb":        true,
		"smbfs":      true,
		"sshfs":      true,
		"fuse.sshfs": true,
		"glusterfs":  true,
		"ceph":       true,
		"lustre":     true,
		"9p":         true,
	}
	return networkTypes[strings.ToLower(fsType)]
}

// isSpecialDevice returns true if the device is a special pseudo-device.
func isSpecialDevice(what string) bool {
	// UUID, LABEL, PARTUUID, etc.
	if strings.HasPrefix(what, "UUID=") ||
		strings.HasPrefix(what, "LABEL=") ||
		strings.HasPrefix(what, "PARTUUID=") ||
		strings.HasPrefix(what, "PARTLABEL=") {
		return true
	}

	// Pseudo filesystems
	specialPrefixes := []string{
		"tmpfs",
		"proc",
		"sysfs",
		"devtmpfs",
		"devpts",
		"cgroup",
		"cgroup2",
		"hugetlbfs",
		"mqueue",
		"securityfs",
		"debugfs",
		"tracefs",
		"configfs",
		"fusectl",
		"pstore",
		"efivarfs",
		"bpf",
	}
	for _, prefix := range specialPrefixes {
		if what == prefix || strings.HasPrefix(what, prefix+":") {
			return true
		}
	}

	return false
}

// isValidFSType returns true if the filesystem type is known.
func isValidFSType(fsType string) bool {
	// Common filesystem types
	knownTypes := map[string]bool{
		// Linux native
		"ext2": true, "ext3": true, "ext4": true,
		"xfs": true, "btrfs": true, "f2fs": true,
		"jfs": true, "reiserfs": true,
		// FAT/NTFS
		"vfat": true, "fat": true, "msdos": true,
		"ntfs": true, "ntfs-3g": true, "exfat": true,
		// Network
		"nfs": true, "nfs4": true, "cifs": true, "smb": true,
		"sshfs": true, "fuse.sshfs": true, "glusterfs": true,
		// Pseudo
		"tmpfs": true, "ramfs": true, "devtmpfs": true,
		"proc": true, "sysfs": true, "devpts": true,
		"cgroup": true, "cgroup2": true,
		"securityfs": true, "debugfs": true, "tracefs": true,
		"hugetlbfs": true, "mqueue": true, "configfs": true,
		"fusectl": true, "pstore": true, "efivarfs": true, "bpf": true,
		// Other
		"iso9660": true, "udf": true,
		"squashfs": true, "overlay": true, "overlayfs": true,
		"fuse": true, "fuseblk": true,
		"autofs": true, "nfsd": true,
		"swap": true,
	}

	// Also allow fuse.* types
	if strings.HasPrefix(strings.ToLower(fsType), "fuse.") {
		return true
	}

	return knownTypes[strings.ToLower(fsType)]
}

// ValidateAllMounts validates all mount units in a collection.
func ValidateAllMounts(units map[string]*types.UnitFile, fs FileSystem) map[string]MountValidation {
	results := make(map[string]MountValidation)

	for name, unit := range units {
		if unit.Type == "mount" {
			results[name] = ValidateMount(unit, fs)
		}
	}

	return results
}
