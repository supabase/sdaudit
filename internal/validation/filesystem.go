// Package validation provides type-specific validation for systemd units.
package validation

import (
	"os"
	"os/user"
)

// FileSystem abstracts filesystem operations for testability.
type FileSystem interface {
	Exists(path string) bool
	IsExecutable(path string) bool
	IsDirectory(path string) bool
	UserExists(name string) bool
	GroupExists(name string) bool
}

// RealFileSystem implements FileSystem using the actual filesystem.
type RealFileSystem struct {
	Root string // Root path for offline analysis (empty = live system)
}

// NewRealFileSystem creates a new RealFileSystem.
func NewRealFileSystem(root string) *RealFileSystem {
	return &RealFileSystem{Root: root}
}

// Exists checks if a path exists.
func (fs *RealFileSystem) Exists(path string) bool {
	fullPath := fs.resolvePath(path)
	_, err := os.Stat(fullPath)
	return err == nil
}

// IsExecutable checks if a path is executable.
func (fs *RealFileSystem) IsExecutable(path string) bool {
	fullPath := fs.resolvePath(path)
	info, err := os.Stat(fullPath)
	if err != nil {
		return false
	}
	// Check if any execute bit is set
	return info.Mode()&0111 != 0
}

// IsDirectory checks if a path is a directory.
func (fs *RealFileSystem) IsDirectory(path string) bool {
	fullPath := fs.resolvePath(path)
	info, err := os.Stat(fullPath)
	if err != nil {
		return false
	}
	return info.IsDir()
}

// UserExists checks if a user exists.
func (fs *RealFileSystem) UserExists(name string) bool {
	// For offline analysis, we can't reliably check users
	if fs.Root != "" {
		return true // Assume exists in offline mode
	}
	_, err := user.Lookup(name)
	return err == nil
}

// GroupExists checks if a group exists.
func (fs *RealFileSystem) GroupExists(name string) bool {
	// For offline analysis, we can't reliably check groups
	if fs.Root != "" {
		return true // Assume exists in offline mode
	}
	_, err := user.LookupGroup(name)
	return err == nil
}

// resolvePath prepends the root if set.
func (fs *RealFileSystem) resolvePath(path string) string {
	if fs.Root == "" {
		return path
	}
	return fs.Root + path
}

// MockFileSystem implements FileSystem for testing.
type MockFileSystem struct {
	Files       map[string]bool // path -> exists
	Executables map[string]bool // path -> is executable
	Directories map[string]bool // path -> is directory
	Users       map[string]bool // username -> exists
	Groups      map[string]bool // groupname -> exists
}

// NewMockFileSystem creates a new MockFileSystem.
func NewMockFileSystem() *MockFileSystem {
	return &MockFileSystem{
		Files:       make(map[string]bool),
		Executables: make(map[string]bool),
		Directories: make(map[string]bool),
		Users:       make(map[string]bool),
		Groups:      make(map[string]bool),
	}
}

func (fs *MockFileSystem) Exists(path string) bool {
	return fs.Files[path]
}

func (fs *MockFileSystem) IsExecutable(path string) bool {
	return fs.Executables[path]
}

func (fs *MockFileSystem) IsDirectory(path string) bool {
	return fs.Directories[path]
}

func (fs *MockFileSystem) UserExists(name string) bool {
	return fs.Users[name]
}

func (fs *MockFileSystem) GroupExists(name string) bool {
	return fs.Groups[name]
}
