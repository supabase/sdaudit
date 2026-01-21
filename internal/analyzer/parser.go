package analyzer

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"github.com/samrose/sdaudit/pkg/types"
)

// ParseUnitFile parses a systemd unit file from the given path
func ParseUnitFile(path string) (*types.UnitFile, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return ParseUnitFileContent(path, string(content))
}

// ParseUnitFileContent parses a systemd unit file from string content
func ParseUnitFileContent(path, content string) (*types.UnitFile, error) {
	name := filepath.Base(path)
	unitType := getUnitType(name)

	unit := &types.UnitFile{
		Name:     name,
		Path:     path,
		Type:     unitType,
		Sections: make(map[string]*types.Section),
		Raw:      content,
	}

	scanner := bufio.NewScanner(strings.NewReader(content))
	var currentSection *types.Section
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			sectionName := line[1 : len(line)-1]
			currentSection = &types.Section{
				Name:       sectionName,
				Directives: make(map[string][]types.Directive),
			}
			unit.Sections[sectionName] = currentSection
			continue
		}

		if currentSection != nil {
			if idx := strings.Index(line, "="); idx > 0 {
				key := strings.TrimSpace(line[:idx])
				value := strings.TrimSpace(line[idx+1:])

				directive := types.Directive{
					Key:   key,
					Value: value,
					Line:  lineNum,
				}

				currentSection.Directives[key] = append(currentSection.Directives[key], directive)
			}
		}
	}

	return unit, scanner.Err()
}

func getUnitType(name string) string {
	ext := filepath.Ext(name)
	if ext == "" {
		return "unknown"
	}
	return ext[1:]
}

// LoadUnitsFromDirectory loads all unit files from a directory
func LoadUnitsFromDirectory(dir string) (map[string]*types.UnitFile, error) {
	units := make(map[string]*types.UnitFile)

	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if !isUnitFile(name) {
			continue
		}

		path := filepath.Join(dir, name)
		unit, err := ParseUnitFile(path)
		if err != nil {
			continue
		}

		units[name] = unit
	}

	return units, nil
}

// LoadUnitsFromPaths loads unit files from multiple directories
func LoadUnitsFromPaths(paths []string) (map[string]*types.UnitFile, error) {
	allUnits := make(map[string]*types.UnitFile)

	for _, path := range paths {
		info, err := os.Stat(path)
		if err != nil {
			continue
		}

		if info.IsDir() {
			units, err := LoadUnitsFromDirectory(path)
			if err != nil {
				continue
			}
			for name, unit := range units {
				allUnits[name] = unit
			}
		} else {
			unit, err := ParseUnitFile(path)
			if err != nil {
				continue
			}
			allUnits[unit.Name] = unit
		}
	}

	return allUnits, nil
}

func isUnitFile(name string) bool {
	extensions := []string{".service", ".socket", ".timer", ".mount", ".automount", ".swap", ".target", ".path", ".slice", ".scope"}
	for _, ext := range extensions {
		if strings.HasSuffix(name, ext) {
			return true
		}
	}
	return false
}

// DefaultUnitPaths returns the default systemd unit file paths
func DefaultUnitPaths() []string {
	return []string{
		"/etc/systemd/system",
		"/run/systemd/system",
		"/lib/systemd/system",
		"/usr/lib/systemd/system",
	}
}
