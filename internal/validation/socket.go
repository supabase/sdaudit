package validation

import (
	"fmt"
	"net"
	"regexp"
	"strconv"
	"strings"

	"github.com/supabase/sdaudit/pkg/types"
)

// SocketValidation contains results of socket unit validation.
type SocketValidation struct {
	Unit           string
	MissingService bool            // No matching .service unit
	ServiceName    string          // The expected service name
	InvalidListen  []InvalidListen // Malformed ListenStream/ListenDatagram
	PortConflicts  []PortConflict  // Same port as another socket
	Issues         []string
	Valid          bool
}

// InvalidListen represents an invalid listen directive.
type InvalidListen struct {
	Directive string // "ListenStream", "ListenDatagram", etc.
	Value     string
	Reason    string
	Line      int
}

// PortConflict represents a port conflict between sockets.
type PortConflict struct {
	Port        string
	OtherSocket string
}

// ValidateSocket checks socket unit configuration.
func ValidateSocket(unit *types.UnitFile, allUnits map[string]*types.UnitFile) SocketValidation {
	result := SocketValidation{
		Unit:  unit.Name,
		Valid: true,
	}

	if unit.Type != "socket" {
		return result
	}

	socketSection, hasSocket := unit.Sections["Socket"]
	if !hasSocket {
		result.Valid = false
		result.Issues = append(result.Issues, "Socket unit has no [Socket] section")
		return result
	}

	// Determine expected service name
	serviceName := getExpectedServiceName(unit, socketSection)
	result.ServiceName = serviceName

	// Check if service exists
	if _, exists := allUnits[serviceName]; !exists {
		result.MissingService = true
		result.Valid = false
	}

	// Validate listen directives
	listenDirectives := []string{
		"ListenStream",
		"ListenDatagram",
		"ListenSequentialPacket",
		"ListenFIFO",
		"ListenSpecial",
		"ListenNetlink",
		"ListenMessageQueue",
		"ListenUSBFunction",
	}

	for _, directive := range listenDirectives {
		if dirs, ok := socketSection.Directives[directive]; ok {
			for _, d := range dirs {
				if invalid := validateListenValue(directive, d.Value, d.Line); invalid != nil {
					result.InvalidListen = append(result.InvalidListen, *invalid)
				}
			}
		}
	}

	// Check for at least one listen directive
	hasListen := false
	for _, directive := range listenDirectives {
		if _, ok := socketSection.Directives[directive]; ok {
			hasListen = true
			break
		}
	}
	if !hasListen {
		result.Issues = append(result.Issues, "Socket unit has no Listen* directives")
		result.Valid = false
	}

	if len(result.InvalidListen) > 0 || len(result.Issues) > 0 {
		result.Valid = false
	}

	return result
}

// getExpectedServiceName determines which service this socket activates.
func getExpectedServiceName(unit *types.UnitFile, socketSection *types.Section) string {
	// Check explicit Service= directive
	if service := getDirectiveValue(socketSection, "Service"); service != "" {
		return service
	}

	// Default: same name with .service extension
	return strings.TrimSuffix(unit.Name, ".socket") + ".service"
}

// validateListenValue validates a listen directive value.
func validateListenValue(directive, value string, line int) *InvalidListen {
	if value == "" {
		return &InvalidListen{
			Directive: directive,
			Value:     value,
			Reason:    "Empty value",
			Line:      line,
		}
	}

	switch directive {
	case "ListenStream", "ListenDatagram", "ListenSequentialPacket":
		return validateNetworkListen(directive, value, line)
	case "ListenFIFO", "ListenSpecial":
		return validatePathListen(directive, value, line)
	case "ListenNetlink":
		return validateNetlinkListen(directive, value, line)
	}

	return nil
}

// validateNetworkListen validates ListenStream/ListenDatagram/ListenSequentialPacket.
func validateNetworkListen(directive, value string, line int) *InvalidListen {
	// Can be:
	// - Port number: 8080
	// - IP:port: 127.0.0.1:8080
	// - [IPv6]:port: [::1]:8080
	// - Unix socket path: /run/foo.sock
	// - Abstract socket: @foo
	// - File descriptor name: foo.socket

	// Check if it's a path (Unix socket)
	if strings.HasPrefix(value, "/") || strings.HasPrefix(value, "@") {
		// Unix socket path or abstract socket
		if strings.HasPrefix(value, "/") && len(value) > 108 {
			return &InvalidListen{
				Directive: directive,
				Value:     value,
				Reason:    "Unix socket path exceeds maximum length (108 characters)",
				Line:      line,
			}
		}
		return nil
	}

	// Check if it's just a port number
	if port, err := strconv.Atoi(value); err == nil {
		if port < 1 || port > 65535 {
			return &InvalidListen{
				Directive: directive,
				Value:     value,
				Reason:    fmt.Sprintf("Port %d is out of valid range (1-65535)", port),
				Line:      line,
			}
		}
		return nil
	}

	// Check if it's IP:port or [IPv6]:port
	_, portStr, err := net.SplitHostPort(value)
	if err != nil {
		// Try treating the whole thing as a host (for default port scenarios)
		if net.ParseIP(value) != nil {
			return &InvalidListen{
				Directive: directive,
				Value:     value,
				Reason:    "IP address without port",
				Line:      line,
			}
		}
		// Could be a service name reference
		return nil
	}

	// Validate port
	port, err := strconv.Atoi(portStr)
	if err != nil {
		// Could be a service name like "http"
		return nil
	}
	if port < 1 || port > 65535 {
		return &InvalidListen{
			Directive: directive,
			Value:     value,
			Reason:    fmt.Sprintf("Port %d is out of valid range (1-65535)", port),
			Line:      line,
		}
	}

	// Note: host could be an IP address or hostname, both are valid
	// net.ParseIP(host) == nil just means it's a hostname, not an error

	return nil
}

// validatePathListen validates ListenFIFO/ListenSpecial.
func validatePathListen(directive, value string, line int) *InvalidListen {
	// Must be an absolute path
	if !strings.HasPrefix(value, "/") {
		return &InvalidListen{
			Directive: directive,
			Value:     value,
			Reason:    "Must be an absolute path",
			Line:      line,
		}
	}

	return nil
}

// validateNetlinkListen validates ListenNetlink.
func validateNetlinkListen(directive, value string, line int) *InvalidListen {
	// Format: FAMILY [GROUP...]
	// Valid families: route, audit, etc.
	validFamilies := map[string]bool{
		"route":          true,
		"firewall":       true,
		"inet-diag":      true,
		"nflog":          true,
		"xfrm":           true,
		"selinux":        true,
		"iscsi":          true,
		"audit":          true,
		"fib-lookup":     true,
		"connector":      true,
		"netfilter":      true,
		"ip6-firewall":   true,
		"dnrtmsg":        true,
		"kobject-uevent": true,
		"generic":        true,
		"scsitransport":  true,
		"ecryptfs":       true,
		"rdma":           true,
		"crypto":         true,
	}

	parts := strings.Fields(value)
	if len(parts) == 0 {
		return &InvalidListen{
			Directive: directive,
			Value:     value,
			Reason:    "Empty netlink family",
			Line:      line,
		}
	}

	family := strings.ToLower(parts[0])
	if !validFamilies[family] {
		// Could be numeric family ID
		if _, err := strconv.Atoi(family); err != nil {
			return &InvalidListen{
				Directive: directive,
				Value:     value,
				Reason:    fmt.Sprintf("Unknown netlink family: %s", family),
				Line:      line,
			}
		}
	}

	return nil
}

// DetectPortConflicts finds sockets listening on the same port.
func DetectPortConflicts(units map[string]*types.UnitFile) []PortConflict {
	var conflicts []PortConflict

	// Map port -> socket unit name
	portMap := make(map[string]string)

	// Regex to extract port from various formats
	portRegex := regexp.MustCompile(`(?::(\d+)$|^(\d+)$)`)

	for name, unit := range units {
		if unit.Type != "socket" {
			continue
		}

		socketSection, ok := unit.Sections["Socket"]
		if !ok {
			continue
		}

		for _, directive := range []string{"ListenStream", "ListenDatagram"} {
			if dirs, ok := socketSection.Directives[directive]; ok {
				for _, d := range dirs {
					// Extract port number
					matches := portRegex.FindStringSubmatch(d.Value)
					var port string
					if len(matches) > 1 && matches[1] != "" {
						port = matches[1]
					} else if len(matches) > 2 && matches[2] != "" {
						port = matches[2]
					}

					if port != "" {
						key := directive + ":" + port
						if existingUnit, exists := portMap[key]; exists && existingUnit != name {
							conflicts = append(conflicts, PortConflict{
								Port:        port,
								OtherSocket: existingUnit,
							})
						} else {
							portMap[key] = name
						}
					}
				}
			}
		}
	}

	return conflicts
}
