package platform

import (
	"fmt"
	"runtime"
	"syscall"
)

// Platform represents the current operating system platform
type Platform struct {
	OS           string
	Architecture string
	Version      string
	Capabilities PlatformCapabilities
}

// PlatformCapabilities represents what the platform supports
type PlatformCapabilities struct {
	SupportsIPv6          bool
	SupportsRawSockets    bool
	RequiresElevation     bool
	SupportsMSSClamping   bool
	SupportsTimestamps    bool
	SupportsInterfaceBind bool
}

// Detector handles platform detection and capability checking
type Detector struct {
	platform Platform
}

// NewDetector creates a new platform detector
func NewDetector() *Detector {
	return &Detector{
		platform: Platform{
			OS:           runtime.GOOS,
			Architecture: runtime.GOARCH,
			Version:      runtime.Version(),
		},
	}
}

// DetectPlatform detects the current platform and its capabilities
func (d *Detector) DetectPlatform() (*Platform, error) {
	// Detect capabilities
	capabilities, err := d.detectCapabilities()
	if err != nil {
		return nil, fmt.Errorf("failed to detect platform capabilities: %w", err)
	}

	d.platform.Capabilities = capabilities
	return &d.platform, nil
}

// detectCapabilities detects what the current platform supports
func (d *Detector) detectCapabilities() (PlatformCapabilities, error) {
	caps := PlatformCapabilities{}

	// Test IPv6 support
	caps.SupportsIPv6 = d.testIPv6Support()

	// Test raw socket support
	caps.SupportsRawSockets = d.testRawSocketSupport()

	// Determine if elevation is required
	caps.RequiresElevation = d.requiresElevation()

	// Test MSS clamping support
	caps.SupportsMSSClamping = d.testMSSClampingSupport()

	// Test timestamp support
	caps.SupportsTimestamps = d.testTimestampSupport()

	// Test interface binding support
	caps.SupportsInterfaceBind = d.testInterfaceBindSupport()

	return caps, nil
}

// testIPv6Support tests if IPv6 is supported
func (d *Detector) testIPv6Support() bool {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// testRawSocketSupport tests if raw sockets are supported
func (d *Detector) testRawSocketSupport() bool {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		// On Linux, EPERM usually means insufficient privileges, not lack of support
		if d.platform.OS == "linux" && err == syscall.EPERM {
			// Raw sockets are supported but require privileges
			return true
		}
		return false
	}
	syscall.Close(fd)
	return true
}

// requiresElevation determines if the platform requires elevated privileges
func (d *Detector) requiresElevation() bool {
	switch d.platform.OS {
	case "linux":
		// Linux can use capabilities, so elevation is not always required
		return false
	case "darwin", "freebsd", "openbsd", "netbsd":
		return true
	case "windows":
		return true
	default:
		return true
	}
}

// testMSSClampingSupport tests if TCP MSS clamping is supported
func (d *Detector) testMSSClampingSupport() bool {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	// Try to set MSS option
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, 1400)
	return err == nil
}

// testTimestampSupport tests if packet timestamps are supported
func (d *Detector) testTimestampSupport() bool {
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false
	}
	defer syscall.Close(fd)

	// Try to enable timestamps
	err = syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1)
	return err == nil
}

// testInterfaceBindSupport tests if interface binding is supported
func (d *Detector) testInterfaceBindSupport() bool {
	switch d.platform.OS {
	case "linux", "darwin", "freebsd", "openbsd", "netbsd":
		return true
	case "windows":
		return true // Windows supports it but with different APIs
	default:
		return false
	}
}

// GetPlatformInfo returns detailed platform information
func (d *Detector) GetPlatformInfo() PlatformInfo {
	return PlatformInfo{
		OS:                    d.platform.OS,
		Architecture:          d.platform.Architecture,
		GoVersion:             d.platform.Version,
		SupportsIPv6:          d.platform.Capabilities.SupportsIPv6,
		SupportsRawSockets:    d.platform.Capabilities.SupportsRawSockets,
		RequiresElevation:     d.platform.Capabilities.RequiresElevation,
		SupportsMSSClamping:   d.platform.Capabilities.SupportsMSSClamping,
		SupportsTimestamps:    d.platform.Capabilities.SupportsTimestamps,
		SupportsInterfaceBind: d.platform.Capabilities.SupportsInterfaceBind,
	}
}

// PlatformInfo contains comprehensive platform information
type PlatformInfo struct {
	OS                    string
	Architecture          string
	GoVersion             string
	SupportsIPv6          bool
	SupportsRawSockets    bool
	RequiresElevation     bool
	SupportsMSSClamping   bool
	SupportsTimestamps    bool
	SupportsInterfaceBind bool
}

// String returns a string representation of platform info
func (pi PlatformInfo) String() string {
	return fmt.Sprintf("Platform: %s/%s, Go: %s, IPv6: %t, Raw Sockets: %t, Requires Elevation: %t",
		pi.OS, pi.Architecture, pi.GoVersion, pi.SupportsIPv6, pi.SupportsRawSockets, pi.RequiresElevation)
}

// IsSupported returns whether the platform is supported for MTU discovery
func (pi PlatformInfo) IsSupported() bool {
	return pi.SupportsIPv6 && pi.SupportsRawSockets
}

// GetRequiredPrivileges returns a description of required privileges
func (pi PlatformInfo) GetRequiredPrivileges() string {
	if !pi.RequiresElevation {
		return "standard user privileges (or CAP_NET_RAW capability on Linux)"
	}

	switch pi.OS {
	case "linux":
		return "root privileges or CAP_NET_RAW capability"
	case "darwin":
		return "root privileges (use sudo)"
	case "windows":
		return "administrator privileges"
	case "freebsd", "openbsd", "netbsd":
		return "root privileges (use sudo)"
	default:
		return "elevated privileges"
	}
}

// GetPlatformSpecificNotes returns platform-specific usage notes
func (pi PlatformInfo) GetPlatformSpecificNotes() []string {
	var notes []string

	switch pi.OS {
	case "linux":
		notes = append(notes, "On Linux, you can use 'sudo setcap cap_net_raw+ep ./binary' to avoid running as root")
		if !pi.SupportsRawSockets {
			notes = append(notes, "Raw socket support may be disabled by security policies")
		}

	case "darwin":
		notes = append(notes, "On macOS, raw sockets require root privileges")
		notes = append(notes, "System Integrity Protection (SIP) may affect raw socket operations")

	case "windows":
		notes = append(notes, "On Windows, run Command Prompt or PowerShell as Administrator")
		notes = append(notes, "Windows Defender or antivirus software may interfere with raw sockets")

	case "freebsd", "openbsd", "netbsd":
		notes = append(notes, "On BSD systems, raw sockets require root privileges")
		notes = append(notes, "Some BSD variants may have additional security restrictions")

	default:
		notes = append(notes, "Platform support may be limited or experimental")
	}

	if !pi.SupportsIPv6 {
		notes = append(notes, "IPv6 support is not available on this system")
	}

	return notes
}
