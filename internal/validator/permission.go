package validator

import (
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
)

// PermissionChecker handles privilege validation across different platforms
type PermissionChecker struct {
	platform      string
	supportsEmoji bool
}

// NewPermissionChecker creates a new PermissionChecker
func NewPermissionChecker() *PermissionChecker {
	return &PermissionChecker{
		platform:      runtime.GOOS,
		supportsEmoji: detectEmojiSupport(),
	}
}

// detectEmojiSupport detects if the current terminal/shell supports emoji
func detectEmojiSupport() bool {
	// Check environment variables that indicate emoji support
	term := os.Getenv("TERM")
	termProgram := os.Getenv("TERM_PROGRAM")
	lang := os.Getenv("LANG")

	// Windows Command Prompt typically doesn't support emoji well
	if runtime.GOOS == "windows" {
		// Windows Terminal and newer PowerShell versions support emoji
		if termProgram == "Windows Terminal" ||
			strings.Contains(os.Getenv("WT_SESSION"), "WT") ||
			strings.Contains(os.Getenv("TERM_PROGRAM_VERSION"), "PowerShell") {
			return true
		}
		// Traditional cmd.exe doesn't support emoji well
		return false
	}

	// Most modern Unix terminals support emoji
	if strings.Contains(term, "xterm") ||
		strings.Contains(term, "screen") ||
		strings.Contains(term, "tmux") ||
		term == "alacritty" ||
		term == "kitty" ||
		termProgram == "iTerm.app" ||
		termProgram == "Apple_Terminal" {
		return true
	}

	// Check if locale supports UTF-8 (usually indicates emoji support)
	if strings.Contains(strings.ToUpper(lang), "UTF-8") ||
		strings.Contains(strings.ToUpper(lang), "UTF8") {
		return true
	}

	// Conservative default: assume no emoji support for unknown terminals
	return false
}

// getErrorIcon returns appropriate error indicator based on emoji support
func (pc *PermissionChecker) getErrorIcon() string {
	if pc.supportsEmoji {
		return "❌"
	}
	return "[ERROR]"
}

// getSolutionIcon returns appropriate solution indicator based on emoji support
func (pc *PermissionChecker) getSolutionIcon() string {
	if pc.supportsEmoji {
		return "💡"
	}
	return "[SOLUTION]"
}

// getInfoIcon returns appropriate info indicator based on emoji support
func (pc *PermissionChecker) getInfoIcon() string {
	if pc.supportsEmoji {
		return "ℹ️"
	}
	return "[INFO]"
}

// getWarningIcon returns appropriate warning indicator based on emoji support
func (pc *PermissionChecker) getWarningIcon() string {
	if pc.supportsEmoji {
		return "⚠️"
	}
	return "[WARNING]"
}

// CheckRootPrivileges checks if the current process has sufficient privileges
// for raw socket operations on the current platform
func (pc *PermissionChecker) CheckRootPrivileges() error {
	switch pc.platform {
	case "linux":
		return pc.checkLinuxPrivileges()
	case "darwin":
		return pc.checkDarwinPrivileges()
	case "windows":
		return pc.checkWindowsPrivileges()
	case "freebsd", "openbsd", "netbsd":
		return pc.checkBSDPrivileges()
	default:
		return &PermissionError{
			Code:     ErrUnsupportedPlatform,
			Message:  fmt.Sprintf("unsupported platform: %s", pc.platform),
			Platform: pc.platform,
		}
	}
}

// checkLinuxPrivileges checks privileges on Linux systems
func (pc *PermissionChecker) checkLinuxPrivileges() error {
	// Check effective user ID
	if os.Geteuid() != 0 {
		// Also check for CAP_NET_RAW capability
		if !pc.hasCapNetRaw() {
			return &PermissionError{
				Code:     ErrInsufficientPrivileges,
				Message:  "root privileges or CAP_NET_RAW capability required for raw socket operations",
				Platform: "linux",
			}
		}
	}
	return nil
}

// checkDarwinPrivileges checks privileges on macOS systems
func (pc *PermissionChecker) checkDarwinPrivileges() error {
	if os.Geteuid() != 0 {
		return &PermissionError{
			Code:     ErrInsufficientPrivileges,
			Message:  "root privileges required for raw socket operations on macOS",
			Platform: "darwin",
		}
	}
	return nil
}

// checkBSDPrivileges checks privileges on BSD systems
func (pc *PermissionChecker) checkBSDPrivileges() error {
	if os.Geteuid() != 0 {
		return &PermissionError{
			Code:     ErrInsufficientPrivileges,
			Message:  "root privileges required for raw socket operations on BSD systems",
			Platform: pc.platform,
		}
	}
	return nil
}

// checkWindowsPrivileges checks privileges on Windows systems
func (pc *PermissionChecker) checkWindowsPrivileges() error {
	if !pc.isWindowsAdmin() {
		return &PermissionError{
			Code:     ErrInsufficientPrivileges,
			Message:  "administrator privileges required for raw socket operations on Windows",
			Platform: "windows",
		}
	}
	return nil
}

// hasCapNetRaw checks if the process has CAP_NET_RAW capability on Linux
func (pc *PermissionChecker) hasCapNetRaw() bool {
	// This is a simplified check - in a full implementation,
	// we would use libcap or parse /proc/self/status
	// For now, we'll try to create a raw socket to test
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// isWindowsAdmin checks if the current process is running as administrator on Windows
func (pc *PermissionChecker) isWindowsAdmin() bool {
	if runtime.GOOS != "windows" {
		return false
	}

	// For cross-platform compatibility, we'll use a simpler approach
	// Try to create a raw socket - if it succeeds, we likely have admin privileges
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// PrintPermissionError prints a user-friendly permission error message
func (pc *PermissionChecker) PrintPermissionError(err error) {
	if permErr, ok := err.(*PermissionError); ok {
		fmt.Printf("%s Permission Error: %s\n", pc.getErrorIcon(), permErr.Message)
		fmt.Println()

		switch permErr.Platform {
		case "linux":
			fmt.Printf("%s Solutions for Linux:\n", pc.getSolutionIcon())
			fmt.Println("   1. Run with sudo:")
			fmt.Println("      sudo ./ipv6-mtu-discovery <target>")
			fmt.Println()
			fmt.Println("   2. Grant CAP_NET_RAW capability (recommended):")
			fmt.Println("      sudo setcap cap_net_raw+ep ./ipv6-mtu-discovery")
			fmt.Println("      ./ipv6-mtu-discovery <target>")
			fmt.Println()
			fmt.Println("   3. Check if your user is in the 'netdev' group (some distributions):")
			fmt.Println("      groups $USER")

		case "darwin":
			fmt.Printf("%s Solution for macOS:\n", pc.getSolutionIcon())
			fmt.Println("   Run with sudo:")
			fmt.Println("   sudo ./ipv6-mtu-discovery <target>")
			fmt.Println()
			fmt.Println("   Note: macOS requires root privileges for raw socket operations")

		case "windows":
			fmt.Printf("%s Solution for Windows:\n", pc.getSolutionIcon())
			fmt.Println("   1. Right-click Command Prompt or PowerShell")
			fmt.Println("   2. Select 'Run as Administrator'")
			fmt.Println("   3. Run: .\\ipv6-mtu-discovery.exe <target>")

		case "freebsd", "openbsd", "netbsd":
			fmt.Printf("%s Solution for BSD systems:\n", pc.getSolutionIcon())
			fmt.Println("   Run with sudo:")
			fmt.Println("   sudo ./ipv6-mtu-discovery <target>")

		default:
			fmt.Printf("%s Platform '%s' may not be fully supported\n", pc.getWarningIcon(), permErr.Platform)
			fmt.Println("   Try running with elevated privileges")
		}

		fmt.Println()
		fmt.Printf("%s Raw socket access is required for IPv6 Path MTU Discovery\n", pc.getInfoIcon())
		fmt.Println("   This allows the program to send and receive ICMP packets")

	} else {
		fmt.Printf("%s Permission check failed: %v\n", pc.getErrorIcon(), err)
	}
}

// CanCreateRawSocket tests if raw socket creation is possible
func (pc *PermissionChecker) CanCreateRawSocket() error {
	// Try to create an IPv6 ICMP raw socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		// Provide more specific error messages based on the error type
		var message string
		switch err {
		case syscall.EPERM:
			message = "permission denied - insufficient privileges for raw socket operations"
		case syscall.EACCES:
			message = "access denied - raw socket operations not permitted"
		case syscall.EPROTONOSUPPORT:
			message = "protocol not supported - IPv6 ICMP raw sockets not available"
		case syscall.EAFNOSUPPORT:
			message = "address family not supported - IPv6 not available"
		default:
			message = fmt.Sprintf("failed to create raw socket: %v", err)
		}

		return &PermissionError{
			Code:     ErrSocketCreationFailed,
			Message:  message,
			Platform: pc.platform,
		}
	}

	// Close the socket immediately
	syscall.Close(fd)
	return nil
}

// GetRequiredPrivileges returns a description of required privileges for the current platform
func (pc *PermissionChecker) GetRequiredPrivileges() string {
	switch pc.platform {
	case "linux":
		return "root privileges or CAP_NET_RAW capability"
	case "darwin":
		return "root privileges (sudo)"
	case "windows":
		return "administrator privileges"
	case "freebsd", "openbsd", "netbsd":
		return "root privileges (sudo)"
	default:
		return "elevated privileges (platform-specific)"
	}
}

// PermissionError represents a permission-related error with additional context
type PermissionError struct {
	Code     PermissionErrorCode
	Message  string
	Platform string
}

// PermissionErrorCode represents different types of permission errors
type PermissionErrorCode int

const (
	ErrInsufficientPrivileges PermissionErrorCode = iota
	ErrUnsupportedPlatform
	ErrSocketCreationFailed
)

// Error implements the error interface
func (e *PermissionError) Error() string {
	return fmt.Sprintf("[%s] %s", e.Platform, e.Message)
}

// IsPermissionError checks if an error is a permission error
func IsPermissionError(err error) bool {
	_, ok := err.(*PermissionError)
	return ok
}
