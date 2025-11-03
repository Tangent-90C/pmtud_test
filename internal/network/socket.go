package network

import (
	"fmt"
	"net"
	"runtime"
	"syscall"
	"time"
)

// SocketManager handles platform-specific socket operations
type SocketManager struct {
	platform string
}

// NewSocketManager creates a new SocketManager
func NewSocketManager() *SocketManager {
	return &SocketManager{
		platform: runtime.GOOS,
	}
}

// CreateRawICMP6Socket creates a raw ICMP6 socket for the current platform
func (sm *SocketManager) CreateRawICMP6Socket() (int, error) {
	return sm.createPlatformRawSocket()
}

// CreateTCPv6Socket creates a TCP IPv6 socket for the current platform
func (sm *SocketManager) CreateTCPv6Socket() (int, error) {
	return sm.createPlatformTCPSocket()
}

// SetSocketOptions sets platform-specific socket options
func (sm *SocketManager) SetSocketOptions(fd int, sockType SocketType) error {
	return sm.setPlatformSocketOptions(fd, sockType)
}

// SocketType represents different types of sockets
type SocketType int

const (
	SocketTypeRawICMP6 SocketType = iota
	SocketTypeTCPv6
)

// GetPlatformInfo returns information about the current platform
func (sm *SocketManager) GetPlatformInfo() PlatformInfo {
	return PlatformInfo{
		OS:           sm.platform,
		Architecture: runtime.GOARCH,
		SupportsIPv6: sm.supportsIPv6(),
		RequiresRoot: sm.requiresRootForRawSockets(),
	}
}

// PlatformInfo contains information about the current platform
type PlatformInfo struct {
	OS           string
	Architecture string
	SupportsIPv6 bool
	RequiresRoot bool
}

// supportsIPv6 checks if the platform supports IPv6
func (sm *SocketManager) supportsIPv6() bool {
	// Try to create an IPv6 socket to test support
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_DGRAM, 0)
	if err != nil {
		return false
	}
	syscall.Close(fd)
	return true
}

// requiresRootForRawSockets returns whether the platform requires root privileges for raw sockets
func (sm *SocketManager) requiresRootForRawSockets() bool {
	switch sm.platform {
	case "linux":
		// Linux can use capabilities instead of root
		return false
	case "darwin", "freebsd", "openbsd", "netbsd":
		return true
	case "windows":
		return true
	default:
		return true
	}
}

// CloseSocket closes a socket with platform-specific cleanup
func (sm *SocketManager) CloseSocket(fd int) error {
	return syscall.Close(fd)
}

// GetSocketError returns a platform-specific socket error with enhanced error handling
func (sm *SocketManager) GetSocketError(err error) error {
	if err == nil {
		return nil
	}

	// Convert syscall errors to more user-friendly messages
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.EACCES, syscall.EPERM:
			return fmt.Errorf("permission denied: %w (try running with elevated privileges)", err)
		case syscall.EADDRINUSE:
			return fmt.Errorf("address already in use: %w", err)
		case syscall.EADDRNOTAVAIL:
			return fmt.Errorf("address not available: %w", err)
		case syscall.ENETUNREACH:
			return fmt.Errorf("network unreachable: %w", err)
		case syscall.EHOSTUNREACH:
			return fmt.Errorf("host unreachable: %w", err)
		case syscall.ECONNREFUSED:
			return fmt.Errorf("connection refused: %w", err)
		case syscall.ETIMEDOUT:
			return fmt.Errorf("operation timed out: %w", err)
		case syscall.EINVAL:
			return fmt.Errorf("invalid argument: %w", err)
		case syscall.ENOTSOCK:
			return fmt.Errorf("not a socket: %w", err)
		case syscall.EPROTONOSUPPORT:
			return fmt.Errorf("protocol not supported: %w", err)
		case syscall.EAFNOSUPPORT:
			return fmt.Errorf("address family not supported: %w", err)
		case syscall.ESOCKTNOSUPPORT:
			return fmt.Errorf("socket type not supported: %w", err)
		case syscall.EOPNOTSUPP:
			return fmt.Errorf("operation not supported: %w", err)
		case syscall.ENOBUFS:
			return fmt.Errorf("no buffer space available: %w", err)
		case syscall.ENOMEM:
			return fmt.Errorf("out of memory: %w", err)
		case syscall.EBADF:
			return fmt.Errorf("bad file descriptor: %w", err)
		case syscall.EFAULT:
			return fmt.Errorf("bad address: %w", err)
		default:
			return fmt.Errorf("socket error (%d): %w", errno, err)
		}
	}

	// Handle network errors
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return fmt.Errorf("network timeout: %w", err)
		}
		if netErr.Temporary() {
			return fmt.Errorf("temporary network error: %w", err)
		}
	}

	return fmt.Errorf("socket operation failed: %w", err)
}

// BindToInterface binds a socket to a specific network interface (if supported)
func (sm *SocketManager) BindToInterface(fd int, interfaceName string) error {
	if interfaceName == "" {
		return nil // No interface specified
	}

	iface, err := net.InterfaceByName(interfaceName)
	if err != nil {
		return fmt.Errorf("interface %s not found: %w", interfaceName, err)
	}

	return sm.bindPlatformInterface(fd, iface.Index)
}

// SetSocketTimeout sets timeout options for a socket
func (sm *SocketManager) SetSocketTimeout(fd int, timeout time.Duration) error {
	return sm.setPlatformTimeout(fd, timeout)
}

// SetSocketBufferSizes sets send and receive buffer sizes for a socket
func (sm *SocketManager) SetSocketBufferSizes(fd int, sendBuf, recvBuf int) error {
	if sendBuf > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, sendBuf); err != nil {
			return sm.GetSocketError(err)
		}
	}

	if recvBuf > 0 {
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, recvBuf); err != nil {
			return sm.GetSocketError(err)
		}
	}

	return nil
}

// GetSocketBufferSizes gets current send and receive buffer sizes
func (sm *SocketManager) GetSocketBufferSizes(fd int) (sendBuf, recvBuf int, err error) {
	sendBuf, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err != nil {
		return 0, 0, sm.GetSocketError(err)
	}

	recvBuf, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return 0, 0, sm.GetSocketError(err)
	}

	return sendBuf, recvBuf, nil
}

// SetMSSOption sets the TCP Maximum Segment Size option
func (sm *SocketManager) SetMSSOption(fd int, mss int) error {
	return sm.setPlatformMSSOption(fd, mss)
}

// GetMSSOption gets the TCP Maximum Segment Size option
func (sm *SocketManager) GetMSSOption(fd int) (int, error) {
	return sm.getPlatformMSSOption(fd)
}

// EnableTimestamps enables packet timestamps for performance measurement
func (sm *SocketManager) EnableTimestamps(fd int) error {
	return sm.enablePlatformTimestamps(fd)
}

// SetTOS sets the Type of Service/Traffic Class field
func (sm *SocketManager) SetTOS(fd int, tos int) error {
	return sm.setPlatformTOS(fd, tos)
}

// SetHopLimit sets the IPv6 hop limit
func (sm *SocketManager) SetHopLimit(fd int, hops int) error {
	return sm.setPlatformHopLimit(fd, hops)
}

// ValidateSocket checks if a socket is valid and operational
func (sm *SocketManager) ValidateSocket(fd int) error {
	// Try to get socket type to validate the socket
	_, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return sm.GetSocketError(err)
	}
	return nil
}

// GetSocketInfo returns detailed information about a socket
func (sm *SocketManager) GetSocketInfo(fd int) (*SocketInfo, error) {
	info := &SocketInfo{
		FileDescriptor: fd,
		Platform:       sm.platform,
	}

	// Get socket type
	sockType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return nil, sm.GetSocketError(err)
	}
	info.Type = sockType

	// Get socket family
	// Note: Getting socket family is platform-specific and complex
	// For now, we'll assume IPv6 based on our use case
	info.Family = syscall.AF_INET6

	// Get buffer sizes
	info.SendBufferSize, info.RecvBufferSize, err = sm.GetSocketBufferSizes(fd)
	if err != nil {
		return nil, err
	}

	return info, nil
}

// SocketInfo contains detailed information about a socket
type SocketInfo struct {
	FileDescriptor int
	Platform       string
	Type           int
	Family         int
	SendBufferSize int
	RecvBufferSize int
}

// Platform-specific methods are implemented in:
// - socket_linux.go (Linux)
// - socket_darwin.go (macOS)
// - socket_windows.go (Windows)
// - socket_bsd.go (FreeBSD, OpenBSD, NetBSD)
