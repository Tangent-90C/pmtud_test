//go:build linux

package network

import (
	"syscall"
	"time"
)

// Linux-specific socket constants
const (
	// Socket options
	SO_BINDTODEVICE     = 25
	SO_RCVTIMEO         = 20
	SO_SNDTIMEO         = 21
	IPV6_V6ONLY         = 26
	IPV6_RECVPKTINFO    = 49
	IPV6_PKTINFO        = 50
	IPV6_TCLASS         = 67
	IPV6_UNICAST_HOPS   = 16
	IPV6_MULTICAST_HOPS = 18

	// TCP options
	TCP_MAXSEG       = 2
	TCP_NODELAY      = 1
	TCP_CORK         = 3
	TCP_KEEPIDLE     = 4
	TCP_KEEPINTVL    = 5
	TCP_KEEPCNT      = 6
	TCP_USER_TIMEOUT = 18
)

// createLinuxRawSocket creates a raw ICMP6 socket on Linux
func (sm *SocketManager) createLinuxRawSocket() (int, error) {
	// Create raw IPv6 ICMP socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}

	// Set socket options
	if err := sm.setLinuxSocketOptions(fd, SocketTypeRawICMP6); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

// createLinuxTCPSocket creates a TCP IPv6 socket on Linux
func (sm *SocketManager) createLinuxTCPSocket() (int, error) {
	// Create TCP IPv6 socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}

	// Set socket options
	if err := sm.setLinuxSocketOptions(fd, SocketTypeTCPv6); err != nil {
		syscall.Close(fd)
		return -1, err
	}

	return fd, nil
}

// setLinuxSocketOptions sets Linux-specific socket options with enhanced error handling
func (sm *SocketManager) setLinuxSocketOptions(fd int, sockType SocketType) error {
	// Enable IPv6 only (disable IPv4-mapped IPv6 addresses)
	if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_V6ONLY, 1); err != nil {
		return sm.GetSocketError(err)
	}

	switch sockType {
	case SocketTypeRawICMP6:
		// Enable packet info reception for raw sockets
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_RECVPKTINFO, 1); err != nil {
			return sm.GetSocketError(err)
		}

		// Set receive buffer size (larger for better performance)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 131072); err != nil {
			// Try smaller buffer if large one fails
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 65536); err != nil {
				return sm.GetSocketError(err)
			}
		}

		// Set send buffer size
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65536); err != nil {
			return sm.GetSocketError(err)
		}

		// Enable timestamps for performance measurement
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1); err != nil {
			// Non-fatal error, continue without timestamps
		}

	case SocketTypeTCPv6:
		// Enable address reuse
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return sm.GetSocketError(err)
		}

		// Set TCP no delay for low latency
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_NODELAY, 1); err != nil {
			return sm.GetSocketError(err)
		}

		// Enable TCP keepalive
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
			// Non-fatal, continue without keepalive
		}

		// Set TCP keepalive parameters (if keepalive was enabled)
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_KEEPIDLE, 60)  // 60 seconds
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_KEEPINTVL, 10) // 10 seconds
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_KEEPCNT, 3)    // 3 probes
	}

	return nil
}

// bindLinuxInterface binds socket to a specific interface on Linux
func (sm *SocketManager) bindLinuxInterface(fd int, ifIndex int) error {
	// Convert interface name to bytes for SO_BINDTODEVICE
	// Note: This is a simplified implementation
	// In practice, you'd need to get the interface name and convert it properly
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_BINDTODEVICE, ifIndex)
}

// setLinuxMSSOption sets the TCP MSS option on Linux
func (sm *SocketManager) setLinuxMSSOption(fd int, mss int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}

// getLinuxMSSOption gets the TCP MSS option on Linux
func (sm *SocketManager) getLinuxMSSOption(fd int) (int, error) {
	return syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
}

// enableLinuxTimestamps enables packet timestamps on Linux
func (sm *SocketManager) enableLinuxTimestamps(fd int) error {
	// Enable SO_TIMESTAMP for packet timing
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1)
}

// setLinuxTOS sets the Type of Service field on Linux
func (sm *SocketManager) setLinuxTOS(fd int, tos int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
}

// setLinuxHopLimit sets the hop limit on Linux
func (sm *SocketManager) setLinuxHopLimit(fd int, hops int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_UNICAST_HOPS, hops)
}

// setLinuxTimeout sets socket timeout options on Linux
func (sm *SocketManager) setLinuxTimeout(fd int, timeout time.Duration) error {
	tv := syscall.Timeval{
		Sec:  int64(timeout.Seconds()),
		Usec: int64(timeout.Nanoseconds()%1e9) / 1000,
	}

	// Set receive timeout
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, SO_RCVTIMEO, &tv); err != nil {
		return sm.GetSocketError(err)
	}

	// Set send timeout
	if err := syscall.SetsockoptTimeval(fd, syscall.SOL_SOCKET, SO_SNDTIMEO, &tv); err != nil {
		return sm.GetSocketError(err)
	}

	return nil
}

// setLinuxAdvancedOptions sets advanced Linux-specific socket options
func (sm *SocketManager) setLinuxAdvancedOptions(fd int, sockType SocketType) error {
	switch sockType {
	case SocketTypeRawICMP6:
		// Enable extended error information
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_RECVERR, 1); err != nil {
			// Non-fatal, continue without extended errors
		}

		// Set hop limit for outgoing packets
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_UNICAST_HOPS, 64); err != nil {
			// Non-fatal
		}

	case SocketTypeTCPv6:
		// Set TCP user timeout (total time for unacknowledged data)
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_USER_TIMEOUT, 30000); err != nil {
			// Non-fatal
		}

		// Disable Nagle's algorithm for low latency
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_NODELAY, 1); err != nil {
			return sm.GetSocketError(err)
		}
	}

	return nil
}

// getLinuxSocketStats gets Linux-specific socket statistics
func (sm *SocketManager) getLinuxSocketStats(fd int) (*LinuxSocketStats, error) {
	stats := &LinuxSocketStats{}

	// Get socket error status
	sockErr, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_ERROR)
	if err != nil {
		return nil, sm.GetSocketError(err)
	}
	stats.SocketError = sockErr

	// Get socket type
	sockType, err := syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TYPE)
	if err != nil {
		return nil, sm.GetSocketError(err)
	}
	stats.SocketType = sockType

	return stats, nil
}

// LinuxSocketStats contains Linux-specific socket statistics
type LinuxSocketStats struct {
	SocketError int
	SocketType  int
}

// optimizeLinuxSocket applies Linux-specific optimizations
func (sm *SocketManager) optimizeLinuxSocket(fd int, sockType SocketType) error {
	switch sockType {
	case SocketTypeRawICMP6:
		// Increase socket priority for raw sockets
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_PRIORITY, 6); err != nil {
			// Non-fatal
		}

	case SocketTypeTCPv6:
		// Enable TCP fast open (if supported)
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, 23, 1); err != nil { // TCP_FASTOPEN
			// Non-fatal, not all kernels support this
		}
	}

	return nil
}

// Platform-specific method aliases for generic interface
func (sm *SocketManager) createPlatformRawSocket() (int, error) {
	return sm.createLinuxRawSocket()
}

func (sm *SocketManager) createPlatformTCPSocket() (int, error) {
	return sm.createLinuxTCPSocket()
}

func (sm *SocketManager) setPlatformSocketOptions(fd int, sockType SocketType) error {
	return sm.setLinuxSocketOptions(fd, sockType)
}

func (sm *SocketManager) bindPlatformInterface(fd int, ifIndex int) error {
	return sm.bindLinuxInterface(fd, ifIndex)
}

func (sm *SocketManager) setPlatformTimeout(fd int, timeout time.Duration) error {
	return sm.setLinuxTimeout(fd, timeout)
}

func (sm *SocketManager) setPlatformMSSOption(fd int, mss int) error {
	return sm.setLinuxMSSOption(fd, mss)
}

func (sm *SocketManager) getPlatformMSSOption(fd int) (int, error) {
	return sm.getLinuxMSSOption(fd)
}

func (sm *SocketManager) enablePlatformTimestamps(fd int) error {
	return sm.enableLinuxTimestamps(fd)
}

func (sm *SocketManager) setPlatformTOS(fd int, tos int) error {
	return sm.setLinuxTOS(fd, tos)
}

func (sm *SocketManager) setPlatformHopLimit(fd int, hops int) error {
	return sm.setLinuxHopLimit(fd, hops)
}
