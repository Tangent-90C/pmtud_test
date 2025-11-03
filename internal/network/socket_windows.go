//go:build windows

package network

import (
	"syscall"
	"time"
	"unsafe"
)

// Windows-specific socket constants
const (
	// Socket options for Windows
	IPV6_V6ONLY      = 27
	IPV6_PKTINFO     = 19
	IPV6_RECVPKTINFO = 19
	IPV6_TCLASS      = 39
	IPV6_UNICAST_HOPS = 4
	SIO_RCVALL       = 0x98000001
	SO_RCVTIMEO      = 0x1006
	SO_SNDTIMEO      = 0x1005
	
	// TCP options for Windows
	TCP_MAXSEG       = 4
	TCP_NODELAY      = 1
)

// createWindowsRawSocket creates a raw ICMP6 socket on Windows
func (sm *SocketManager) createWindowsRawSocket() (int, error) {
	// Create raw IPv6 ICMP socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}
	
	// Set socket options
	if err := sm.setWindowsSocketOptions(fd, SocketTypeRawICMP6); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	
	return fd, nil
}

// createWindowsTCPSocket creates a TCP IPv6 socket on Windows
func (sm *SocketManager) createWindowsTCPSocket() (int, error) {
	// Create TCP IPv6 socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}
	
	// Set socket options
	if err := sm.setWindowsSocketOptions(fd, SocketTypeTCPv6); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	
	return fd, nil
}

// setWindowsSocketOptions sets Windows-specific socket options with enhanced error handling
func (sm *SocketManager) setWindowsSocketOptions(fd int, sockType SocketType) error {
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
		
		// Set receive buffer size (try larger first, fallback to smaller)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 131072); err != nil {
			if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 65536); err != nil {
				return sm.GetSocketError(err)
			}
		}
		
		// Set send buffer size
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65536); err != nil {
			return sm.GetSocketError(err)
		}
		
	case SocketTypeTCPv6:
		// Enable address reuse (Windows uses SO_REUSEADDR differently)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return sm.GetSocketError(err)
		}
		
		// Set TCP no delay for low latency
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_NODELAY, 1); err != nil {
			return sm.GetSocketError(err)
		}
		
		// Enable TCP keepalive (Windows specific)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
			// Non-fatal, continue without keepalive
		}
	}
	
	return nil
}

// bindWindowsInterface binds socket to a specific interface on Windows
func (sm *SocketManager) bindWindowsInterface(fd int, ifIndex int) error {
	// Windows uses different approach for interface binding
	// This is a simplified implementation
	const IPV6_UNICAST_IF = 31
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_UNICAST_IF, ifIndex)
}

// setWindowsMSSOption sets the TCP MSS option on Windows
func (sm *SocketManager) setWindowsMSSOption(fd int, mss int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}

// getWindowsMSSOption gets the TCP MSS option on Windows
func (sm *SocketManager) getWindowsMSSOption(fd int) (int, error) {
	return syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
}

// enableWindowsTimestamps enables packet timestamps on Windows
func (sm *SocketManager) enableWindowsTimestamps(fd int) error {
	// Windows has different timestamp mechanisms
	// This is a placeholder for Windows-specific timestamp enabling
	return nil // Not implemented for Windows in this version
}

// setWindowsTOS sets the Type of Service field on Windows
func (sm *SocketManager) setWindowsTOS(fd int, tos int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
}

// setWindowsHopLimit sets the hop limit on Windows
func (sm *SocketManager) setWindowsHopLimit(fd int, hops int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_UNICAST_HOPS, hops)
}

// setWindowsTimeout sets socket timeout options on Windows
func (sm *SocketManager) setWindowsTimeout(fd int, timeout time.Duration) error {
	// Windows uses milliseconds for socket timeouts
	timeoutMs := uint32(timeout.Milliseconds())
	
	// Set receive timeout
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_RCVTIMEO, int(timeoutMs)); err != nil {
		return sm.GetSocketError(err)
	}
	
	// Set send timeout
	if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_SNDTIMEO, int(timeoutMs)); err != nil {
		return sm.GetSocketError(err)
	}
	
	return nil
}

// setWindowsAdvancedOptions sets advanced Windows-specific socket options
func (sm *SocketManager) setWindowsAdvancedOptions(fd int, sockType SocketType) error {
	switch sockType {
	case SocketTypeRawICMP6:
		// Set traffic class for QoS on Windows
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_TCLASS, 0); err != nil {
			// Non-fatal
		}
		
	case SocketTypeTCPv6:
		// Windows-specific TCP optimizations
		// Disable Nagle's algorithm for low latency
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_NODELAY, 1); err != nil {
			return sm.GetSocketError(err)
		}
	}
	
	return nil
}

// enableWindowsPromiscuous enables promiscuous mode on Windows (for raw sockets)
func (sm *SocketManager) enableWindowsPromiscuous(fd int) error {
	// Enable promiscuous mode using WSAIoctl
	var bytesReturned uint32
	flag := uint32(1)
	
	// This would require calling WSAIoctl, which is more complex in Go
	// For now, we'll return nil (not implemented)
	_ = bytesReturned
	_ = flag
	
	return nil
}// P
latform-specific method aliases for generic interface
func (sm *SocketManager) createPlatformRawSocket() (int, error) {
	return sm.createWindowsRawSocket()
}

func (sm *SocketManager) createPlatformTCPSocket() (int, error) {
	return sm.createWindowsTCPSocket()
}

func (sm *SocketManager) setPlatformSocketOptions(fd int, sockType SocketType) error {
	return sm.setWindowsSocketOptions(fd, sockType)
}

func (sm *SocketManager) bindPlatformInterface(fd int, ifIndex int) error {
	return sm.bindWindowsInterface(fd, ifIndex)
}

func (sm *SocketManager) setPlatformTimeout(fd int, timeout time.Duration) error {
	return sm.setWindowsTimeout(fd, timeout)
}

func (sm *SocketManager) setPlatformMSSOption(fd int, mss int) error {
	return sm.setWindowsMSSOption(fd, mss)
}

func (sm *SocketManager) getPlatformMSSOption(fd int) (int, error) {
	return sm.getWindowsMSSOption(fd)
}

func (sm *SocketManager) enablePlatformTimestamps(fd int) error {
	return sm.enableWindowsTimestamps(fd)
}

func (sm *SocketManager) setPlatformTOS(fd int, tos int) error {
	return sm.setWindowsTOS(fd, tos)
}

func (sm *SocketManager) setPlatformHopLimit(fd int, hops int) error {
	return sm.setWindowsHopLimit(fd, hops)
}