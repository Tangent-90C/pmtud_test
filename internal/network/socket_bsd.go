//go:build freebsd || openbsd || netbsd

package network

import (
	"syscall"
	"time"
)

// BSD-specific socket constants
const (
	// Socket options for BSD systems
	IPV6_V6ONLY      = 27
	IPV6_RECVPKTINFO = 36
	IPV6_PKTINFO     = 25
	IPV6_TCLASS      = 61
	IPV6_UNICAST_HOPS = 4
	SO_RCVTIMEO      = 0x1006
	SO_SNDTIMEO      = 0x1005
	
	// TCP options for BSD systems
	TCP_MAXSEG       = 2
	TCP_NODELAY      = 1
)

// createBSDRawSocket creates a raw ICMP6 socket on BSD systems
func (sm *SocketManager) createBSDRawSocket() (int, error) {
	// Create raw IPv6 ICMP socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}
	
	// Set socket options
	if err := sm.setBSDSocketOptions(fd, SocketTypeRawICMP6); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	
	return fd, nil
}

// createBSDTCPSocket creates a TCP IPv6 socket on BSD systems
func (sm *SocketManager) createBSDTCPSocket() (int, error) {
	// Create TCP IPv6 socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}
	
	// Set socket options
	if err := sm.setBSDSocketOptions(fd, SocketTypeTCPv6); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	
	return fd, nil
}

// setBSDSocketOptions sets BSD-specific socket options
func (sm *SocketManager) setBSDSocketOptions(fd int, sockType SocketType) error {
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
		
		// Set receive buffer size
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF, 65536); err != nil {
			return sm.GetSocketError(err)
		}
		
		// Set send buffer size
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF, 65536); err != nil {
			return sm.GetSocketError(err)
		}
		
	case SocketTypeTCPv6:
		// Enable address reuse
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEADDR, 1); err != nil {
			return sm.GetSocketError(err)
		}
		
		// Set TCP no delay
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_NODELAY, 1); err != nil {
			return sm.GetSocketError(err)
		}
		
		// Enable port reuse (BSD specific)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); err != nil {
			// This is optional, don't fail if not supported
		}
	}
	
	return nil
}

// bindBSDInterface binds socket to a specific interface on BSD systems
func (sm *SocketManager) bindBSDInterface(fd int, ifIndex int) error {
	// BSD systems typically use different constants for interface binding
	// This is a simplified implementation that may need adjustment per BSD variant
	const IPV6_MULTICAST_IF = 9
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_MULTICAST_IF, ifIndex)
}

// setBSDMSSOption sets the TCP MSS option on BSD systems
func (sm *SocketManager) setBSDMSSOption(fd int, mss int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}

// getBSDMSSOption gets the TCP MSS option on BSD systems
func (sm *SocketManager) getBSDMSSOption(fd int) (int, error) {
	return syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
}

// enableBSDTimestamps enables packet timestamps on BSD systems
func (sm *SocketManager) enableBSDTimestamps(fd int) error {
	// Enable SO_TIMESTAMP for packet timing
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1)
}

// setBSDTOS sets the Type of Service field on BSD systems
func (sm *SocketManager) setBSDTOS(fd int, tos int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
}

// setBSDHopLimit sets the hop limit on BSD systems
func (sm *SocketManager) setBSDHopLimit(fd int, hops int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_UNICAST_HOPS, hops)
}

// setBSDTimeout sets socket timeout options on BSD systems
func (sm *SocketManager) setBSDTimeout(fd int, timeout time.Duration) error {
	tv := syscall.Timeval{
		Sec:  int64(timeout.Seconds()),
		Usec: int32(timeout.Nanoseconds()%1e9) / 1000,
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
}//
 Platform-specific method aliases for generic interface
func (sm *SocketManager) createPlatformRawSocket() (int, error) {
	return sm.createBSDRawSocket()
}

func (sm *SocketManager) createPlatformTCPSocket() (int, error) {
	return sm.createBSDTCPSocket()
}

func (sm *SocketManager) setPlatformSocketOptions(fd int, sockType SocketType) error {
	return sm.setBSDSocketOptions(fd, sockType)
}

func (sm *SocketManager) bindPlatformInterface(fd int, ifIndex int) error {
	return sm.bindBSDInterface(fd, ifIndex)
}

func (sm *SocketManager) setPlatformTimeout(fd int, timeout time.Duration) error {
	return sm.setBSDTimeout(fd, timeout)
}

func (sm *SocketManager) setPlatformMSSOption(fd int, mss int) error {
	return sm.setBSDMSSOption(fd, mss)
}

func (sm *SocketManager) getPlatformMSSOption(fd int) (int, error) {
	return sm.getBSDMSSOption(fd)
}

func (sm *SocketManager) enablePlatformTimestamps(fd int) error {
	return sm.enableBSDTimestamps(fd)
}

func (sm *SocketManager) setPlatformTOS(fd int, tos int) error {
	return sm.setBSDTOS(fd, tos)
}

func (sm *SocketManager) setPlatformHopLimit(fd int, hops int) error {
	return sm.setBSDHopLimit(fd, hops)
}