//go:build darwin

package network

import (
	"syscall"
	"time"
	"unsafe"
)

// Darwin-specific socket constants
const (
	// Socket options for macOS
	IPV6_V6ONLY      = 27
	IPV6_RECVPKTINFO = 61
	IPV6_PKTINFO     = 46
	IPV6_TCLASS      = 36
	IPV6_UNICAST_HOPS = 4
	SO_RECV_ANYIF    = 0x1104
	SO_RCVTIMEO      = 0x1006
	SO_SNDTIMEO      = 0x1005
	
	// TCP options for macOS
	TCP_MAXSEG       = 0x02
	TCP_NODELAY      = 0x01
	TCP_KEEPALIVE    = 0x02
	TCP_KEEPINTVL    = 0x101
	TCP_KEEPCNT      = 0x102
)

// createDarwinRawSocket creates a raw ICMP6 socket on macOS
func (sm *SocketManager) createDarwinRawSocket() (int, error) {
	// Create raw IPv6 ICMP socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_RAW, syscall.IPPROTO_ICMPV6)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}
	
	// Set socket options
	if err := sm.setDarwinSocketOptions(fd, SocketTypeRawICMP6); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	
	return fd, nil
}

// createDarwinTCPSocket creates a TCP IPv6 socket on macOS
func (sm *SocketManager) createDarwinTCPSocket() (int, error) {
	// Create TCP IPv6 socket
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return -1, sm.GetSocketError(err)
	}
	
	// Set socket options
	if err := sm.setDarwinSocketOptions(fd, SocketTypeTCPv6); err != nil {
		syscall.Close(fd)
		return -1, err
	}
	
	return fd, nil
}

// setDarwinSocketOptions sets macOS-specific socket options with enhanced error handling
func (sm *SocketManager) setDarwinSocketOptions(fd int, sockType SocketType) error {
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
		
		// Enable receiving on any interface (macOS specific)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, SO_RECV_ANYIF, 1); err != nil {
			// This is optional, don't fail if not supported
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
		
		// Enable port reuse (macOS specific)
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_REUSEPORT, 1); err != nil {
			// This is optional, don't fail if not supported
		}
		
		// Enable TCP keepalive
		if err := syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_KEEPALIVE, 1); err != nil {
			// Non-fatal, continue without keepalive
		}
		
		// Set TCP keepalive parameters (macOS specific values)
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_KEEPALIVE, 60)    // 60 seconds
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_KEEPINTVL, 10)    // 10 seconds  
		syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_KEEPCNT, 3)       // 3 probes
	}
	
	return nil
}

// bindDarwinInterface binds socket to a specific interface on macOS
func (sm *SocketManager) bindDarwinInterface(fd int, ifIndex int) error {
	// On macOS, we use IP_BOUND_IF for IPv4 and IPV6_BOUND_IF for IPv6
	const IPV6_BOUND_IF = 125
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_BOUND_IF, ifIndex)
}

// setDarwinMSSOption sets the TCP MSS option on macOS
func (sm *SocketManager) setDarwinMSSOption(fd int, mss int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
}

// getDarwinMSSOption gets the TCP MSS option on macOS
func (sm *SocketManager) getDarwinMSSOption(fd int) (int, error) {
	return syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
}

// enableDarwinTimestamps enables packet timestamps on macOS
func (sm *SocketManager) enableDarwinTimestamps(fd int) error {
	// Enable SO_TIMESTAMP for packet timing
	return syscall.SetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_TIMESTAMP, 1)
}

// setDarwinTOS sets the Type of Service field on macOS
func (sm *SocketManager) setDarwinTOS(fd int, tos int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_TCLASS, tos)
}

// setDarwinHopLimit sets the hop limit on macOS
func (sm *SocketManager) setDarwinHopLimit(fd int, hops int) error {
	return syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_UNICAST_HOPS, hops)
}

// setDarwinTimeout sets socket timeout options on macOS
func (sm *SocketManager) setDarwinTimeout(fd int, timeout time.Duration) error {
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
}

// setDarwinAdvancedOptions sets advanced macOS-specific socket options
func (sm *SocketManager) setDarwinAdvancedOptions(fd int, sockType SocketType) error {
	switch sockType {
	case SocketTypeRawICMP6:
		// Set traffic class for QoS
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, IPV6_TCLASS, 0); err != nil {
			// Non-fatal
		}
		
	case SocketTypeTCPv6:
		// Enable TCP_NOPUSH for better performance (macOS specific)
		const TCP_NOPUSH = 4
		if err := syscall.SetsockoptInt(fd, syscall.IPPROTO_TCP, TCP_NOPUSH, 0); err != nil {
			// Non-fatal
		}
	}
	
	return nil
}// Platf
orm-specific method aliases for generic interface
func (sm *SocketManager) createPlatformRawSocket() (int, error) {
	return sm.createDarwinRawSocket()
}

func (sm *SocketManager) createPlatformTCPSocket() (int, error) {
	return sm.createDarwinTCPSocket()
}

func (sm *SocketManager) setPlatformSocketOptions(fd int, sockType SocketType) error {
	return sm.setDarwinSocketOptions(fd, sockType)
}

func (sm *SocketManager) bindPlatformInterface(fd int, ifIndex int) error {
	return sm.bindDarwinInterface(fd, ifIndex)
}

func (sm *SocketManager) setPlatformTimeout(fd int, timeout time.Duration) error {
	return sm.setDarwinTimeout(fd, timeout)
}

func (sm *SocketManager) setPlatformMSSOption(fd int, mss int) error {
	return sm.setDarwinMSSOption(fd, mss)
}

func (sm *SocketManager) getPlatformMSSOption(fd int) (int, error) {
	return sm.getDarwinMSSOption(fd)
}

func (sm *SocketManager) enablePlatformTimestamps(fd int) error {
	return sm.enableDarwinTimestamps(fd)
}

func (sm *SocketManager) setPlatformTOS(fd int, tos int) error {
	return sm.setDarwinTOS(fd, tos)
}

func (sm *SocketManager) setPlatformHopLimit(fd int, hops int) error {
	return sm.setDarwinHopLimit(fd, hops)
}