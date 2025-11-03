package probe

import (
	"context"
	"fmt"
	"net"
	"time"

	"golang.org/x/net/icmp"
)

// UnreachabilityChecker provides simple IPv6 target reachability checking
// based on Echo Request/Reply mechanism as specified in requirements 4.1-4.3
type UnreachabilityChecker struct {
	conn    *icmp.PacketConn
	target  *net.IPAddr
	timeout time.Duration
}

// NewUnreachabilityChecker creates a new simplified unreachability checker
func NewUnreachabilityChecker(target *net.IPAddr, timeout time.Duration) (*UnreachabilityChecker, error) {
	if target == nil {
		return nil, fmt.Errorf("target address cannot be nil")
	}

	// Create ICMP6 connection for reachability checking
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		return nil, fmt.Errorf("failed to create ICMP6 socket for reachability check: %w", err)
	}

	return &UnreachabilityChecker{
		conn:    conn,
		target:  target,
		timeout: timeout,
	}, nil
}

// IsReachable performs a simple connectivity check using ICMP6 Echo Request/Reply
// Returns true if target responds with Echo Reply, false otherwise
// This implements the simplified detection logic from requirement 4.2
func (uc *UnreachabilityChecker) IsReachable(ctx context.Context) (bool, string, error) {
	debugf("Performing simple reachability check for %s\n", uc.target.String())

	// Create a simple echo request packet (small size for basic connectivity)
	packet, err := CreateProbePacketForMTU(1280, 1, 1)
	if err != nil {
		return false, "Failed to create probe packet", fmt.Errorf("failed to create probe packet: %w", err)
	}

	// Send the echo request
	err = SendICMP6Probe(uc.conn, uc.target, packet)
	if err != nil {
		return false, "Failed to send probe", fmt.Errorf("failed to send probe: %w", err)
	}

	debugf("Echo request sent, waiting for reply (timeout: %v)\n", uc.timeout)

	// Set read timeout
	deadline := time.Now().Add(uc.timeout)
	err = uc.conn.SetReadDeadline(deadline)
	if err != nil {
		return false, "Failed to set timeout", fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Wait for response with retry logic for multiple packets
	buffer := make([]byte, 1500)
	maxAttempts := 3

	for attempt := 0; attempt < maxAttempts; attempt++ {
		debugf("Reading attempt %d/%d\n", attempt+1, maxAttempts)

		n, srcAddr, err := uc.conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				debugf("Read timeout on attempt %d\n", attempt+1)
				if attempt == maxAttempts-1 {
					// Final timeout - target is unreachable
					debugf("All attempts timed out - target unreachable\n")
					return false, "No echo reply received within timeout period", nil
				}
				continue
			}
			return false, "Network error during reachability check", fmt.Errorf("read error: %w", err)
		}

		debugf("Received %d bytes from %s on attempt %d\n", n, srcAddr.String(), attempt+1)

		// Parse and validate the response
		response, err := ParsePMTUDResponseWithSource(buffer[:n], srcAddr)
		if err != nil {
			debugf("Failed to parse response on attempt %d: %v - continuing\n", attempt+1, err)
			// Continue to next attempt if we can't parse this response
			continue
		}

		debugf("Parsed response - Type: %d, Code: %d\n", response.Type, response.Code)

		// Check if we got a successful echo reply
		if response.IsEchoReply() {
			debugf("Echo reply received - target is reachable\n")
			return true, "", nil
		}

		// Log other response types but continue trying
		debugf("Received non-echo response (Type: %d, Code: %d) on attempt %d - continuing\n",
			response.Type, response.Code, attempt+1)
	}

	// If we get here, we didn't receive a valid echo reply after all attempts
	debugf("No valid echo reply received after %d attempts - target unreachable\n", maxAttempts)
	return false, "No echo reply received after multiple attempts", nil
}

// Close closes the unreachability checker and releases resources
func (uc *UnreachabilityChecker) Close() error {
	if uc.conn != nil {
		return uc.conn.Close()
	}
	return nil
}
