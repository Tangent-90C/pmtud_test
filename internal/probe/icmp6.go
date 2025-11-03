package probe

import (
	"context"
	"fmt"
	"net"
	"time"

	"ipv6-mtu-discovery/internal/algorithm"
	"ipv6-mtu-discovery/internal/validator"

	"golang.org/x/net/icmp"
)

// debugEnabled controls whether debug output is shown
var debugEnabled = false

// SetDebugMode enables or disables debug output
func SetDebugMode(enabled bool) {
	debugEnabled = enabled
}

// debugf prints debug information only if debug mode is enabled
func debugf(format string, args ...interface{}) {
	if debugEnabled {
		fmt.Printf("DEBUG: "+format, args...)
	}
}

// ICMP6Prober handles ICMP6 MTU probing
type ICMP6Prober struct {
	conn       *icmp.PacketConn
	target     *net.IPAddr
	currentMTU int
	minMTU     int
	maxMTU     int
	probeCount int
	// Simplified unreachability detection
	checker *UnreachabilityChecker
}

// MTUResult represents the result of MTU probing
type MTUResult struct {
	MTUFound       bool
	FinalMTU       int
	ProbeAttempts  int
	PMTUDResponses []PMTUDResponse
	// TCP MSS testing results
	TCPMSSTested bool // Whether TCP MSS was actually tested
	ActualTCPMSS int  // Actual TCP MSS from real connection (0 if not tested)

	// Simplified target unreachability detection results
	IsUnreachable        bool   // Simple unreachable flag
	UnreachabilityReason string // Simple reason string

	// Additional fields for display compatibility
	ReachabilityChecked    bool   // Whether reachability was checked
	TargetReachable        bool   // Whether target is reachable (opposite of IsUnreachable)
	EarlyTermination       bool   // Whether probing was terminated early
	EarlyTerminationReason string // Reason for early termination
}

// PMTUDResponse represents a PMTUD response message
type PMTUDResponse struct {
	Type           int           // ICMP6 message type
	Code           int           // ICMP6 message code
	ReportedMTU    int           // MTU reported by intermediate router (for Packet Too Big)
	RouterAddr     net.IP        // Address of the router that sent the response
	Timestamp      time.Time     // When the response was received
	OriginalPacket []byte        // Original packet that triggered the response (optional)
	PacketSize     int           // Size of the probe packet that generated this response (IPv6 layer)
	RTT            time.Duration // Round-trip time for the probe
}

// NewICMP6Prober creates a new ICMP6 prober with raw socket connection
func NewICMP6Prober(target *validator.IPv6Address) (*ICMP6Prober, error) {
	if target == nil || !target.IsValid {
		return nil, fmt.Errorf("invalid target IPv6 address")
	}

	debugf("NewICMP6Prober - target: %s (valid: %t)\n", target.Original, target.IsValid)

	targetAddr := &net.IPAddr{
		IP: target.IP,
	}

	debugf("Target IP address: %s\n", targetAddr.String())

	// Create raw ICMP6 socket connection
	debugf("Creating ICMP6 socket connection...\n")
	conn, err := icmp.ListenPacket("ip6:ipv6-icmp", "::")
	if err != nil {
		debugf("Failed to create ICMP6 socket: %v\n", err)
		return nil, fmt.Errorf("failed to create ICMP6 socket: %w", err)
	}

	debugf("ICMP6 socket created successfully\n")

	// Create simplified unreachability checker with 5 second timeout
	checker, err := NewUnreachabilityChecker(targetAddr, 5*time.Second)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to create unreachability checker: %w", err)
	}

	return &ICMP6Prober{
		conn:       conn,
		target:     targetAddr,
		minMTU:     68,   // Minimum IPv6 MTU
		maxMTU:     1500, // Standard Ethernet MTU
		currentMTU: 1500, // Start with maximum
		probeCount: 0,
		checker:    checker,
	}, nil
}

// SendProbe sends a single ICMP6 probe packet with specified MTU size
func (p *ICMP6Prober) SendProbe(ctx context.Context, mtuSize int, timeout time.Duration) (*PMTUDResponse, error) {
	if p.conn == nil {
		return nil, fmt.Errorf("prober not initialized")
	}

	p.probeCount++
	sendTime := time.Now()

	debugf("SendProbe - MTU size: %d, probe count: %d, target: %s\n",
		mtuSize, p.probeCount, p.target.String())

	// Create probe packet for the specified MTU
	packet, err := CreateProbePacketForMTU(mtuSize, 1, p.probeCount)
	if err != nil {
		debugf("Failed to create probe packet: %v\n", err)
		return nil, fmt.Errorf("failed to create probe packet: %w", err)
	}

	debugf("Created packet - payload size: %d, total size: %d\n",
		len(packet.Data), packet.GetTotalSize())

	// Send the probe
	err = SendICMP6Probe(p.conn, p.target, packet)
	if err != nil {
		debugf("Failed to send probe: %v\n", err)
		return nil, fmt.Errorf("failed to send probe: %w", err)
	}

	debugf("Probe sent successfully, waiting for response (timeout: %v)\n", timeout)

	// Set read timeout
	deadline := time.Now().Add(timeout)
	err = p.conn.SetReadDeadline(deadline)
	if err != nil {
		debugf("Failed to set read deadline: %v\n", err)
		return nil, fmt.Errorf("failed to set read deadline: %w", err)
	}

	// Wait for response and calculate RTT
	response, err := p.receiveResponse(ctx, timeout)
	if err != nil {
		return nil, err
	}

	// Calculate and set RTT if we got a response
	if response != nil {
		rtt := time.Since(sendTime)
		response.RTT = rtt
		debugf("Probe RTT: %v\n", rtt)
	}

	return response, nil
}

// receiveResponse waits for and processes ICMP6 responses
func (p *ICMP6Prober) receiveResponse(ctx context.Context, timeout time.Duration) (*PMTUDResponse, error) {
	buffer := make([]byte, 1500) // Buffer for receiving responses

	debugf("receiveResponse - waiting for response, timeout: %v\n", timeout)

	for {
		select {
		case <-ctx.Done():
			debugf("Context cancelled while waiting for response\n")
			return nil, ctx.Err()
		default:
		}

		// Read response
		debugf("Attempting to read from connection...\n")
		n, srcAddr, err := p.conn.ReadFrom(buffer)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				debugf("Read timeout occurred after %v\n", timeout)
				return nil, fmt.Errorf("probe timeout")
			}
			debugf("Failed to read response: %v\n", err)
			return nil, fmt.Errorf("failed to read response: %w", err)
		}

		debugf("Received %d bytes from %s\n", n, srcAddr.String())

		// Parse the response
		response, err := ParsePMTUDResponseWithSource(buffer[:n], srcAddr)
		if err != nil {
			debugf("Failed to parse response: %v, continuing...\n", err)
			// Continue reading if we can't parse this response
			continue
		}

		debugf("Parsed response - Type: %d, Code: %d\n", response.Type, response.Code)

		// Validate the response
		err = ValidatePMTUDResponse(response)
		if err != nil {
			debugf("Response validation failed: %v, continuing...\n", err)
			// Continue reading if response is invalid
			continue
		}

		debugf("Valid response received and validated\n")
		return response, nil
	}
}

// ProbeMTU performs complete MTU discovery using binary search
func (p *ICMP6Prober) ProbeMTU(ctx context.Context) (*MTUResult, error) {
	return p.ProbeMTUWithOptions(ctx, 3*time.Second, 2, 60*time.Second)
}

// ProbeMTUWithOptions performs MTU discovery with configurable options
func (p *ICMP6Prober) ProbeMTUWithOptions(ctx context.Context, probeTimeout time.Duration, maxRetries int, totalTimeout time.Duration) (*MTUResult, error) {
	if p.conn == nil {
		return nil, fmt.Errorf("prober not initialized")
	}

	// Create context with total timeout
	probeCtx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	result := &MTUResult{
		PMTUDResponses: make([]PMTUDResponse, 0),
		// Initialize simplified unreachability detection fields
		IsUnreachable:       false,
		ReachabilityChecked: false,
		TargetReachable:     false,
		EarlyTermination:    false,
	}

	// Step 1: Skip pre-validation to avoid false negatives
	// Proceed directly to MTU probing - let the actual probes determine connectivity
	if p.checker != nil {
		debugf("Skipping pre-validation check - proceeding directly to MTU probing\n")
		result.ReachabilityChecked = false
		result.TargetReachable = true // Assume reachable, let MTU probing determine actual connectivity
	}

	// Initialize binary search
	search := algorithm.NewBinarySearch(p.minMTU, p.maxMTU)

	// Perform binary search
	for !search.IsDone() {
		select {
		case <-probeCtx.Done():
			// Context timeout - return partial results if we have any
			debugf("Total timeout reached, returning partial results\n")
			result.ProbeAttempts = p.probeCount
			result.MTUFound = search.HasValidResult()
			result.FinalMTU = search.GetResult()
			return result, nil
		default:
		}

		currentMTU := search.Next()

		// Test the current MTU size
		success, response, err := p.TestMTUSize(probeCtx, currentMTU, probeTimeout, maxRetries)

		if err != nil {
			// Handle probe errors - continue search but record the failure
			search.Update(false)
			continue
		}

		// Record PMTUD responses (only real PMTUD messages, not Echo Replies)
		if response != nil {
			// Set the packet size (IPv6 layer size = MTU being tested)
			response.PacketSize = currentMTU

			// Only record actual PMTUD responses (Packet Too Big, Destination Unreachable, Time Exceeded)
			// Don't record Echo Replies as they are not PMTUD responses
			if response.IsPacketTooBig() || response.IsDestinationUnreachable() || response.IsTimeExceeded() {
				result.PMTUDResponses = append(result.PMTUDResponses, *response)
			}

			// If we got MTU hint from PMTUD, use it
			if response.IsPacketTooBig() && response.ReportedMTU > 0 {
				search.UpdateWithMTUHint(success, response.ReportedMTU)
			} else {
				search.Update(success)
			}
		} else {
			search.Update(success)
		}
	}

	// Finalize results
	result.ProbeAttempts = p.probeCount
	result.MTUFound = search.HasValidResult()
	result.FinalMTU = search.GetResult()

	return result, nil
}

// TestMTUSize tests if a specific MTU size works
func (p *ICMP6Prober) TestMTUSize(ctx context.Context, mtuSize int, timeout time.Duration, maxRetries int) (bool, *PMTUDResponse, error) {
	var lastResponse *PMTUDResponse
	var lastErr error

	for retry := 0; retry < maxRetries; retry++ {
		response, err := p.SendProbe(ctx, mtuSize, timeout)
		if err != nil {
			lastErr = err
			continue
		}

		lastResponse = response

		// Check response type
		if response.IsPacketTooBig() {
			// MTU is too large
			debugf("Received Packet Too Big - MTU %d is too large\n", mtuSize)
			return false, response, nil
		} else if response.IsEchoReply() {
			// Echo reply means the packet got through successfully
			debugf("Received Echo Reply - MTU %d works\n", mtuSize)
			return true, response, nil
		} else if response.IsDestinationUnreachable() || response.IsTimeExceeded() {
			// These might indicate network issues, but not necessarily MTU problems
			// Continue with retries
			debugf("Received error response (Type: %d) - retrying...\n", response.Type)
			continue
		}

		// If we get here with an unknown response type, assume it works
		debugf("Received unknown response type %d - assuming MTU %d works\n", response.Type, mtuSize)
		return true, response, nil
	}

	// If we exhausted retries, assume the MTU doesn't work
	// For timeout errors, we don't return the error since timeout usually means MTU is too large
	if lastErr != nil {
		debugf("All retries failed with error: %v - assuming MTU %d is too large\n", lastErr, mtuSize)
	}
	return false, lastResponse, nil
}

// GetProbeCount returns the number of probes sent
func (p *ICMP6Prober) GetProbeCount() int {
	return p.probeCount
}

// GetTarget returns the target address
func (p *ICMP6Prober) GetTarget() *net.IPAddr {
	return p.target
}

// GetMTURange returns the current MTU search range
func (p *ICMP6Prober) GetMTURange() (int, int) {
	return p.minMTU, p.maxMTU
}

// SetMTURange sets the MTU search range
func (p *ICMP6Prober) SetMTURange(minMTU, maxMTU int) error {
	if minMTU < 68 {
		return fmt.Errorf("minimum MTU cannot be less than 68")
	}
	if maxMTU > 65535 {
		return fmt.Errorf("maximum MTU cannot be greater than 65535")
	}
	if minMTU > maxMTU {
		return fmt.Errorf("minimum MTU cannot be greater than maximum MTU")
	}

	p.minMTU = minMTU
	p.maxMTU = maxMTU
	return nil
}

// Close closes the prober and releases resources
func (p *ICMP6Prober) Close() error {
	var err error
	if p.checker != nil {
		if checkerErr := p.checker.Close(); checkerErr != nil {
			err = checkerErr
		}
	}
	if p.conn != nil {
		if connErr := p.conn.Close(); connErr != nil {
			if err == nil {
				err = connErr
			}
		}
	}
	return err
}

// IsPacketTooBig checks if the response indicates packet too big
func (r *PMTUDResponse) IsPacketTooBig() bool {
	return r.Type == 2 // ICMPv6 Packet Too Big
}

// IsDestinationUnreachable checks if the response indicates destination unreachable
func (r *PMTUDResponse) IsDestinationUnreachable() bool {
	return r.Type == 1 // ICMPv6 Destination Unreachable
}

// IsTimeExceeded checks if the response indicates time exceeded
func (r *PMTUDResponse) IsTimeExceeded() bool {
	return r.Type == 3 // ICMPv6 Time Exceeded
}

// IsEchoReply checks if the response is an echo reply (successful probe)
func (r *PMTUDResponse) IsEchoReply() bool {
	return r.Type == 129 // ICMPv6 Echo Reply
}

// GetMTUInfo returns MTU information if available
func (r *PMTUDResponse) GetMTUInfo() (int, bool) {
	if r.IsPacketTooBig() && r.ReportedMTU > 0 {
		return r.ReportedMTU, true
	}
	return 0, false
}

// String returns a string representation of the PMTUD response
func (r *PMTUDResponse) String() string {
	var typeStr string
	switch r.Type {
	case 1:
		typeStr = "Destination Unreachable"
	case 2:
		typeStr = "Packet Too Big"
	case 3:
		typeStr = "Time Exceeded"
	default:
		typeStr = fmt.Sprintf("Type %d", r.Type)
	}

	result := fmt.Sprintf("ICMP6 %s (Code: %d)", typeStr, r.Code)

	if r.IsPacketTooBig() && r.ReportedMTU > 0 {
		result += fmt.Sprintf(", MTU: %d", r.ReportedMTU)
	}

	if r.RouterAddr != nil && !r.RouterAddr.IsUnspecified() {
		result += fmt.Sprintf(", Router: %s", r.RouterAddr.String())
	}

	return result
}

// ProgressCallback defines the callback function for progress updates
type ProgressCallback func(currentMTU, low, high, iteration int)

// ResultCallback defines the callback function for individual test results
type ResultCallback func(success bool, mtu int, response *PMTUDResponse)

// DiscoverMTUWithCallback performs MTU discovery with progress callback
func (p *ICMP6Prober) DiscoverMTUWithCallback(ctx context.Context, progressCallback ProgressCallback) (*MTUResult, error) {
	return p.DiscoverMTUWithCallbacks(ctx, progressCallback, nil)
}

// DiscoverMTUWithCallbacks performs MTU discovery with both progress and result callbacks
func (p *ICMP6Prober) DiscoverMTUWithCallbacks(ctx context.Context, progressCallback ProgressCallback, resultCallback ResultCallback) (*MTUResult, error) {
	if p.conn == nil {
		return nil, fmt.Errorf("prober not initialized")
	}

	probeTimeout := 1500 * time.Millisecond
	maxRetries := 2
	totalTimeout := 180 * time.Second

	// Create context with total timeout
	probeCtx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()

	// Initialize binary search
	search := algorithm.NewBinarySearch(p.minMTU, p.maxMTU)

	result := &MTUResult{
		PMTUDResponses: make([]PMTUDResponse, 0),
		// Initialize simplified unreachability detection fields
		IsUnreachable:       false,
		ReachabilityChecked: false,
		TargetReachable:     false,
		EarlyTermination:    false,
	}

	// Step 1: Skip pre-validation to avoid false negatives
	// Proceed directly to MTU probing - let the actual probes determine connectivity
	if p.checker != nil {
		debugf("Skipping pre-validation check - proceeding directly to MTU probing\n")
		result.ReachabilityChecked = false
		result.TargetReachable = true // Assume reachable, let MTU probing determine actual connectivity
	}

	// Perform binary search with progress reporting
	for !search.IsDone() {
		select {
		case <-probeCtx.Done():
			// Context timeout - return partial results if we have any
			debugf("Total timeout reached, returning partial results\n")
			result.ProbeAttempts = p.probeCount
			result.MTUFound = search.HasValidResult()
			result.FinalMTU = search.GetResult()
			return result, nil
		default:
		}

		currentMTU := search.Next()
		current, low, high, iterations, _ := search.GetProgress()

		// Report progress
		if progressCallback != nil {
			progressCallback(current, low, high, iterations)
		}

		// Test the current MTU size
		success, response, err := p.TestMTUSize(probeCtx, currentMTU, probeTimeout, maxRetries)

		// Report result callback
		if resultCallback != nil {
			resultCallback(success, currentMTU, response)
		}

		if err != nil {
			// Handle probe errors - continue search but record the failure
			search.Update(false)
			continue
		}

		// Record PMTUD responses (only real PMTUD messages, not Echo Replies)
		if response != nil {
			// Set the packet size (IPv6 layer size = MTU being tested)
			response.PacketSize = currentMTU

			// Only record actual PMTUD responses (Packet Too Big, Destination Unreachable, Time Exceeded)
			// Don't record Echo Replies as they are not PMTUD responses
			if response.IsPacketTooBig() || response.IsDestinationUnreachable() || response.IsTimeExceeded() {
				result.PMTUDResponses = append(result.PMTUDResponses, *response)
			}

			// If we got MTU hint from PMTUD, use it
			if response.IsPacketTooBig() && response.ReportedMTU > 0 {
				search.UpdateWithMTUHint(success, response.ReportedMTU)
			} else {
				search.Update(success)
			}
		} else {
			search.Update(success)
		}
	}

	// Finalize results
	result.ProbeAttempts = p.probeCount
	result.MTUFound = search.HasValidResult()
	result.FinalMTU = search.GetResult()

	return result, nil
}

// QuickMTUTest performs a quick MTU test for a specific size
func (p *ICMP6Prober) QuickMTUTest(ctx context.Context, mtuSize int) (bool, error) {
	success, _, err := p.TestMTUSize(ctx, mtuSize, 3*time.Second, 2)
	return success, err
}

// ValidateMTUResult validates the MTU discovery result
func ValidateMTUResult(result *MTUResult) error {
	if result == nil {
		return fmt.Errorf("result is nil")
	}

	if result.MTUFound {
		if result.FinalMTU < 68 {
			return fmt.Errorf("final MTU too small: %d", result.FinalMTU)
		}
		if result.FinalMTU > 65535 {
			return fmt.Errorf("final MTU too large: %d", result.FinalMTU)
		}
	}

	if result.ProbeAttempts < 0 {
		return fmt.Errorf("invalid probe attempts count: %d", result.ProbeAttempts)
	}

	return nil
}
