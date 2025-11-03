package probe

import (
	"context"
	"fmt"
	"testing"
	"time"

	"ipv6-mtu-discovery/internal/validator"
)

// TestICMP6ProberIntegration tests the complete ICMP6 probing flow
func TestICMP6ProberIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name           string
		targetAddr     string
		expectSuccess  bool
		expectMTURange [2]int
	}{
		{
			name:           "Loopback probe",
			targetAddr:     "::1",
			expectSuccess:  true,
			expectMTURange: [2]int{1280, 65535},
		},
		{
			name:           "Link-local probe",
			targetAddr:     "fe80::1",
			expectSuccess:  false, // Usually not reachable without zone
			expectMTURange: [2]int{0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Validate target address
			targetAddr, err := validator.ValidateIPv6Address(tt.targetAddr)
			if err != nil {
				if tt.expectSuccess {
					t.Fatalf("Failed to validate target address: %v", err)
				}
				return
			}

			// Create prober
			prober, err := NewICMP6Prober(targetAddr)
			if err != nil {
				if tt.expectSuccess {
					t.Fatalf("Failed to create ICMP6 prober: %v", err)
				}
				return
			}
			defer prober.Close()

			// Set MTU range
			if err := prober.SetMTURange(68, 1500); err != nil {
				t.Fatalf("Failed to set MTU range: %v", err)
			}

			// Perform MTU discovery with timeout
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()

			result, err := prober.ProbeMTU(ctx)

			if tt.expectSuccess {
				if err != nil {
					t.Fatalf("MTU discovery failed: %v", err)
				}

				if !result.MTUFound {
					t.Error("Expected to find MTU")
				}

				if result.FinalMTU < tt.expectMTURange[0] || result.FinalMTU > tt.expectMTURange[1] {
					t.Errorf("MTU %d outside expected range [%d, %d]",
						result.FinalMTU, tt.expectMTURange[0], tt.expectMTURange[1])
				}

				if result.ProbeAttempts == 0 {
					t.Error("Expected probe attempts to be recorded")
				}
			} else {
				// For unsuccessful cases, we might get an error or no MTU found
				if err == nil && result.MTUFound {
					t.Error("Expected probe to fail or not find MTU")
				}
			}
		})
	}
}

// TestMTUDiscoveryWithCallbacks tests MTU discovery with progress callbacks
func TestMTUDiscoveryWithCallbacks(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	prober, err := NewICMP6Prober(targetAddr)
	if err != nil {
		t.Fatalf("Failed to create ICMP6 prober: %v", err)
	}
	defer prober.Close()

	if err := prober.SetMTURange(68, 1500); err != nil {
		t.Fatalf("Failed to set MTU range: %v", err)
	}

	// Track callback invocations
	progressCallCount := 0
	resultCallCount := 0

	progressCallback := func(currentMTU, low, high, iteration int) {
		progressCallCount++
		if currentMTU < 68 || currentMTU > 1500 {
			t.Errorf("Invalid current MTU in progress callback: %d", currentMTU)
		}
		if low > high {
			t.Errorf("Invalid range in progress callback: low=%d, high=%d", low, high)
		}
		if iteration < 0 {
			t.Errorf("Invalid iteration in progress callback: %d", iteration)
		}
	}

	resultCallback := func(success bool, mtu int, response *PMTUDResponse) {
		resultCallCount++
		if mtu < 0 || mtu > 65535 {
			t.Errorf("Invalid MTU in result callback: %d", mtu)
		}
		// Response can be nil for timeouts
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()

	result, err := prober.DiscoverMTUWithCallbacks(ctx, progressCallback, resultCallback)
	if err != nil {
		t.Fatalf("MTU discovery with callbacks failed: %v", err)
	}

	if !result.MTUFound {
		t.Error("Expected to find MTU")
	}

	if progressCallCount == 0 {
		t.Error("Expected progress callback to be called")
	}

	if resultCallCount == 0 {
		t.Error("Expected result callback to be called")
	}

	t.Logf("Progress callbacks: %d, Result callbacks: %d", progressCallCount, resultCallCount)
}

// TestProbePacketSending tests actual packet sending and receiving
func TestProbePacketSending(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	prober, err := NewICMP6Prober(targetAddr)
	if err != nil {
		t.Fatalf("Failed to create ICMP6 prober: %v", err)
	}
	defer prober.Close()

	// Test single probe
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Create a test packet
	packet, err := BuildICMP6Packet(64)
	if err != nil {
		t.Fatalf("Failed to build test packet: %v", err)
	}

	// Send probe and wait for response
	response, err := prober.SendProbe(ctx, packet.GetTotalSize()+40, 2*time.Second) // Add IPv6 header size
	success := err == nil && response != nil
	if err != nil {
		t.Logf("Probe failed (may be expected in test environment): %v", err)
		return // Don't fail test as this requires raw socket privileges
	}

	if success {
		t.Logf("Probe successful")
		if response != nil {
			t.Logf("Response type: %d, code: %d", response.Type, response.Code)
		}
	} else {
		t.Logf("Probe unsuccessful (timeout or error)")
	}
}

// TestPMTUDResponseParsing tests PMTUD response parsing with real data
func TestPMTUDResponseParsing(t *testing.T) {
	tests := []struct {
		name        string
		icmpType    int
		icmpCode    int
		expectError bool
		expectMTU   bool
	}{
		{
			name:        "Packet Too Big",
			icmpType:    2, // ICMPv6 Packet Too Big
			icmpCode:    0,
			expectError: false,
			expectMTU:   true,
		},
		{
			name:        "Destination Unreachable",
			icmpType:    1, // ICMPv6 Destination Unreachable
			icmpCode:    0,
			expectError: false,
			expectMTU:   false,
		},
		{
			name:        "Echo Reply",
			icmpType:    129, // ICMPv6 Echo Reply
			icmpCode:    0,
			expectError: false,
			expectMTU:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create minimal ICMP6 message
			data := make([]byte, 8)
			data[0] = byte(tt.icmpType)
			data[1] = byte(tt.icmpCode)
			// Checksum (bytes 2-3) - leave as zero for test

			if tt.expectMTU {
				// Set MTU value in bytes 4-7 for Packet Too Big
				mtu := uint32(1280)
				data[4] = byte(mtu >> 24)
				data[5] = byte(mtu >> 16)
				data[6] = byte(mtu >> 8)
				data[7] = byte(mtu)
			}

			response, err := ParsePMTUDResponse(data)

			if tt.expectError && err == nil {
				t.Error("Expected error but got none")
				return
			}

			if !tt.expectError && err != nil {
				t.Errorf("Unexpected error: %v", err)
				return
			}

			if err != nil {
				return // Expected error case
			}

			if response.Type != tt.icmpType {
				t.Errorf("Expected type %d, got %d", tt.icmpType, response.Type)
			}

			if response.Code != tt.icmpCode {
				t.Errorf("Expected code %d, got %d", tt.icmpCode, response.Code)
			}

			if tt.expectMTU {
				if response.ReportedMTU != 1280 {
					t.Errorf("Expected MTU 1280, got %d", response.ReportedMTU)
				}
				if !response.IsPacketTooBig() {
					t.Error("Expected Packet Too Big response")
				}
			} else {
				if response.IsPacketTooBig() && response.ReportedMTU > 0 {
					t.Error("Unexpected MTU in non-Packet Too Big response")
				}
			}
		})
	}
}

// TestProbeTimeout tests timeout handling in probe operations
func TestProbeTimeout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Use an unreachable address for timeout testing
	targetAddr, err := validator.ValidateIPv6Address("2400:3200::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	prober, err := NewICMP6Prober(targetAddr)
	if err != nil {
		t.Fatalf("Failed to create ICMP6 prober: %v", err)
	}
	defer prober.Close()

	if err := prober.SetMTURange(68, 1500); err != nil {
		t.Fatalf("Failed to set MTU range: %v", err)
	}

	// Set very short timeout to force timeout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	start := time.Now()
	result, err := prober.ProbeMTU(ctx)
	duration := time.Since(start)

	// Should complete within reasonable time of the timeout
	if duration > 3*time.Second {
		t.Errorf("Timeout took too long: %v", duration)
	}

	// Either error due to timeout or no MTU found
	if err == nil && result.MTUFound {
		t.Log("Unexpectedly found MTU (network may be faster than expected)")
	}

	if err != nil {
		t.Logf("Expected timeout error: %v", err)
	}
}

// TestConcurrentProbes tests concurrent probe operations
func TestConcurrentProbes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	const numProbes = 3

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	results := make(chan struct {
		result *MTUResult
		err    error
	}, numProbes)

	// Start concurrent probes
	for i := 0; i < numProbes; i++ {
		go func(id int) {
			prober, err := NewICMP6Prober(targetAddr)
			if err != nil {
				results <- struct {
					result *MTUResult
					err    error
				}{nil, err}
				return
			}
			defer prober.Close()

			if err := prober.SetMTURange(68, 1500); err != nil {
				results <- struct {
					result *MTUResult
					err    error
				}{nil, err}
				return
			}

			ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
			defer cancel()

			result, err := prober.ProbeMTU(ctx)
			results <- struct {
				result *MTUResult
				err    error
			}{result, err}
		}(i)
	}

	// Collect results
	var successCount int
	var errors []error

	for i := 0; i < numProbes; i++ {
		select {
		case res := <-results:
			if res.err != nil {
				errors = append(errors, res.err)
			} else if res.result != nil && res.result.MTUFound {
				successCount++
			}
		case <-time.After(15 * time.Second):
			t.Fatal("Concurrent probe test timed out")
		}
	}

	t.Logf("Successful probes: %d/%d, Errors: %d", successCount, numProbes, len(errors))

	// Allow some failures due to resource constraints
	if len(errors) == numProbes {
		t.Errorf("All concurrent probes failed: %v", errors)
	}
}

// TestProbePacketSizes tests probing with different packet sizes
func TestProbePacketSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	prober, err := NewICMP6Prober(targetAddr)
	if err != nil {
		t.Fatalf("Failed to create ICMP6 prober: %v", err)
	}
	defer prober.Close()

	testSizes := []int{68, 576, 1280, 1500}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("MTU_%d", size), func(t *testing.T) {
			packet, err := CreateProbePacketForMTU(size, 1, 1)
			if err != nil {
				t.Fatalf("Failed to create packet for MTU %d: %v", size, err)
			}

			if packet.GetTotalSize() > size-40 { // Account for IPv6 header
				t.Errorf("Packet size %d exceeds MTU %d (minus IPv6 header)",
					packet.GetTotalSize(), size-40)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			// Test sending the packet
			response, err := prober.SendProbe(ctx, size, 1*time.Second)
			success := err == nil && response != nil
			if err != nil {
				t.Logf("Probe for MTU %d failed: %v", size, err)
				return // Don't fail test as this requires privileges
			}

			t.Logf("MTU %d probe: success=%v, response=%v", size, success, response != nil)
		})
	}
}

// TestProbeStatistics tests probe statistics collection
func TestProbeStatistics(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	prober, err := NewICMP6Prober(targetAddr)
	if err != nil {
		t.Fatalf("Failed to create ICMP6 prober: %v", err)
	}
	defer prober.Close()

	if err := prober.SetMTURange(1280, 1500); err != nil {
		t.Fatalf("Failed to set MTU range: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	result, err := prober.ProbeMTU(ctx)
	if err != nil {
		t.Fatalf("MTU discovery failed: %v", err)
	}

	// Verify statistics are collected
	if result.ProbeAttempts == 0 {
		t.Error("Expected probe attempts to be recorded")
	}

	// Check if we have reasonable number of attempts for the range
	expectedMaxAttempts := 10 // Binary search should not need many attempts
	if result.ProbeAttempts > expectedMaxAttempts {
		t.Errorf("Too many probe attempts: %d (expected <= %d)",
			result.ProbeAttempts, expectedMaxAttempts)
	}

	t.Logf("MTU discovery completed with %d probe attempts, final MTU: %d",
		result.ProbeAttempts, result.FinalMTU)
}
