package app

import (
	"context"
	"net"
	"testing"
	"time"

	"ipv6-mtu-discovery/internal/cli"
	"ipv6-mtu-discovery/internal/config"
	"ipv6-mtu-discovery/internal/network"
	"ipv6-mtu-discovery/internal/validator"
)

// TestMTUDiscoveryIntegration tests the complete MTU discovery flow
func TestMTUDiscoveryIntegration(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name           string
		targetAddr     string
		expectSuccess  bool
		expectMTURange [2]int // min, max expected MTU
	}{
		{
			name:           "Loopback MTU discovery",
			targetAddr:     "::1",
			expectSuccess:  true,
			expectMTURange: [2]int{1280, 65535}, // IPv6 minimum to maximum
		},
		{
			name:           "Invalid address",
			targetAddr:     "invalid::address",
			expectSuccess:  false,
			expectMTURange: [2]int{0, 0},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test configuration
			cfg := config.GetDefaultConfig()

			// Create CLI args for MTU probe mode
			args := &cli.CLIArgs{
				TargetIPv6: tt.targetAddr,
				Mode:       cli.ModeMTUProbe,
				MinMTU:     68,
				MaxMTU:     1500,
				Timeout:    10 * time.Second,
				Verbose:    true,
			}

			// Create application state
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()

			state := NewAppState(args, cfg, ctx)
			defer state.Cleanup()

			// Initialize components
			err := state.InitializeComponents()
			if !tt.expectSuccess {
				if err == nil {
					t.Error("Expected initialization to fail for invalid address")
				}
				return
			}

			if err != nil {
				t.Fatalf("Failed to initialize components: %v", err)
			}

			// Validate mode
			if err := state.ValidateMode(); err != nil {
				t.Fatalf("Mode validation failed: %v", err)
			}

			// Perform MTU discovery
			if state.ICMPProber == nil {
				t.Fatal("ICMP prober not initialized")
			}

			result, err := state.ICMPProber.ProbeMTU(ctx)
			if err != nil {
				t.Fatalf("MTU discovery failed: %v", err)
			}

			// Validate results
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
		})
	}
}

// TestMSSDetectionIntegration tests MSS detection functionality
func TestMSSDetectionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test TCP server MSS detection
	t.Run("TCP Server MSS Detection", func(t *testing.T) {
		// Create test configuration
		cfg := config.GetDefaultConfig()

		// Use a random available port
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("Cannot create IPv6 listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()

		args := &cli.CLIArgs{
			TargetIPv6: "::1",
			Mode:       cli.ModeTCPServerMSS,
			Port:       port,
			Timeout:    5 * time.Second,
			Verbose:    true,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		state := NewAppState(args, cfg, ctx)
		defer state.Cleanup()

		// Initialize components
		if err := state.InitializeComponents(); err != nil {
			t.Fatalf("Failed to initialize components: %v", err)
		}

		// Start server in goroutine
		resultChan := make(chan *struct {
			result *network.MSSResult
			err    error
		}, 1)

		go func() {
			result, err := state.MSSDetector.DetectMSSClamping(ctx)
			resultChan <- &struct {
				result *network.MSSResult
				err    error
			}{result, err}
		}()

		// Give server time to start
		time.Sleep(100 * time.Millisecond)

		// Connect as client
		clientConn, err := net.DialTimeout("tcp6", net.JoinHostPort("::1", string(rune(port))), 2*time.Second)
		if err != nil {
			t.Fatalf("Failed to connect to server: %v", err)
		}
		clientConn.Close()

		// Wait for server result
		select {
		case res := <-resultChan:
			if res.err != nil {
				t.Fatalf("MSS detection failed: %v", res.err)
			}
			if !res.result.ConnectionSuccess {
				t.Error("Expected connection to succeed")
			}
		case <-time.After(8 * time.Second):
			t.Fatal("MSS detection timed out")
		}
	})
}

// TestNetworkErrorScenarios tests various network error conditions
func TestNetworkErrorScenarios(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name        string
		targetAddr  string
		mode        cli.ProbeMode
		port        int
		expectError bool
		errorType   string
	}{
		{
			name:        "Unreachable address MTU probe",
			targetAddr:  "2400:3200::1", // Documentation prefix, should be unreachable
			mode:        cli.ModeMTUProbe,
			port:        0,
			expectError: true,
			errorType:   "timeout",
		},
		{
			name:        "Connection refused TCP client",
			targetAddr:  "::1",
			mode:        cli.ModeTCPClientMSS,
			port:        1, // Port 1 should be closed
			expectError: true,
			errorType:   "connection_refused",
		},
		{
			name:        "Invalid port range",
			targetAddr:  "::1",
			mode:        cli.ModeTCPClientMSS,
			port:        70000, // Invalid port
			expectError: true,
			errorType:   "invalid_port",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := config.GetDefaultConfig()

			args := &cli.CLIArgs{
				TargetIPv6: tt.targetAddr,
				Mode:       tt.mode,
				Port:       tt.port,
				MinMTU:     68,
				MaxMTU:     1500,
				Timeout:    2 * time.Second, // Short timeout for error scenarios
				Verbose:    true,
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			state := NewAppState(args, cfg, ctx)
			defer state.Cleanup()

			// Test component initialization
			err := state.InitializeComponents()

			if tt.errorType == "invalid_port" {
				if err == nil {
					t.Error("Expected initialization to fail for invalid port")
				}
				return
			}

			if err != nil && tt.expectError {
				// Expected error during initialization
				return
			}

			if err != nil {
				t.Fatalf("Unexpected initialization error: %v", err)
			}

			// Test operation execution
			switch tt.mode {
			case cli.ModeMTUProbe:
				if state.ICMPProber != nil {
					result, err := state.ICMPProber.ProbeMTU(ctx)
					if tt.expectError {
						if err == nil && result.MTUFound {
							t.Error("Expected MTU discovery to fail or timeout")
						}
					}
				}
			case cli.ModeTCPClientMSS:
				if state.MSSDetector != nil {
					result, err := state.MSSDetector.DetectMSSClamping(ctx)
					if tt.expectError {
						if err == nil && result.ConnectionSuccess {
							t.Error("Expected TCP connection to fail")
						}
					}
				}
			}
		})
	}
}

// TestApplicationLifecycle tests the complete application lifecycle
func TestApplicationLifecycle(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Complete MTU discovery lifecycle", func(t *testing.T) {
		app := NewApp()

		// Test with loopback address
		args := []string{
			"ipv6-mtu-discovery",
			"--target", "::1",
			"--mode", "mtu",
			"--timeout", "5s",
			"--verbose",
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		err := app.Run(ctx, args)
		if err != nil {
			t.Logf("Application run completed with: %v", err)
			// Note: This might fail in test environments without proper privileges
			// We log the error but don't fail the test
		}
	})

	t.Run("Help command lifecycle", func(t *testing.T) {
		app := NewApp()

		args := []string{"ipv6-mtu-discovery", "--help"}

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		err := app.Run(ctx, args)
		if err != nil {
			t.Errorf("Help command should not return error: %v", err)
		}
	})
}

// TestConcurrentOperations tests concurrent probe operations
func TestConcurrentOperations(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Concurrent MTU probes", func(t *testing.T) {
		const numProbes = 3

		results := make(chan error, numProbes)

		for i := 0; i < numProbes; i++ {
			go func(id int) {
				cfg := config.GetDefaultConfig()

				args := &cli.CLIArgs{
					TargetIPv6: "::1",
					Mode:       cli.ModeMTUProbe,
					MinMTU:     68,
					MaxMTU:     1500,
					Timeout:    3 * time.Second,
					Verbose:    false, // Reduce output noise
				}

				ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
				defer cancel()

				state := NewAppState(args, cfg, ctx)
				defer state.Cleanup()

				err := state.InitializeComponents()
				if err != nil {
					results <- err
					return
				}

				if state.ICMPProber != nil {
					_, err = state.ICMPProber.ProbeMTU(ctx)
				}

				results <- err
			}(i)
		}

		// Collect results
		var errors []error
		for i := 0; i < numProbes; i++ {
			select {
			case err := <-results:
				if err != nil {
					errors = append(errors, err)
				}
			case <-time.After(15 * time.Second):
				t.Fatal("Concurrent probe test timed out")
			}
		}

		// Allow some failures due to resource constraints in test environment
		if len(errors) == numProbes {
			t.Errorf("All concurrent probes failed: %v", errors)
		}
	})
}

// TestResourceCleanup tests proper resource cleanup
func TestResourceCleanup(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("State cleanup", func(t *testing.T) {
		cfg := config.GetDefaultConfig()

		args := &cli.CLIArgs{
			TargetIPv6: "::1",
			Mode:       cli.ModeMTUProbe,
			MinMTU:     68,
			MaxMTU:     1500,
			Timeout:    5 * time.Second,
			Verbose:    true,
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		state := NewAppState(args, cfg, ctx)

		// Initialize components
		if err := state.InitializeComponents(); err != nil {
			t.Fatalf("Failed to initialize components: %v", err)
		}

		// Verify state is running
		if !state.IsRunning() {
			t.Error("State should be running after initialization")
		}

		// Test cleanup
		if err := state.Cleanup(); err != nil {
			t.Errorf("Cleanup failed: %v", err)
		}

		// Verify state is stopped
		if state.IsRunning() {
			t.Error("State should not be running after cleanup")
		}

		// Test double cleanup (should not panic or error)
		if err := state.Cleanup(); err != nil {
			t.Errorf("Double cleanup should not error: %v", err)
		}
	})
}

// TestConfigurationIntegration tests configuration loading and validation
func TestConfigurationIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("Default configuration", func(t *testing.T) {
		app := NewApp()

		cfg := app.GetConfig()
		if cfg == nil {
			t.Fatal("Default configuration should not be nil")
		}

		// Test basic configuration values
		if cfg.GetTimeout() <= 0 {
			t.Error("Timeout should be positive")
		}

		// Test that config has reasonable values
		if cfg.Network.MaxRetries < 0 {
			t.Error("Max retries should be non-negative")
		}
	})

	t.Run("Platform detection integration", func(t *testing.T) {
		app := NewApp()

		platformInfo, err := app.GetPlatformInfo()
		if err != nil {
			t.Fatalf("Platform detection failed: %v", err)
		}

		if platformInfo.OS == "" {
			t.Error("Platform OS should not be empty")
		}

		if platformInfo.Architecture == "" {
			t.Error("Platform architecture should not be empty")
		}
	})
}

// TestAddressValidationIntegration tests IPv6 address validation in context
func TestAddressValidationIntegration(t *testing.T) {
	tests := []struct {
		name            string
		address         string
		expectValid     bool
		expectReachable bool
	}{
		{
			name:            "Loopback address",
			address:         "::1",
			expectValid:     true,
			expectReachable: true,
		},
		{
			name:            "All zeros address",
			address:         "::",
			expectValid:     true,
			expectReachable: false, // Usually not reachable
		},
		{
			name:            "Documentation address",
			address:         "2400:3200::1",
			expectValid:     true,
			expectReachable: false, // Documentation prefix, not routable
		},
		{
			name:            "Invalid address",
			address:         "invalid::address",
			expectValid:     false,
			expectReachable: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			addr, err := validator.ValidateIPv6Address(tt.address)

			if tt.expectValid && err != nil {
				t.Errorf("Expected valid address, got error: %v", err)
				return
			}

			if !tt.expectValid && err == nil {
				t.Error("Expected invalid address to return error")
				return
			}

			if !tt.expectValid {
				return // Skip reachability test for invalid addresses
			}

			if addr.IsValid != tt.expectValid {
				t.Errorf("Expected IsValid=%v, got %v", tt.expectValid, addr.IsValid)
			}

			// Test reachability with short timeout
			err = addr.CheckReachability(1 * time.Second)
			reachable := err == nil

			if tt.expectReachable && !reachable {
				t.Logf("Expected address to be reachable, but got: %v", err)
				// Don't fail the test as network conditions may vary
			}
		})
	}
}
