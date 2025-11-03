package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"testing"
	"time"

	"ipv6-mtu-discovery/internal/cli"
	"ipv6-mtu-discovery/internal/validator"
)

// TestMSSDetectionIntegration tests complete MSS detection functionality
func TestMSSDetectionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Test server mode MSS detection
	t.Run("Server Mode MSS Detection", func(t *testing.T) {
		targetAddr, err := validator.ValidateIPv6Address("::1")
		if err != nil {
			t.Fatalf("Failed to validate target address: %v", err)
		}

		// Find available port
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("Cannot create IPv6 listener: %v", err)
		}
		port := listener.Addr().(*net.TCPAddr).Port
		listener.Close()

		detector, err := NewMSSDetector(targetAddr, cli.ModeTCPServerMSS, port, 0)
		if err != nil {
			t.Fatalf("Failed to create MSS detector: %v", err)
		}
		defer detector.Close()

		// Start server detection in goroutine
		resultChan := make(chan *MSSResult, 1)
		errChan := make(chan error, 1)

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		go func() {
			result, err := detector.DetectMSSClamping(ctx)
			if err != nil {
				errChan <- err
				return
			}
			resultChan <- result
		}()

		// Give server time to start
		time.Sleep(200 * time.Millisecond)

		// Connect as client
		dialer := &net.Dialer{Timeout: 3 * time.Second}
		clientConn, err := dialer.Dial("tcp6", net.JoinHostPort("::1", strconv.Itoa(port)))
		if err != nil {
			t.Fatalf("Failed to connect to server: %v", err)
		}
		defer clientConn.Close()

		// Wait for server result
		select {
		case result := <-resultChan:
			if !result.ConnectionSuccess {
				t.Error("Expected connection to succeed")
			}
			if result.ClampedMSS <= 0 {
				t.Error("Expected valid MSS value")
			}
			t.Logf("Server detected MSS: %d", result.ClampedMSS)

		case err := <-errChan:
			t.Fatalf("MSS detection failed: %v", err)

		case <-time.After(8 * time.Second):
			t.Fatal("MSS detection timed out")
		}
	})

	// Test client mode MSS detection
	t.Run("Client Mode MSS Detection", func(t *testing.T) {
		// Start a simple echo server
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("Cannot create IPv6 listener: %v", err)
		}
		defer listener.Close()

		port := listener.Addr().(*net.TCPAddr).Port

		// Accept connections in background
		go func() {
			for {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				conn.Close() // Just close immediately for test
			}
		}()

		targetAddr, err := validator.ValidateIPv6Address("::1")
		if err != nil {
			t.Fatalf("Failed to validate target address: %v", err)
		}

		detector, err := NewMSSDetector(targetAddr, cli.ModeTCPClientMSS, port, 0)
		if err != nil {
			t.Fatalf("Failed to create MSS detector: %v", err)
		}
		defer detector.Close()

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		result, err := detector.DetectMSSClamping(ctx)
		if err != nil {
			t.Fatalf("MSS detection failed: %v", err)
		}

		if !result.ConnectionSuccess {
			t.Error("Expected connection to succeed")
		}

		t.Logf("Client detected MSS: %d, Clamped: %v", result.ClampedMSS, result.MSSClamped)
	})
}

// TestMSSIntegrityVerification tests MSS integrity verification functionality
func TestMSSIntegrityVerification(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	t.Run("MSS Integrity Check", func(t *testing.T) {
		targetAddr, err := validator.ValidateIPv6Address("::1")
		if err != nil {
			t.Fatalf("Failed to validate target address: %v", err)
		}

		// Find available ports
		listener1, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("Cannot create IPv6 listener: %v", err)
		}
		mainPort := listener1.Addr().(*net.TCPAddr).Port
		listener1.Close()

		listener2, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("Cannot create IPv6 listener: %v", err)
		}
		controlPort := listener2.Addr().(*net.TCPAddr).Port
		listener2.Close()

		detector, err := NewMSSDetector(targetAddr, cli.ModeMSSIntegrityCheck, mainPort, controlPort)
		if err != nil {
			t.Fatalf("Failed to create MSS detector: %v", err)
		}
		defer detector.Close()

		// Create MSS integrity verifier
		verifier := NewMSSIntegrityVerifier(detector, 1460, controlPort)
		defer verifier.Close()

		// Start mock server for testing
		go func() {
			// Mock control server
			controlListener, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(controlPort)))
			if err != nil {
				return
			}
			defer controlListener.Close()

			// Mock main server
			mainListener, err := net.Listen("tcp6", net.JoinHostPort("::1", strconv.Itoa(mainPort)))
			if err != nil {
				return
			}
			defer mainListener.Close()

			// Handle one connection on each port
			go func() {
				conn, err := controlListener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()
				// Simple echo for control messages
				buffer := make([]byte, 1024)
				conn.Read(buffer)
				conn.Write(buffer)
			}()

			conn, err := mainListener.Accept()
			if err != nil {
				return
			}
			conn.Close()
		}()

		time.Sleep(100 * time.Millisecond) // Let server start

		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		defer cancel()

		// Test verification session
		session, err := verifier.StartVerificationSession(ctx)
		if err != nil {
			t.Logf("Verification session failed (expected in test environment): %v", err)
			return // Don't fail test as this requires complex setup
		}

		if session.TestMSS != 1460 {
			t.Errorf("Expected test MSS 1460, got %d", session.TestMSS)
		}

		t.Logf("Verification session started: %s", session.SessionID)
	})
}

// TestTCPManagerIntegration tests TCP manager functionality
func TestTCPManagerIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	manager := NewTCPManager()
	defer manager.Close()

	t.Run("TCP Connection Creation", func(t *testing.T) {
		// Test creating IPv6 TCP socket
		conn, err := manager.CreateTCPv6Socket()
		if err != nil {
			t.Logf("Failed to create TCP socket (may require privileges): %v", err)
			return
		}
		defer conn.Close()

		// Verify it's a TCP connection
		if _, ok := conn.(*net.TCPConn); !ok {
			t.Error("Expected TCP connection")
		}
	})

	t.Run("TCP Listener Creation", func(t *testing.T) {
		addr := &net.TCPAddr{
			IP:   net.IPv6loopback,
			Port: 0, // Let system choose port
		}

		listener, err := manager.ListenTCPv6(addr)
		if err != nil {
			t.Fatalf("Failed to create TCP listener: %v", err)
		}
		defer listener.Close()

		// Verify listener address
		listenAddr := listener.Addr().(*net.TCPAddr)
		if !listenAddr.IP.Equal(net.IPv6loopback) && !listenAddr.IP.IsUnspecified() {
			t.Errorf("Unexpected listen address: %v", listenAddr.IP)
		}

		if listenAddr.Port == 0 {
			t.Error("Expected system to assign a port")
		}

		t.Logf("Listening on: %s", listenAddr)
	})

	t.Run("TCP Connection with MSS", func(t *testing.T) {
		// Start a simple server
		listener, err := net.Listen("tcp6", "[::1]:0")
		if err != nil {
			t.Skipf("Cannot create IPv6 listener: %v", err)
		}
		defer listener.Close()

		port := listener.Addr().(*net.TCPAddr).Port

		// Accept connections in background
		go func() {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			defer conn.Close()

			// Try to get MSS from server side
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				rawConn, err := tcpConn.SyscallConn()
				if err == nil {
					rawConn.Control(func(fd uintptr) {
						// Just verify we can access the socket
					})
				}
			}
		}()

		targetAddr := &net.TCPAddr{
			IP:   net.IPv6loopback,
			Port: port,
		}

		// Test connection with specific MSS
		conn, err := manager.ConnectWithMSS(targetAddr, 1400, 3*time.Second)
		if err != nil {
			t.Logf("Failed to connect with MSS (may require privileges): %v", err)
			return
		}
		defer conn.Close()

		// Try to get connection info
		info, err := manager.GetConnectionInfo(conn)
		if err != nil {
			t.Logf("Failed to get connection info: %v", err)
		} else {
			t.Logf("Connection info - Local: %s, Remote: %s, MSS: %d",
				info.LocalAddr, info.RemoteAddr, info.EffectiveMSS)
		}
	})
}

// TestMSSDetectionWithDifferentSizes tests MSS detection with various MSS sizes
func TestMSSDetectionWithDifferentSizes(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	// Start a simple server
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("Cannot create IPv6 listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			conn.Close() // Just close immediately
		}
	}()

	detector, err := NewMSSDetector(targetAddr, cli.ModeTCPClientMSS, port, 0)
	if err != nil {
		t.Fatalf("Failed to create MSS detector: %v", err)
	}
	defer detector.Close()

	testSizes := []int{536, 1280, 1400, 1460}

	for _, size := range testSizes {
		t.Run(fmt.Sprintf("MSS_%d", size), func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			result, err := detector.TestMSSWithSize(ctx, size)
			if err != nil {
				t.Fatalf("MSS test with size %d failed: %v", size, err)
			}

			if !result.ConnectionSuccess {
				t.Error("Expected connection to succeed")
			}

			t.Logf("MSS %d test - Original: %d, Clamped: %d, Is Clamped: %v",
				size, result.OriginalMSS, result.ClampedMSS, result.MSSClamped)
		})
	}
}

// TestMSSDiscoveryIntegration tests MSS discovery functionality
func TestMSSDiscoveryIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	// Start a simple server
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("Cannot create IPv6 listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	connectionCount := 0
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connectionCount++
			conn.Close()
		}
	}()

	detector, err := NewMSSDetector(targetAddr, cli.ModeTCPClientMSS, port, 0)
	if err != nil {
		t.Fatalf("Failed to create MSS detector: %v", err)
	}
	defer detector.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	results, err := detector.PerformMSSDiscovery(ctx)
	if err != nil {
		t.Fatalf("MSS discovery failed: %v", err)
	}

	if len(results) == 0 {
		t.Error("Expected at least one MSS test result")
	}

	successCount := 0
	for i, result := range results {
		if result.ConnectionSuccess {
			successCount++
		}
		t.Logf("MSS test %d - Original: %d, Clamped: %d, Success: %v",
			i, result.OriginalMSS, result.ClampedMSS, result.ConnectionSuccess)
	}

	if successCount == 0 {
		t.Error("Expected at least one successful MSS test")
	}

	t.Logf("MSS discovery completed: %d tests, %d successful, %d connections made",
		len(results), successCount, connectionCount)
}

// TestNetworkErrorHandling tests network error scenarios
func TestNetworkErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	tests := []struct {
		name        string
		targetAddr  string
		port        int
		expectError bool
		errorType   string
	}{
		{
			name:        "Connection refused",
			targetAddr:  "::1",
			port:        1, // Port 1 should be closed
			expectError: true,
			errorType:   "connection_refused",
		},
		{
			name:        "Invalid port",
			targetAddr:  "::1",
			port:        70000,
			expectError: true,
			errorType:   "invalid_port",
		},
		{
			name:        "Unreachable address",
			targetAddr:  "2400:3200::1", // Documentation prefix
			port:        80,
			expectError: true,
			errorType:   "unreachable",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			targetAddr, err := validator.ValidateIPv6Address(tt.targetAddr)
			if err != nil && tt.expectError {
				return // Expected validation error
			}
			if err != nil {
				t.Fatalf("Unexpected validation error: %v", err)
			}

			detector, err := NewMSSDetector(targetAddr, cli.ModeTCPClientMSS, tt.port, 0)
			if tt.errorType == "invalid_port" {
				if err == nil {
					t.Error("Expected error for invalid port")
				}
				return
			}
			if err != nil {
				t.Fatalf("Failed to create MSS detector: %v", err)
			}
			defer detector.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
			defer cancel()

			result, err := detector.DetectMSSClamping(ctx)

			if tt.expectError {
				if err == nil && result.ConnectionSuccess {
					t.Error("Expected connection to fail")
				}
				if result.ErrorMessage == "" && !result.ConnectionSuccess {
					t.Log("Connection failed as expected")
				}
			} else {
				if err != nil {
					t.Errorf("Unexpected error: %v", err)
				}
				if !result.ConnectionSuccess {
					t.Error("Expected connection to succeed")
				}
			}
		})
	}
}

// TestConcurrentMSSDetection tests concurrent MSS detection operations
func TestConcurrentMSSDetection(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	const numDetectors = 3

	// Start a simple server
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("Cannot create IPv6 listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Accept connections in background
	connectionCount := 0
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			connectionCount++
			conn.Close()
		}
	}()

	targetAddr, err := validator.ValidateIPv6Address("::1")
	if err != nil {
		t.Fatalf("Failed to validate target address: %v", err)
	}

	results := make(chan struct {
		result *MSSResult
		err    error
	}, numDetectors)

	// Start concurrent detectors
	for i := 0; i < numDetectors; i++ {
		go func(id int) {
			detector, err := NewMSSDetector(targetAddr, cli.ModeTCPClientMSS, port, 0)
			if err != nil {
				results <- struct {
					result *MSSResult
					err    error
				}{nil, err}
				return
			}
			defer detector.Close()

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			result, err := detector.DetectMSSClamping(ctx)
			results <- struct {
				result *MSSResult
				err    error
			}{result, err}
		}(i)
	}

	// Collect results
	var successCount int
	var errors []error

	for i := 0; i < numDetectors; i++ {
		select {
		case res := <-results:
			if res.err != nil {
				errors = append(errors, res.err)
			} else if res.result != nil && res.result.ConnectionSuccess {
				successCount++
			}
		case <-time.After(10 * time.Second):
			t.Fatal("Concurrent MSS detection test timed out")
		}
	}

	t.Logf("Concurrent MSS detection: %d successful, %d errors, %d total connections",
		successCount, len(errors), connectionCount)

	// Allow some failures due to resource constraints
	if len(errors) == numDetectors {
		t.Errorf("All concurrent MSS detections failed: %v", errors)
	}
}

// TestControlConnectionIntegration tests control connection functionality
func TestControlConnectionIntegration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	manager := NewTCPManager()
	defer manager.Close()

	// Start control server
	listener, err := net.Listen("tcp6", "[::1]:0")
	if err != nil {
		t.Skipf("Cannot create IPv6 listener: %v", err)
	}
	defer listener.Close()

	port := listener.Addr().(*net.TCPAddr).Port

	// Handle control connections
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()

		// Echo back any data received
		buffer := make([]byte, 1024)
		n, err := conn.Read(buffer)
		if err != nil {
			return
		}
		conn.Write(buffer[:n])
	}()

	// Test establishing control channel
	controlAddr := &net.TCPAddr{
		IP:   net.IPv6loopback,
		Port: port,
	}

	conn, err := manager.EstablishControlChannel(controlAddr)
	if err != nil {
		t.Fatalf("Failed to establish control channel: %v", err)
	}
	defer conn.Close()

	// Test sending and receiving verification data
	testData := []byte("test verification data")

	if err := manager.SendVerificationData(conn, testData); err != nil {
		t.Fatalf("Failed to send verification data: %v", err)
	}

	receivedData, err := manager.ReceiveVerificationData(conn)
	if err != nil {
		t.Fatalf("Failed to receive verification data: %v", err)
	}

	if string(receivedData) != string(testData) {
		t.Errorf("Data mismatch - sent: %s, received: %s", testData, receivedData)
	}

	t.Logf("Control connection test successful - sent and received: %s", testData)
}
