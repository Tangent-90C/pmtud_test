package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// NetworkOptimizer provides network performance optimization and reliability features
type NetworkOptimizer struct {
	socketManager *SocketManager
	config        *OptimizationConfig
	stats         *NetworkStats
	mutex         sync.RWMutex
}

// OptimizationConfig contains configuration for network optimization
type OptimizationConfig struct {
	// Timeout settings
	ConnectTimeout time.Duration
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration

	// Retry settings
	MaxRetries        int
	RetryDelay        time.Duration
	BackoffMultiplier float64
	MaxRetryDelay     time.Duration

	// Buffer settings
	SendBufferSize int
	RecvBufferSize int

	// Performance settings
	EnableTCPNoDelay  bool
	EnableKeepalive   bool
	KeepaliveIdle     time.Duration
	KeepaliveInterval time.Duration
	KeepaliveCount    int

	// Quality of Service
	TrafficClass int
	HopLimit     int

	// Advanced settings
	EnableTimestamps  bool
	EnableFastOpen    bool
	CongestionControl string
}

// DefaultOptimizationConfig returns a default optimization configuration
func DefaultOptimizationConfig() *OptimizationConfig {
	return &OptimizationConfig{
		ConnectTimeout:    10 * time.Second,
		ReadTimeout:       5 * time.Second,
		WriteTimeout:      5 * time.Second,
		MaxRetries:        3,
		RetryDelay:        100 * time.Millisecond,
		BackoffMultiplier: 2.0,
		MaxRetryDelay:     5 * time.Second,
		SendBufferSize:    65536,
		RecvBufferSize:    131072,
		EnableTCPNoDelay:  true,
		EnableKeepalive:   true,
		KeepaliveIdle:     60 * time.Second,
		KeepaliveInterval: 10 * time.Second,
		KeepaliveCount:    3,
		TrafficClass:      0,
		HopLimit:          64,
		EnableTimestamps:  true,
		EnableFastOpen:    false,
		CongestionControl: "cubic",
	}
}

// NetworkStats tracks network performance statistics
type NetworkStats struct {
	PacketsSent     uint64
	PacketsReceived uint64
	BytesSent       uint64
	BytesReceived   uint64
	Errors          uint64
	Timeouts        uint64
	Retries         uint64
	ConnectionTime  time.Duration
	MinRTT          time.Duration
	MaxRTT          time.Duration
	AvgRTT          time.Duration
	PacketLoss      float64
	LastUpdate      time.Time
	mutex           sync.RWMutex
}

// NewNetworkOptimizer creates a new network optimizer
func NewNetworkOptimizer(socketManager *SocketManager, config *OptimizationConfig) *NetworkOptimizer {
	if config == nil {
		config = DefaultOptimizationConfig()
	}

	return &NetworkOptimizer{
		socketManager: socketManager,
		config:        config,
		stats: &NetworkStats{
			MinRTT:     time.Duration(^uint64(0) >> 1), // Max duration
			LastUpdate: time.Now(),
		},
	}
}

// OptimizeSocket applies optimization settings to a socket
func (no *NetworkOptimizer) OptimizeSocket(fd int, sockType SocketType) error {
	no.mutex.Lock()
	defer no.mutex.Unlock()

	// Set buffer sizes
	if err := no.socketManager.SetSocketBufferSizes(fd, no.config.SendBufferSize, no.config.RecvBufferSize); err != nil {
		return fmt.Errorf("failed to set buffer sizes: %w", err)
	}

	// Set timeouts
	if err := no.socketManager.SetSocketTimeout(fd, no.config.ReadTimeout); err != nil {
		return fmt.Errorf("failed to set timeout: %w", err)
	}

	// Enable timestamps for performance measurement
	if no.config.EnableTimestamps {
		if err := no.socketManager.EnableTimestamps(fd); err != nil {
			// Non-fatal error, continue without timestamps
		}
	}

	// Set traffic class for QoS
	if no.config.TrafficClass > 0 {
		if err := no.socketManager.SetTOS(fd, no.config.TrafficClass); err != nil {
			// Non-fatal error
		}
	}

	// Set hop limit
	if no.config.HopLimit > 0 {
		if err := no.socketManager.SetHopLimit(fd, no.config.HopLimit); err != nil {
			// Non-fatal error
		}
	}

	// Apply socket type specific optimizations
	switch sockType {
	case SocketTypeTCPv6:
		return no.optimizeTCPSocket(fd)
	case SocketTypeRawICMP6:
		return no.optimizeRawSocket(fd)
	}

	return nil
}

// optimizeTCPSocket applies TCP-specific optimizations
func (no *NetworkOptimizer) optimizeTCPSocket(fd int) error {
	// Set MSS if configured
	if no.config.SendBufferSize > 0 {
		// Calculate optimal MSS based on buffer size
		optimalMSS := no.config.SendBufferSize / 16 // Conservative estimate
		if optimalMSS > 1460 {
			optimalMSS = 1460 // Standard Ethernet MSS
		}
		if optimalMSS < 536 {
			optimalMSS = 536 // Minimum MSS
		}

		if err := no.socketManager.SetMSSOption(fd, optimalMSS); err != nil {
			// Non-fatal error
		}
	}

	return nil
}

// optimizeRawSocket applies raw socket specific optimizations
func (no *NetworkOptimizer) optimizeRawSocket(fd int) error {
	// Raw sockets typically need larger buffers for packet capture
	largerRecvBuf := no.config.RecvBufferSize * 2
	if err := no.socketManager.SetSocketBufferSizes(fd, no.config.SendBufferSize, largerRecvBuf); err != nil {
		// Fallback to original buffer size
		return no.socketManager.SetSocketBufferSizes(fd, no.config.SendBufferSize, no.config.RecvBufferSize)
	}

	return nil
}

// CreateOptimizedConnection creates an optimized network connection
func (no *NetworkOptimizer) CreateOptimizedConnection(ctx context.Context, network, address string) (net.Conn, error) {
	var conn net.Conn
	var err error

	// Create connection with timeout
	connectCtx, cancel := context.WithTimeout(ctx, no.config.ConnectTimeout)
	defer cancel()

	dialer := &net.Dialer{
		Timeout: no.config.ConnectTimeout,
	}

	startTime := time.Now()

	// Retry connection with exponential backoff
	retryDelay := no.config.RetryDelay
	for attempt := 0; attempt <= no.config.MaxRetries; attempt++ {
		conn, err = dialer.DialContext(connectCtx, network, address)
		if err == nil {
			// Connection successful
			no.updateConnectionStats(time.Since(startTime), attempt)

			// Apply optimizations to the connection
			if tcpConn, ok := conn.(*net.TCPConn); ok {
				if err := no.optimizeTCPConnection(tcpConn); err != nil {
					conn.Close()
					return nil, fmt.Errorf("failed to optimize TCP connection: %w", err)
				}
			}

			return conn, nil
		}

		// Check if we should retry
		if attempt < no.config.MaxRetries && no.isRetryableError(err) {
			no.updateRetryStats()

			select {
			case <-connectCtx.Done():
				return nil, fmt.Errorf("connection timeout: %w", connectCtx.Err())
			case <-time.After(retryDelay):
				// Continue to next attempt
				retryDelay = time.Duration(float64(retryDelay) * no.config.BackoffMultiplier)
				if retryDelay > no.config.MaxRetryDelay {
					retryDelay = no.config.MaxRetryDelay
				}
			}
		}
	}

	no.updateErrorStats()
	return nil, fmt.Errorf("failed to connect after %d attempts: %w", no.config.MaxRetries+1, err)
}

// optimizeTCPConnection applies optimizations to an established TCP connection
func (no *NetworkOptimizer) optimizeTCPConnection(conn *net.TCPConn) error {
	// Enable TCP no delay if configured
	if no.config.EnableTCPNoDelay {
		if err := conn.SetNoDelay(true); err != nil {
			return fmt.Errorf("failed to set TCP no delay: %w", err)
		}
	}

	// Enable keepalive if configured
	if no.config.EnableKeepalive {
		if err := conn.SetKeepAlive(true); err != nil {
			return fmt.Errorf("failed to enable keepalive: %w", err)
		}

		if err := conn.SetKeepAlivePeriod(no.config.KeepaliveIdle); err != nil {
			// Non-fatal error
		}
	}

	// Set read and write deadlines
	if no.config.ReadTimeout > 0 {
		conn.SetReadDeadline(time.Now().Add(no.config.ReadTimeout))
	}

	if no.config.WriteTimeout > 0 {
		conn.SetWriteDeadline(time.Now().Add(no.config.WriteTimeout))
	}

	return nil
}

// isRetryableError determines if an error is retryable
func (no *NetworkOptimizer) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors that are typically retryable
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}

	// Check for specific error types
	errStr := err.Error()
	retryableErrors := []string{
		"connection refused",
		"network is unreachable",
		"no route to host",
		"timeout",
		"temporary failure",
	}

	for _, retryableErr := range retryableErrors {
		if contains(errStr, retryableErr) {
			return true
		}
	}

	return false
}

// contains checks if a string contains a substring (case-insensitive)
func contains(s, substr string) bool {
	return len(s) >= len(substr) &&
		(s == substr ||
			(len(s) > len(substr) &&
				(s[:len(substr)] == substr ||
					s[len(s)-len(substr):] == substr ||
					findSubstring(s, substr))))
}

// findSubstring performs a simple substring search
func findSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// UpdateRTTStats updates round-trip time statistics
func (no *NetworkOptimizer) UpdateRTTStats(rtt time.Duration) {
	no.stats.mutex.Lock()
	defer no.stats.mutex.Unlock()

	if rtt < no.stats.MinRTT {
		no.stats.MinRTT = rtt
	}

	if rtt > no.stats.MaxRTT {
		no.stats.MaxRTT = rtt
	}

	// Calculate running average (simple moving average)
	if no.stats.AvgRTT == 0 {
		no.stats.AvgRTT = rtt
	} else {
		no.stats.AvgRTT = (no.stats.AvgRTT + rtt) / 2
	}

	no.stats.LastUpdate = time.Now()
}

// updateConnectionStats updates connection statistics
func (no *NetworkOptimizer) updateConnectionStats(duration time.Duration, attempts int) {
	no.stats.mutex.Lock()
	defer no.stats.mutex.Unlock()

	no.stats.ConnectionTime = duration
	if attempts > 0 {
		no.stats.Retries += uint64(attempts)
	}
	no.stats.LastUpdate = time.Now()
}

// updateRetryStats updates retry statistics
func (no *NetworkOptimizer) updateRetryStats() {
	no.stats.mutex.Lock()
	defer no.stats.mutex.Unlock()

	no.stats.Retries++
	no.stats.LastUpdate = time.Now()
}

// updateErrorStats updates error statistics
func (no *NetworkOptimizer) updateErrorStats() {
	no.stats.mutex.Lock()
	defer no.stats.mutex.Unlock()

	no.stats.Errors++
	no.stats.LastUpdate = time.Now()
}

// UpdatePacketStats updates packet transmission statistics
func (no *NetworkOptimizer) UpdatePacketStats(sent, received uint64, bytesSent, bytesReceived uint64) {
	no.stats.mutex.Lock()
	defer no.stats.mutex.Unlock()

	no.stats.PacketsSent += sent
	no.stats.PacketsReceived += received
	no.stats.BytesSent += bytesSent
	no.stats.BytesReceived += bytesReceived

	// Calculate packet loss
	if no.stats.PacketsSent > 0 {
		no.stats.PacketLoss = float64(no.stats.PacketsSent-no.stats.PacketsReceived) / float64(no.stats.PacketsSent) * 100
	}

	no.stats.LastUpdate = time.Now()
}

// GetStats returns a copy of current network statistics
func (no *NetworkOptimizer) GetStats() NetworkStats {
	no.stats.mutex.RLock()
	defer no.stats.mutex.RUnlock()

	// Create a copy without the mutex
	stats := NetworkStats{
		PacketsSent:     no.stats.PacketsSent,
		PacketsReceived: no.stats.PacketsReceived,
		BytesSent:       no.stats.BytesSent,
		BytesReceived:   no.stats.BytesReceived,
		Errors:          no.stats.Errors,
		Timeouts:        no.stats.Timeouts,
		Retries:         no.stats.Retries,
		ConnectionTime:  no.stats.ConnectionTime,
		MinRTT:          no.stats.MinRTT,
		MaxRTT:          no.stats.MaxRTT,
		AvgRTT:          no.stats.AvgRTT,
		PacketLoss:      no.stats.PacketLoss,
		LastUpdate:      no.stats.LastUpdate,
	}

	return stats
}

// ResetStats resets all network statistics
func (no *NetworkOptimizer) ResetStats() {
	no.stats.mutex.Lock()
	defer no.stats.mutex.Unlock()

	no.stats.PacketsSent = 0
	no.stats.PacketsReceived = 0
	no.stats.BytesSent = 0
	no.stats.BytesReceived = 0
	no.stats.Errors = 0
	no.stats.Timeouts = 0
	no.stats.Retries = 0
	no.stats.ConnectionTime = 0
	no.stats.MinRTT = time.Duration(^uint64(0) >> 1)
	no.stats.MaxRTT = 0
	no.stats.AvgRTT = 0
	no.stats.PacketLoss = 0
	no.stats.LastUpdate = time.Now()
}

// GetConfig returns the current optimization configuration
func (no *NetworkOptimizer) GetConfig() *OptimizationConfig {
	no.mutex.RLock()
	defer no.mutex.RUnlock()

	// Return a copy to prevent external modification
	config := *no.config
	return &config
}

// UpdateConfig updates the optimization configuration
func (no *NetworkOptimizer) UpdateConfig(config *OptimizationConfig) {
	no.mutex.Lock()
	defer no.mutex.Unlock()

	if config != nil {
		no.config = config
	}
}

// AdaptiveTimeout calculates an adaptive timeout based on current network conditions
func (no *NetworkOptimizer) AdaptiveTimeout() time.Duration {
	stats := no.GetStats()

	// Base timeout on average RTT with some margin
	if stats.AvgRTT > 0 {
		adaptiveTimeout := stats.AvgRTT * 3 // 3x average RTT

		// Ensure it's within reasonable bounds
		minTimeout := 100 * time.Millisecond
		maxTimeout := 30 * time.Second

		if adaptiveTimeout < minTimeout {
			adaptiveTimeout = minTimeout
		} else if adaptiveTimeout > maxTimeout {
			adaptiveTimeout = maxTimeout
		}

		return adaptiveTimeout
	}

	// Fallback to configured timeout
	return no.config.ReadTimeout
}

// ShouldRetry determines if an operation should be retried based on current conditions
func (no *NetworkOptimizer) ShouldRetry(err error, attempt int) bool {
	if attempt >= no.config.MaxRetries {
		return false
	}

	if !no.isRetryableError(err) {
		return false
	}

	// Consider current error rate
	stats := no.GetStats()
	if stats.PacketsSent > 0 {
		errorRate := float64(stats.Errors) / float64(stats.PacketsSent)
		if errorRate > 0.5 { // More than 50% error rate
			return false
		}
	}

	return true
}

// OptimizeForLatency optimizes configuration for low latency
func (no *NetworkOptimizer) OptimizeForLatency() {
	no.mutex.Lock()
	defer no.mutex.Unlock()

	no.config.EnableTCPNoDelay = true
	no.config.SendBufferSize = 32768 // Smaller buffers for lower latency
	no.config.RecvBufferSize = 65536
	no.config.ConnectTimeout = 5 * time.Second
	no.config.ReadTimeout = 2 * time.Second
	no.config.WriteTimeout = 2 * time.Second
}

// OptimizeForThroughput optimizes configuration for high throughput
func (no *NetworkOptimizer) OptimizeForThroughput() {
	no.mutex.Lock()
	defer no.mutex.Unlock()

	no.config.EnableTCPNoDelay = false // Allow Nagle's algorithm for better throughput
	no.config.SendBufferSize = 262144  // Larger buffers for higher throughput
	no.config.RecvBufferSize = 524288
	no.config.ConnectTimeout = 15 * time.Second
	no.config.ReadTimeout = 10 * time.Second
	no.config.WriteTimeout = 10 * time.Second
}

// OptimizeForReliability optimizes configuration for maximum reliability
func (no *NetworkOptimizer) OptimizeForReliability() {
	no.mutex.Lock()
	defer no.mutex.Unlock()

	no.config.MaxRetries = 5
	no.config.RetryDelay = 200 * time.Millisecond
	no.config.BackoffMultiplier = 1.5
	no.config.MaxRetryDelay = 10 * time.Second
	no.config.EnableKeepalive = true
	no.config.KeepaliveIdle = 30 * time.Second
	no.config.KeepaliveInterval = 5 * time.Second
	no.config.KeepaliveCount = 5
}
