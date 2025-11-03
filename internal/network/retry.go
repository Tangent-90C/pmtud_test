package network

import (
	"context"
	"fmt"
	"math"
	"math/rand"
	"net"
	"sync"
	"time"
)

// RetryManager provides intelligent retry logic for network operations
type RetryManager struct {
	config    *RetryConfig
	optimizer *NetworkOptimizer
	stats     *RetryStats
	mutex     sync.RWMutex
}

// RetryConfig defines retry behavior configuration
type RetryConfig struct {
	MaxAttempts       int
	BaseDelay         time.Duration
	MaxDelay          time.Duration
	BackoffMultiplier float64
	JitterEnabled     bool
	JitterRange       float64

	// Adaptive retry settings
	AdaptiveEnabled          bool
	SuccessThreshold         float64
	AdaptiveFailureThreshold float64

	// Circuit breaker settings
	CircuitBreakerEnabled   bool
	FailureWindow           time.Duration
	CircuitFailureThreshold int
	RecoveryTimeout         time.Duration
}

// RetryStats tracks retry operation statistics
type RetryStats struct {
	TotalAttempts       uint64
	SuccessfulRetries   uint64
	FailedRetries       uint64
	CircuitBreakerTrips uint64
	AverageAttempts     float64
	LastSuccess         time.Time
	LastFailure         time.Time
	mutex               sync.RWMutex
}

// CircuitBreakerState represents the state of the circuit breaker
type CircuitBreakerState int

const (
	CircuitClosed CircuitBreakerState = iota
	CircuitOpen
	CircuitHalfOpen
)

// CircuitBreaker implements circuit breaker pattern for network operations
type CircuitBreaker struct {
	state           CircuitBreakerState
	failures        int
	lastFailureTime time.Time
	config          *RetryConfig
	mutex           sync.RWMutex
}

// RetryableOperation represents an operation that can be retried
type RetryableOperation func() error

// RetryableOperationWithResult represents an operation that returns a result and can be retried
type RetryableOperationWithResult[T any] func() (T, error)

// NewRetryManager creates a new retry manager
func NewRetryManager(config *RetryConfig, optimizer *NetworkOptimizer) *RetryManager {
	if config == nil {
		config = DefaultRetryConfig()
	}

	return &RetryManager{
		config:    config,
		optimizer: optimizer,
		stats:     &RetryStats{},
	}
}

// DefaultRetryConfig returns a default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:              3,
		BaseDelay:                100 * time.Millisecond,
		MaxDelay:                 5 * time.Second,
		BackoffMultiplier:        2.0,
		JitterEnabled:            true,
		JitterRange:              0.1,
		AdaptiveEnabled:          true,
		SuccessThreshold:         0.8,
		AdaptiveFailureThreshold: 0.3,
		CircuitBreakerEnabled:    true,
		FailureWindow:            1 * time.Minute,
		CircuitFailureThreshold:  5,
		RecoveryTimeout:          30 * time.Second,
	}
}

// Execute executes an operation with intelligent retry logic
func (rm *RetryManager) Execute(ctx context.Context, operation RetryableOperation) error {
	return rm.ExecuteWithCallback(ctx, operation, nil)
}

// ExecuteWithCallback executes an operation with retry logic and progress callback
func (rm *RetryManager) ExecuteWithCallback(ctx context.Context, operation RetryableOperation,
	callback func(attempt int, err error, delay time.Duration)) error {

	// Check circuit breaker
	if rm.config.CircuitBreakerEnabled {
		if !rm.canExecute() {
			return fmt.Errorf("circuit breaker is open, operation blocked")
		}
	}

	var lastErr error
	startTime := time.Now()

	for attempt := 1; attempt <= rm.config.MaxAttempts; attempt++ {
		// Update attempt statistics
		rm.updateAttemptStats()

		// Execute the operation
		err := operation()
		if err == nil {
			// Success
			rm.recordSuccess(attempt, time.Since(startTime))
			if callback != nil {
				callback(attempt, nil, 0)
			}
			return nil
		}

		lastErr = err

		// Check if we should retry
		if !rm.shouldRetry(err, attempt) {
			break
		}

		// Calculate delay for next attempt
		delay := rm.calculateDelay(attempt, err)

		// Call progress callback
		if callback != nil {
			callback(attempt, err, delay)
		}

		// Don't delay after the last attempt
		if attempt < rm.config.MaxAttempts {
			select {
			case <-ctx.Done():
				rm.recordFailure(attempt, time.Since(startTime))
				return fmt.Errorf("retry cancelled by context: %w", ctx.Err())
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}

	// All attempts failed
	rm.recordFailure(rm.config.MaxAttempts, time.Since(startTime))
	return fmt.Errorf("operation failed after %d attempts: %w", rm.config.MaxAttempts, lastErr)
}

// ExecuteWithResult executes an operation that returns a result with retry logic
// Note: Generic version commented out due to Go version compatibility
// func (rm *RetryManager) ExecuteWithResult[T any](ctx context.Context,
//	operation RetryableOperationWithResult[T]) (T, error) {
//
//	var zeroValue T
//	var result T
//
//	err := rm.ExecuteWithCallback(ctx, func() error {
//		var err error
//		result, err = operation()
//		return err
//	}, nil)
//
//	if err != nil {
//		return zeroValue, err
//	}
//
//	return result, nil
// }

// shouldRetry determines if an operation should be retried
func (rm *RetryManager) shouldRetry(err error, attempt int) bool {
	// Don't retry if we've reached max attempts
	if attempt >= rm.config.MaxAttempts {
		return false
	}

	// Check if error is retryable
	if !rm.isRetryableError(err) {
		return false
	}

	// Use optimizer's retry decision if available
	if rm.optimizer != nil {
		return rm.optimizer.ShouldRetry(err, attempt)
	}

	return true
}

// isRetryableError determines if an error is retryable
func (rm *RetryManager) isRetryableError(err error) bool {
	if err == nil {
		return false
	}

	// Check for network errors
	if netErr, ok := err.(net.Error); ok {
		return netErr.Temporary() || netErr.Timeout()
	}

	// Check for specific error patterns
	errStr := err.Error()
	retryablePatterns := []string{
		"connection refused",
		"network is unreachable",
		"no route to host",
		"timeout",
		"temporary failure",
		"connection reset",
		"broken pipe",
	}

	for _, pattern := range retryablePatterns {
		if contains(errStr, pattern) {
			return true
		}
	}

	return false
}

// calculateDelay calculates the delay for the next retry attempt
func (rm *RetryManager) calculateDelay(attempt int, err error) time.Duration {
	// Base exponential backoff
	delay := float64(rm.config.BaseDelay) * math.Pow(rm.config.BackoffMultiplier, float64(attempt-1))

	// Apply maximum delay limit
	if delay > float64(rm.config.MaxDelay) {
		delay = float64(rm.config.MaxDelay)
	}

	// Add jitter if enabled
	if rm.config.JitterEnabled {
		jitter := delay * rm.config.JitterRange * (2.0*rand.Float64() - 1.0)
		delay += jitter

		// Ensure delay is not negative
		if delay < 0 {
			delay = float64(rm.config.BaseDelay)
		}
	}

	// Adaptive delay based on network conditions
	if rm.config.AdaptiveEnabled && rm.optimizer != nil {
		adaptiveTimeout := rm.optimizer.AdaptiveTimeout()
		if adaptiveTimeout > 0 {
			// Adjust delay based on current network conditions
			networkFactor := float64(adaptiveTimeout) / float64(rm.config.BaseDelay)
			if networkFactor > 1.0 && networkFactor < 10.0 {
				delay *= networkFactor
			}
		}
	}

	return time.Duration(delay)
}

// canExecute checks if the circuit breaker allows execution
func (rm *RetryManager) canExecute() bool {
	if !rm.config.CircuitBreakerEnabled {
		return true
	}

	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	now := time.Now()

	// Check circuit breaker state
	switch rm.getCircuitState() {
	case CircuitClosed:
		return true
	case CircuitOpen:
		// Check if recovery timeout has passed
		if now.Sub(rm.stats.LastFailure) > rm.config.RecoveryTimeout {
			// Transition to half-open
			return true
		}
		return false
	case CircuitHalfOpen:
		return true
	}

	return true
}

// getCircuitState returns the current circuit breaker state
func (rm *RetryManager) getCircuitState() CircuitBreakerState {
	now := time.Now()

	// Count failures in the failure window
	recentFailures := rm.countRecentFailures(now)

	if recentFailures >= rm.config.CircuitFailureThreshold {
		if now.Sub(rm.stats.LastFailure) > rm.config.RecoveryTimeout {
			return CircuitHalfOpen
		}
		return CircuitOpen
	}

	return CircuitClosed
}

// countRecentFailures counts failures within the failure window
func (rm *RetryManager) countRecentFailures(now time.Time) int {
	// This is a simplified implementation
	// In a production system, you'd want to track individual failure timestamps
	if now.Sub(rm.stats.LastFailure) <= rm.config.FailureWindow {
		return int(rm.stats.FailedRetries)
	}
	return 0
}

// recordSuccess records a successful operation
func (rm *RetryManager) recordSuccess(attempts int, duration time.Duration) {
	rm.stats.mutex.Lock()
	defer rm.stats.mutex.Unlock()

	rm.stats.TotalAttempts += uint64(attempts)
	rm.stats.SuccessfulRetries++
	rm.stats.LastSuccess = time.Now()

	// Update average attempts
	rm.updateAverageAttempts()
}

// recordFailure records a failed operation
func (rm *RetryManager) recordFailure(attempts int, duration time.Duration) {
	rm.stats.mutex.Lock()
	defer rm.stats.mutex.Unlock()

	rm.stats.TotalAttempts += uint64(attempts)
	rm.stats.FailedRetries++
	rm.stats.LastFailure = time.Now()

	// Update average attempts
	rm.updateAverageAttempts()

	// Check if circuit breaker should trip
	if rm.config.CircuitBreakerEnabled {
		recentFailures := rm.countRecentFailures(time.Now())
		if recentFailures >= rm.config.CircuitFailureThreshold {
			rm.stats.CircuitBreakerTrips++
		}
	}
}

// updateAttemptStats updates attempt statistics
func (rm *RetryManager) updateAttemptStats() {
	rm.stats.mutex.Lock()
	defer rm.stats.mutex.Unlock()

	rm.stats.TotalAttempts++
}

// updateAverageAttempts updates the average attempts statistic
func (rm *RetryManager) updateAverageAttempts() {
	totalOperations := rm.stats.SuccessfulRetries + rm.stats.FailedRetries
	if totalOperations > 0 {
		rm.stats.AverageAttempts = float64(rm.stats.TotalAttempts) / float64(totalOperations)
	}
}

// GetStats returns a copy of current retry statistics
func (rm *RetryManager) GetStats() RetryStats {
	rm.stats.mutex.RLock()
	defer rm.stats.mutex.RUnlock()

	// Create a copy without the mutex
	stats := RetryStats{
		TotalAttempts:       rm.stats.TotalAttempts,
		SuccessfulRetries:   rm.stats.SuccessfulRetries,
		FailedRetries:       rm.stats.FailedRetries,
		CircuitBreakerTrips: rm.stats.CircuitBreakerTrips,
		AverageAttempts:     rm.stats.AverageAttempts,
		LastSuccess:         rm.stats.LastSuccess,
		LastFailure:         rm.stats.LastFailure,
	}

	return stats
}

// ResetStats resets all retry statistics
func (rm *RetryManager) ResetStats() {
	rm.stats.mutex.Lock()
	defer rm.stats.mutex.Unlock()

	rm.stats.TotalAttempts = 0
	rm.stats.SuccessfulRetries = 0
	rm.stats.FailedRetries = 0
	rm.stats.CircuitBreakerTrips = 0
	rm.stats.AverageAttempts = 0
	rm.stats.LastSuccess = time.Time{}
	rm.stats.LastFailure = time.Time{}
}

// GetSuccessRate returns the current success rate
func (rm *RetryManager) GetSuccessRate() float64 {
	rm.stats.mutex.RLock()
	defer rm.stats.mutex.RUnlock()

	totalOperations := rm.stats.SuccessfulRetries + rm.stats.FailedRetries
	if totalOperations == 0 {
		return 0.0
	}

	return float64(rm.stats.SuccessfulRetries) / float64(totalOperations)
}

// IsCircuitOpen returns true if the circuit breaker is open
func (rm *RetryManager) IsCircuitOpen() bool {
	if !rm.config.CircuitBreakerEnabled {
		return false
	}

	rm.mutex.RLock()
	defer rm.mutex.RUnlock()

	return rm.getCircuitState() == CircuitOpen
}

// AdaptRetryConfig adapts retry configuration based on current performance
func (rm *RetryManager) AdaptRetryConfig() {
	if !rm.config.AdaptiveEnabled {
		return
	}

	successRate := rm.GetSuccessRate()

	rm.mutex.Lock()
	defer rm.mutex.Unlock()

	if successRate > rm.config.SuccessThreshold {
		// High success rate - can be more aggressive
		if rm.config.MaxAttempts > 1 {
			rm.config.MaxAttempts--
		}
		if rm.config.BaseDelay > 50*time.Millisecond {
			rm.config.BaseDelay = time.Duration(float64(rm.config.BaseDelay) * 0.9)
		}
	} else if successRate < rm.config.AdaptiveFailureThreshold {
		// Low success rate - be more conservative
		if rm.config.MaxAttempts < 10 {
			rm.config.MaxAttempts++
		}
		if rm.config.BaseDelay < 1*time.Second {
			rm.config.BaseDelay = time.Duration(float64(rm.config.BaseDelay) * 1.1)
		}
	}
}

// CreateNetworkRetryOperation creates a retryable network operation
func CreateNetworkRetryOperation(operation func() error, operationName string) RetryableOperation {
	return func() error {
		err := operation()
		if err != nil {
			// Add context to the error
			return fmt.Errorf("%s failed: %w", operationName, err)
		}
		return nil
	}
}

// CreateTimedRetryOperation creates a retryable operation with timeout
func CreateTimedRetryOperation(operation func() error, timeout time.Duration, operationName string) RetryableOperation {
	return func() error {
		ctx, cancel := context.WithTimeout(context.Background(), timeout)
		defer cancel()

		done := make(chan error, 1)
		go func() {
			done <- operation()
		}()

		select {
		case err := <-done:
			if err != nil {
				return fmt.Errorf("%s failed: %w", operationName, err)
			}
			return nil
		case <-ctx.Done():
			return fmt.Errorf("%s timed out after %v", operationName, timeout)
		}
	}
}
