package cli

import (
	"context"
	"fmt"
	"math"
	"time"
)

// RetryConfig defines configuration for retry operations
type RetryConfig struct {
	MaxAttempts     int           // Maximum number of retry attempts
	InitialDelay    time.Duration // Initial delay between retries
	MaxDelay        time.Duration // Maximum delay between retries
	BackoffFactor   float64       // Exponential backoff factor
	Jitter          bool          // Add random jitter to delays
	RetryableErrors []ErrorCode   // Specific error codes that should be retried
}

// DefaultRetryConfig returns a sensible default retry configuration
func DefaultRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:   3,
		InitialDelay:  100 * time.Millisecond,
		MaxDelay:      5 * time.Second,
		BackoffFactor: 2.0,
		Jitter:        true,
		RetryableErrors: []ErrorCode{
			ErrRecvTimeout,
			ErrProbeTimeout,
			ErrSendFailed,
			ErrNetworkUnreachable,
		},
	}
}

// NetworkRetryConfig returns retry configuration optimized for network operations
func NetworkRetryConfig() *RetryConfig {
	return &RetryConfig{
		MaxAttempts:   5,
		InitialDelay:  200 * time.Millisecond,
		MaxDelay:      10 * time.Second,
		BackoffFactor: 1.5,
		Jitter:        true,
		RetryableErrors: []ErrorCode{
			ErrRecvTimeout,
			ErrProbeTimeout,
			ErrSendFailed,
			ErrNetworkUnreachable,
			ErrSocketCreate,
		},
	}
}

// RetryableOperation represents an operation that can be retried
type RetryableOperation func() error

// RetryableOperationWithResult represents an operation that returns a result and can be retried
type RetryableOperationWithResult[T any] func() (T, error)

// RetryManager handles retry logic for operations
type RetryManager struct {
	config *RetryConfig
}

// NewRetryManager creates a new retry manager with the given configuration
func NewRetryManager(config *RetryConfig) *RetryManager {
	if config == nil {
		config = DefaultRetryConfig()
	}
	return &RetryManager{config: config}
}

// Execute executes an operation with retry logic
func (rm *RetryManager) Execute(ctx context.Context, operation RetryableOperation) error {
	var lastErr error

	for attempt := 1; attempt <= rm.config.MaxAttempts; attempt++ {
		// Execute the operation
		err := operation()
		if err == nil {
			return nil // Success
		}

		lastErr = err

		// Check if we should retry this error
		if !rm.shouldRetry(err, attempt) {
			break
		}

		// Don't delay after the last attempt
		if attempt < rm.config.MaxAttempts {
			delay := rm.calculateDelay(attempt)

			select {
			case <-ctx.Done():
				return NewProbeError(ErrContextCanceled, "retry cancelled by context", ctx.Err())
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}

	// All attempts failed
	if probeErr, ok := lastErr.(*ProbeError); ok {
		return probeErr.WithContext("attempts", rm.config.MaxAttempts)
	}

	return NewProbeError(ErrSystemError,
		fmt.Sprintf("operation failed after %d attempts", rm.config.MaxAttempts),
		lastErr).WithContext("attempts", rm.config.MaxAttempts)
}

// ExecuteWithResult executes an operation that returns a result with retry logic
// Note: Generic version commented out due to Go version compatibility
// func (rm *RetryManager) ExecuteWithResult[T any](ctx context.Context, operation RetryableOperationWithResult[T]) (T, error) {
//	var lastErr error
//	var zeroValue T
//
//	for attempt := 1; attempt <= rm.config.MaxAttempts; attempt++ {
//		// Execute the operation
//		result, err := operation()
//		if err == nil {
//			return result, nil // Success
//		}
//
//		lastErr = err
//
//		// Check if we should retry this error
//		if !rm.shouldRetry(err, attempt) {
//			break
//		}
//
//		// Don't delay after the last attempt
//		if attempt < rm.config.MaxAttempts {
//			delay := rm.calculateDelay(attempt)
//
//			select {
//			case <-ctx.Done():
//				return zeroValue, NewProbeError(ErrContextCanceled, "retry cancelled by context", ctx.Err())
//			case <-time.After(delay):
//				// Continue to next attempt
//			}
//		}
//	}
//
//	// All attempts failed
//	if probeErr, ok := lastErr.(*ProbeError); ok {
//		return zeroValue, probeErr.WithContext("attempts", rm.config.MaxAttempts)
//	}
//
//	return zeroValue, NewProbeError(ErrSystemError,
//		fmt.Sprintf("operation failed after %d attempts", rm.config.MaxAttempts),
//		lastErr).WithContext("attempts", rm.config.MaxAttempts)
// }

// shouldRetry determines if an error should be retried
func (rm *RetryManager) shouldRetry(err error, attempt int) bool {
	// Don't retry if we've reached max attempts
	if attempt >= rm.config.MaxAttempts {
		return false
	}

	// Check if it's a retryable error type
	if !IsRetryableError(err) {
		return false
	}

	// Check specific error codes if configured
	if len(rm.config.RetryableErrors) > 0 {
		if probeErr, ok := err.(*ProbeError); ok {
			for _, code := range rm.config.RetryableErrors {
				if probeErr.Code == code {
					return true
				}
			}
			return false // Error code not in retryable list
		}
	}

	return true
}

// calculateDelay calculates the delay for the next retry attempt
func (rm *RetryManager) calculateDelay(attempt int) time.Duration {
	// Calculate exponential backoff
	delay := float64(rm.config.InitialDelay) * math.Pow(rm.config.BackoffFactor, float64(attempt-1))

	// Apply maximum delay limit
	if delay > float64(rm.config.MaxDelay) {
		delay = float64(rm.config.MaxDelay)
	}

	// Add jitter if enabled
	if rm.config.Jitter {
		// Add up to 25% random jitter
		jitter := delay * 0.25 * (2.0*float64(time.Now().UnixNano()%1000)/1000.0 - 1.0)
		delay += jitter

		// Ensure delay is not negative
		if delay < 0 {
			delay = float64(rm.config.InitialDelay)
		}
	}

	return time.Duration(delay)
}

// GetConfig returns the current retry configuration
func (rm *RetryManager) GetConfig() *RetryConfig {
	return rm.config
}

// UpdateConfig updates the retry configuration
func (rm *RetryManager) UpdateConfig(config *RetryConfig) {
	if config != nil {
		rm.config = config
	}
}

// RetryWithCallback executes an operation with retry logic and progress callback
func (rm *RetryManager) RetryWithCallback(ctx context.Context, operation RetryableOperation,
	callback func(attempt int, err error, delay time.Duration)) error {

	var lastErr error

	for attempt := 1; attempt <= rm.config.MaxAttempts; attempt++ {
		// Execute the operation
		err := operation()
		if err == nil {
			if callback != nil {
				callback(attempt, nil, 0)
			}
			return nil // Success
		}

		lastErr = err

		// Check if we should retry this error
		if !rm.shouldRetry(err, attempt) {
			if callback != nil {
				callback(attempt, err, 0)
			}
			break
		}

		// Calculate delay for next attempt
		var delay time.Duration
		if attempt < rm.config.MaxAttempts {
			delay = rm.calculateDelay(attempt)
		}

		// Call progress callback
		if callback != nil {
			callback(attempt, err, delay)
		}

		// Don't delay after the last attempt
		if attempt < rm.config.MaxAttempts {
			select {
			case <-ctx.Done():
				return NewProbeError(ErrContextCanceled, "retry cancelled by context", ctx.Err())
			case <-time.After(delay):
				// Continue to next attempt
			}
		}
	}

	// All attempts failed
	if probeErr, ok := lastErr.(*ProbeError); ok {
		return probeErr.WithContext("attempts", rm.config.MaxAttempts)
	}

	return NewProbeError(ErrSystemError,
		fmt.Sprintf("operation failed after %d attempts", rm.config.MaxAttempts),
		lastErr).WithContext("attempts", rm.config.MaxAttempts)
}

// QuickRetry performs a quick retry with minimal configuration
func QuickRetry(ctx context.Context, maxAttempts int, operation RetryableOperation) error {
	config := &RetryConfig{
		MaxAttempts:   maxAttempts,
		InitialDelay:  50 * time.Millisecond,
		MaxDelay:      1 * time.Second,
		BackoffFactor: 1.5,
		Jitter:        false,
	}

	manager := NewRetryManager(config)
	return manager.Execute(ctx, operation)
}

// RetryUntilSuccess retries an operation until it succeeds or context is cancelled
func RetryUntilSuccess(ctx context.Context, operation RetryableOperation, delay time.Duration) error {
	for {
		err := operation()
		if err == nil {
			return nil
		}

		// Check if error is retryable
		if !IsRetryableError(err) {
			return err
		}

		select {
		case <-ctx.Done():
			return NewProbeError(ErrContextCanceled, "retry cancelled by context", ctx.Err())
		case <-time.After(delay):
			// Continue to next attempt
		}
	}
}

// CreateRetryableProbeOperation wraps a probe operation to make it retryable
func CreateRetryableProbeOperation(target string, probeFunc func() error) RetryableOperation {
	return func() error {
		err := probeFunc()
		if err != nil {
			// Wrap the error with additional context
			if probeErr, ok := err.(*ProbeError); ok {
				return probeErr.WithContext("target", target)
			}
			return WrapNetworkError(err, "probe operation")
		}
		return nil
	}
}

// ValidateRetryConfig validates a retry configuration
func ValidateRetryConfig(config *RetryConfig) error {
	if config == nil {
		return CreateValidationError("config", nil, "retry config cannot be nil")
	}

	if config.MaxAttempts < 1 {
		return CreateValidationError("MaxAttempts", config.MaxAttempts, "must be at least 1")
	}

	if config.MaxAttempts > 100 {
		return CreateValidationError("MaxAttempts", config.MaxAttempts, "must not exceed 100")
	}

	if config.InitialDelay < 0 {
		return CreateValidationError("InitialDelay", config.InitialDelay, "cannot be negative")
	}

	if config.MaxDelay < config.InitialDelay {
		return CreateValidationError("MaxDelay", config.MaxDelay, "must be greater than or equal to InitialDelay")
	}

	if config.BackoffFactor < 1.0 {
		return CreateValidationError("BackoffFactor", config.BackoffFactor, "must be at least 1.0")
	}

	return nil
}
