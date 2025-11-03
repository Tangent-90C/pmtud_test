package network

import (
	"context"
	"fmt"
	"net"
	"strings"
	"sync"
	"syscall"
	"time"
)

// NetworkErrorHandler provides intelligent network error handling and recovery
type NetworkErrorHandler struct {
	optimizer    *NetworkOptimizer
	retryManager *RetryManager
	config       *ErrorHandlerConfig
	stats        *ErrorStats
	mutex        sync.RWMutex
}

// ErrorHandlerConfig configures error handling behavior
type ErrorHandlerConfig struct {
	EnableAutoRecovery  bool
	RecoveryTimeout     time.Duration
	MaxRecoveryAttempts int
	ErrorThreshold      float64
	AdaptiveThreshold   bool
	LogErrors           bool
	EnableMetrics       bool
}

// ErrorStats tracks error handling statistics
type ErrorStats struct {
	TotalErrors          uint64
	RecoverableErrors    uint64
	FatalErrors          uint64
	RecoveryAttempts     uint64
	SuccessfulRecoveries uint64
	ErrorsByType         map[ErrorType]uint64
	LastError            time.Time
	LastRecovery         time.Time
	mutex                sync.RWMutex
}

// ErrorType categorizes different types of network errors
type ErrorType int

const (
	ErrorTypeUnknown ErrorType = iota
	ErrorTypeTimeout
	ErrorTypeConnectionRefused
	ErrorTypeNetworkUnreachable
	ErrorTypeHostUnreachable
	ErrorTypePermissionDenied
	ErrorTypeAddressInUse
	ErrorTypeAddressNotAvailable
	ErrorTypeSocketError
	ErrorTypeProtocolError
	ErrorTypeBufferError
	ErrorTypeTemporary
)

// NetworkError represents an enhanced network error with additional context
type NetworkError struct {
	Type        ErrorType
	Original    error
	Context     map[string]interface{}
	Timestamp   time.Time
	Retryable   bool
	Recoverable bool
	Severity    ErrorSeverity
}

// ErrorSeverity indicates the severity of an error
type ErrorSeverity int

const (
	SeverityLow ErrorSeverity = iota
	SeverityMedium
	SeverityHigh
	SeverityCritical
)

// RecoveryAction represents an action that can be taken to recover from an error
type RecoveryAction struct {
	Name        string
	Description string
	Action      func() error
	Priority    int
	Timeout     time.Duration
}

// NewNetworkErrorHandler creates a new network error handler
func NewNetworkErrorHandler(optimizer *NetworkOptimizer, retryManager *RetryManager, config *ErrorHandlerConfig) *NetworkErrorHandler {
	if config == nil {
		config = DefaultErrorHandlerConfig()
	}

	return &NetworkErrorHandler{
		optimizer:    optimizer,
		retryManager: retryManager,
		config:       config,
		stats: &ErrorStats{
			ErrorsByType: make(map[ErrorType]uint64),
		},
	}
}

// DefaultErrorHandlerConfig returns a default error handler configuration
func DefaultErrorHandlerConfig() *ErrorHandlerConfig {
	return &ErrorHandlerConfig{
		EnableAutoRecovery:  true,
		RecoveryTimeout:     30 * time.Second,
		MaxRecoveryAttempts: 3,
		ErrorThreshold:      0.1, // 10% error rate threshold
		AdaptiveThreshold:   true,
		LogErrors:           true,
		EnableMetrics:       true,
	}
}

// HandleError processes a network error and attempts recovery if possible
func (neh *NetworkErrorHandler) HandleError(err error, context map[string]interface{}) *NetworkError {
	if err == nil {
		return nil
	}

	// Classify the error
	networkErr := neh.classifyError(err, context)

	// Update statistics
	neh.updateErrorStats(networkErr)

	// Attempt recovery if enabled and error is recoverable
	if neh.config.EnableAutoRecovery && networkErr.Recoverable {
		neh.attemptRecovery(networkErr)
	}

	return networkErr
}

// classifyError classifies an error and determines its properties
func (neh *NetworkErrorHandler) classifyError(err error, context map[string]interface{}) *NetworkError {
	networkErr := &NetworkError{
		Original:  err,
		Context:   context,
		Timestamp: time.Now(),
	}

	// Classify by error type
	networkErr.Type = neh.determineErrorType(err)
	networkErr.Retryable = neh.isRetryable(err, networkErr.Type)
	networkErr.Recoverable = neh.isRecoverable(err, networkErr.Type)
	networkErr.Severity = neh.determineSeverity(err, networkErr.Type)

	return networkErr
}

// determineErrorType determines the type of a network error
func (neh *NetworkErrorHandler) determineErrorType(err error) ErrorType {
	if err == nil {
		return ErrorTypeUnknown
	}

	// Check for specific error types
	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			return ErrorTypeTimeout
		}
		if netErr.Temporary() {
			return ErrorTypeTemporary
		}
	}

	// Check syscall errors
	if errno, ok := err.(syscall.Errno); ok {
		switch errno {
		case syscall.ECONNREFUSED:
			return ErrorTypeConnectionRefused
		case syscall.ENETUNREACH:
			return ErrorTypeNetworkUnreachable
		case syscall.EHOSTUNREACH:
			return ErrorTypeHostUnreachable
		case syscall.EACCES, syscall.EPERM:
			return ErrorTypePermissionDenied
		case syscall.EADDRINUSE:
			return ErrorTypeAddressInUse
		case syscall.EADDRNOTAVAIL:
			return ErrorTypeAddressNotAvailable
		case syscall.ENOBUFS, syscall.ENOMEM:
			return ErrorTypeBufferError
		case syscall.EPROTONOSUPPORT, syscall.EAFNOSUPPORT:
			return ErrorTypeProtocolError
		default:
			return ErrorTypeSocketError
		}
	}

	// Check error message patterns
	errStr := strings.ToLower(err.Error())
	switch {
	case contains(errStr, "timeout"):
		return ErrorTypeTimeout
	case contains(errStr, "connection refused"):
		return ErrorTypeConnectionRefused
	case contains(errStr, "network unreachable"):
		return ErrorTypeNetworkUnreachable
	case contains(errStr, "host unreachable"):
		return ErrorTypeHostUnreachable
	case contains(errStr, "permission denied"):
		return ErrorTypePermissionDenied
	case contains(errStr, "address already in use"):
		return ErrorTypeAddressInUse
	case contains(errStr, "temporary"):
		return ErrorTypeTemporary
	default:
		return ErrorTypeUnknown
	}
}

// isRetryable determines if an error should be retried
func (neh *NetworkErrorHandler) isRetryable(err error, errType ErrorType) bool {
	switch errType {
	case ErrorTypeTimeout, ErrorTypeTemporary, ErrorTypeNetworkUnreachable,
		ErrorTypeHostUnreachable, ErrorTypeConnectionRefused, ErrorTypeBufferError:
		return true
	case ErrorTypePermissionDenied, ErrorTypeAddressInUse, ErrorTypeProtocolError:
		return false
	default:
		// Use retry manager's logic if available
		if neh.retryManager != nil {
			return neh.retryManager.isRetryableError(err)
		}
		return false
	}
}

// isRecoverable determines if an error can be recovered from
func (neh *NetworkErrorHandler) isRecoverable(err error, errType ErrorType) bool {
	switch errType {
	case ErrorTypeTimeout, ErrorTypeTemporary, ErrorTypeBufferError,
		ErrorTypeConnectionRefused, ErrorTypeNetworkUnreachable:
		return true
	case ErrorTypePermissionDenied, ErrorTypeProtocolError:
		return false
	default:
		return true
	}
}

// determineSeverity determines the severity of an error
func (neh *NetworkErrorHandler) determineSeverity(err error, errType ErrorType) ErrorSeverity {
	switch errType {
	case ErrorTypePermissionDenied, ErrorTypeProtocolError:
		return SeverityCritical
	case ErrorTypeAddressInUse, ErrorTypeAddressNotAvailable:
		return SeverityHigh
	case ErrorTypeConnectionRefused, ErrorTypeNetworkUnreachable, ErrorTypeHostUnreachable:
		return SeverityMedium
	case ErrorTypeTimeout, ErrorTypeTemporary, ErrorTypeBufferError:
		return SeverityLow
	default:
		return SeverityMedium
	}
}

// attemptRecovery attempts to recover from a network error
func (neh *NetworkErrorHandler) attemptRecovery(networkErr *NetworkError) bool {
	if !networkErr.Recoverable {
		return false
	}

	// Get recovery actions for this error type
	actions := neh.getRecoveryActions(networkErr)
	if len(actions) == 0 {
		return false
	}

	// Attempt recovery actions in priority order
	for _, action := range actions {
		if neh.executeRecoveryAction(action, networkErr) {
			neh.recordSuccessfulRecovery(networkErr)
			return true
		}
	}

	neh.recordFailedRecovery(networkErr)
	return false
}

// getRecoveryActions returns appropriate recovery actions for an error
func (neh *NetworkErrorHandler) getRecoveryActions(networkErr *NetworkError) []RecoveryAction {
	var actions []RecoveryAction

	switch networkErr.Type {
	case ErrorTypeTimeout:
		actions = append(actions, RecoveryAction{
			Name:        "IncreaseTimeout",
			Description: "Increase timeout duration",
			Action:      neh.createIncreaseTimeoutAction(),
			Priority:    1,
			Timeout:     5 * time.Second,
		})

	case ErrorTypeBufferError:
		actions = append(actions, RecoveryAction{
			Name:        "ReduceBufferSize",
			Description: "Reduce socket buffer sizes",
			Action:      neh.createReduceBufferSizeAction(),
			Priority:    1,
			Timeout:     2 * time.Second,
		})

	case ErrorTypeConnectionRefused:
		actions = append(actions, RecoveryAction{
			Name:        "RetryWithDelay",
			Description: "Retry connection with exponential backoff",
			Action:      neh.createRetryWithDelayAction(),
			Priority:    1,
			Timeout:     10 * time.Second,
		})

	case ErrorTypeNetworkUnreachable, ErrorTypeHostUnreachable:
		actions = append(actions, RecoveryAction{
			Name:        "CheckConnectivity",
			Description: "Check network connectivity and routing",
			Action:      neh.createConnectivityCheckAction(),
			Priority:    1,
			Timeout:     15 * time.Second,
		})
	}

	// Add generic recovery actions
	actions = append(actions, RecoveryAction{
		Name:        "ResetConnection",
		Description: "Reset network connection",
		Action:      neh.createResetConnectionAction(),
		Priority:    2,
		Timeout:     10 * time.Second,
	})

	return actions
}

// executeRecoveryAction executes a recovery action with timeout
func (neh *NetworkErrorHandler) executeRecoveryAction(action RecoveryAction, networkErr *NetworkError) bool {
	ctx, cancel := context.WithTimeout(context.Background(), action.Timeout)
	defer cancel()

	done := make(chan error, 1)
	go func() {
		done <- action.Action()
	}()

	select {
	case err := <-done:
		return err == nil
	case <-ctx.Done():
		return false
	}
}

// Recovery action creators
func (neh *NetworkErrorHandler) createIncreaseTimeoutAction() func() error {
	return func() error {
		if neh.optimizer != nil {
			config := neh.optimizer.GetConfig()
			config.ReadTimeout = time.Duration(float64(config.ReadTimeout) * 1.5)
			config.WriteTimeout = time.Duration(float64(config.WriteTimeout) * 1.5)
			neh.optimizer.UpdateConfig(config)
		}
		return nil
	}
}

func (neh *NetworkErrorHandler) createReduceBufferSizeAction() func() error {
	return func() error {
		if neh.optimizer != nil {
			config := neh.optimizer.GetConfig()
			config.SendBufferSize = int(float64(config.SendBufferSize) * 0.8)
			config.RecvBufferSize = int(float64(config.RecvBufferSize) * 0.8)

			// Ensure minimum buffer sizes
			if config.SendBufferSize < 8192 {
				config.SendBufferSize = 8192
			}
			if config.RecvBufferSize < 8192 {
				config.RecvBufferSize = 8192
			}

			neh.optimizer.UpdateConfig(config)
		}
		return nil
	}
}

func (neh *NetworkErrorHandler) createRetryWithDelayAction() func() error {
	return func() error {
		// This is a placeholder - actual retry logic would be implemented
		// based on the specific operation being retried
		time.Sleep(100 * time.Millisecond)
		return nil
	}
}

func (neh *NetworkErrorHandler) createConnectivityCheckAction() func() error {
	return func() error {
		// Perform basic connectivity check
		// This is a simplified implementation
		conn, err := net.DialTimeout("tcp", "8.8.8.8:53", 5*time.Second)
		if err != nil {
			return err
		}
		conn.Close()
		return nil
	}
}

func (neh *NetworkErrorHandler) createResetConnectionAction() func() error {
	return func() error {
		// Reset network optimization settings to defaults
		if neh.optimizer != nil {
			neh.optimizer.UpdateConfig(DefaultOptimizationConfig())
		}
		return nil
	}
}

// updateErrorStats updates error statistics
func (neh *NetworkErrorHandler) updateErrorStats(networkErr *NetworkError) {
	neh.stats.mutex.Lock()
	defer neh.stats.mutex.Unlock()

	neh.stats.TotalErrors++
	neh.stats.ErrorsByType[networkErr.Type]++
	neh.stats.LastError = networkErr.Timestamp

	if networkErr.Recoverable {
		neh.stats.RecoverableErrors++
	} else {
		neh.stats.FatalErrors++
	}
}

// recordSuccessfulRecovery records a successful recovery attempt
func (neh *NetworkErrorHandler) recordSuccessfulRecovery(networkErr *NetworkError) {
	neh.stats.mutex.Lock()
	defer neh.stats.mutex.Unlock()

	neh.stats.SuccessfulRecoveries++
	neh.stats.LastRecovery = time.Now()
}

// recordFailedRecovery records a failed recovery attempt
func (neh *NetworkErrorHandler) recordFailedRecovery(networkErr *NetworkError) {
	neh.stats.mutex.Lock()
	defer neh.stats.mutex.Unlock()

	neh.stats.RecoveryAttempts++
}

// GetStats returns a copy of current error statistics
func (neh *NetworkErrorHandler) GetStats() ErrorStats {
	neh.stats.mutex.RLock()
	defer neh.stats.mutex.RUnlock()

	// Create a deep copy of the map
	errorsByType := make(map[ErrorType]uint64)
	for k, v := range neh.stats.ErrorsByType {
		errorsByType[k] = v
	}

	// Create a copy without the mutex
	stats := ErrorStats{
		TotalErrors:          neh.stats.TotalErrors,
		RecoverableErrors:    neh.stats.RecoverableErrors,
		FatalErrors:          neh.stats.FatalErrors,
		RecoveryAttempts:     neh.stats.RecoveryAttempts,
		SuccessfulRecoveries: neh.stats.SuccessfulRecoveries,
		ErrorsByType:         errorsByType,
		LastError:            neh.stats.LastError,
		LastRecovery:         neh.stats.LastRecovery,
	}

	return stats
}

// GetErrorRate returns the current error rate
func (neh *NetworkErrorHandler) GetErrorRate() float64 {
	stats := neh.GetStats()

	if neh.optimizer != nil {
		networkStats := neh.optimizer.GetStats()
		totalOperations := networkStats.PacketsSent

		if totalOperations > 0 {
			return float64(stats.TotalErrors) / float64(totalOperations)
		}
	}

	return 0.0
}

// IsErrorThresholdExceeded checks if the error rate exceeds the configured threshold
func (neh *NetworkErrorHandler) IsErrorThresholdExceeded() bool {
	errorRate := neh.GetErrorRate()
	return errorRate > neh.config.ErrorThreshold
}

// AdaptThreshold adapts the error threshold based on current conditions
func (neh *NetworkErrorHandler) AdaptThreshold() {
	if !neh.config.AdaptiveThreshold {
		return
	}

	errorRate := neh.GetErrorRate()

	neh.mutex.Lock()
	defer neh.mutex.Unlock()

	// Adjust threshold based on recent error patterns
	if errorRate < neh.config.ErrorThreshold*0.5 {
		// Low error rate - can be more sensitive
		neh.config.ErrorThreshold *= 0.9
		if neh.config.ErrorThreshold < 0.01 {
			neh.config.ErrorThreshold = 0.01
		}
	} else if errorRate > neh.config.ErrorThreshold*1.5 {
		// High error rate - be less sensitive
		neh.config.ErrorThreshold *= 1.1
		if neh.config.ErrorThreshold > 0.5 {
			neh.config.ErrorThreshold = 0.5
		}
	}
}

// String returns a string representation of ErrorType
func (et ErrorType) String() string {
	switch et {
	case ErrorTypeTimeout:
		return "Timeout"
	case ErrorTypeConnectionRefused:
		return "ConnectionRefused"
	case ErrorTypeNetworkUnreachable:
		return "NetworkUnreachable"
	case ErrorTypeHostUnreachable:
		return "HostUnreachable"
	case ErrorTypePermissionDenied:
		return "PermissionDenied"
	case ErrorTypeAddressInUse:
		return "AddressInUse"
	case ErrorTypeAddressNotAvailable:
		return "AddressNotAvailable"
	case ErrorTypeSocketError:
		return "SocketError"
	case ErrorTypeProtocolError:
		return "ProtocolError"
	case ErrorTypeBufferError:
		return "BufferError"
	case ErrorTypeTemporary:
		return "Temporary"
	default:
		return "Unknown"
	}
}

// Error implements the error interface for NetworkError
func (ne *NetworkError) Error() string {
	return fmt.Sprintf("[%s] %s (severity: %d, retryable: %t, recoverable: %t)",
		ne.Type.String(), ne.Original.Error(), ne.Severity, ne.Retryable, ne.Recoverable)
}

// String returns a string representation of ErrorSeverity
func (es ErrorSeverity) String() string {
	switch es {
	case SeverityLow:
		return "Low"
	case SeverityMedium:
		return "Medium"
	case SeverityHigh:
		return "High"
	case SeverityCritical:
		return "Critical"
	default:
		return "Unknown"
	}
}
