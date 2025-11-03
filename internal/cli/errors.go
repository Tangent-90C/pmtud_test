package cli

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// ErrorCode represents different types of errors
type ErrorCode int

const (
	ErrSuccess ErrorCode = iota
	ErrInvalidArgs
	ErrPermissionDenied
	ErrInvalidIPv6
	ErrSocketCreate
	ErrSocketBind
	ErrSendFailed
	ErrRecvTimeout
	ErrTargetUnreachable
	ErrMTUTooSmall
	ErrMSSDetectionFailed
	ErrContextCanceled
	ErrNetworkUnreachable
	ErrConnectionRefused
	ErrHostUnreachable
	ErrProbeTimeout
	ErrInvalidMTURange
	ErrInvalidPortRange
	ErrConfigurationError
	ErrSystemError
	// Target unreachability detection errors
	ErrTargetUnreachableTimeout
	ErrTargetUnreachableICMP
	ErrTargetUnreachableNetwork
	ErrTargetUnreachableFiltered
)

// ErrorSeverity represents the severity level of an error
type ErrorSeverity int

const (
	SeverityInfo ErrorSeverity = iota
	SeverityWarning
	SeverityError
	SeverityFatal
)

// ProbeError represents a custom error with error code and additional context
type ProbeError struct {
	Code      ErrorCode
	Message   string
	Cause     error
	Severity  ErrorSeverity
	Timestamp time.Time
	Context   map[string]interface{}
	Retryable bool
}

// Error implements the error interface
func (e *ProbeError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s: %v", e.Message, e.Cause)
	}
	return e.Message
}

// String returns a detailed string representation of the error
func (e *ProbeError) String() string {
	var parts []string

	// Add severity prefix
	switch e.Severity {
	case SeverityFatal:
		parts = append(parts, "[FATAL]")
	case SeverityError:
		parts = append(parts, "[ERROR]")
	case SeverityWarning:
		parts = append(parts, "[WARNING]")
	case SeverityInfo:
		parts = append(parts, "[INFO]")
	}

	// Add error code
	parts = append(parts, fmt.Sprintf("(%s)", e.Code.String()))

	// Add message
	parts = append(parts, e.Message)

	// Add cause if present
	if e.Cause != nil {
		parts = append(parts, fmt.Sprintf("caused by: %v", e.Cause))
	}

	// Add context information
	if len(e.Context) > 0 {
		var contextParts []string
		for key, value := range e.Context {
			contextParts = append(contextParts, fmt.Sprintf("%s=%v", key, value))
		}
		parts = append(parts, fmt.Sprintf("context: {%s}", strings.Join(contextParts, ", ")))
	}

	return strings.Join(parts, " ")
}

// NewProbeError creates a new ProbeError with basic information
func NewProbeError(code ErrorCode, message string, cause error) *ProbeError {
	return &ProbeError{
		Code:      code,
		Message:   message,
		Cause:     cause,
		Severity:  SeverityError,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
		Retryable: isRetryableByDefault(code),
	}
}

// NewProbeErrorWithSeverity creates a new ProbeError with specified severity
func NewProbeErrorWithSeverity(code ErrorCode, message string, cause error, severity ErrorSeverity) *ProbeError {
	return &ProbeError{
		Code:      code,
		Message:   message,
		Cause:     cause,
		Severity:  severity,
		Timestamp: time.Now(),
		Context:   make(map[string]interface{}),
		Retryable: isRetryableByDefault(code),
	}
}

// WithContext adds context information to the error
func (e *ProbeError) WithContext(key string, value interface{}) *ProbeError {
	if e.Context == nil {
		e.Context = make(map[string]interface{})
	}
	e.Context[key] = value
	return e
}

// WithRetryable sets whether the error is retryable
func (e *ProbeError) WithRetryable(retryable bool) *ProbeError {
	e.Retryable = retryable
	return e
}

// IsRetryable returns whether the error should be retried
func (e *ProbeError) IsRetryable() bool {
	return e.Retryable
}

// GetUserFriendlyMessage returns a user-friendly error message
func (e *ProbeError) GetUserFriendlyMessage() string {
	switch e.Code {
	case ErrInvalidArgs:
		return "Invalid command line arguments. Please check your input and try again."
	case ErrPermissionDenied:
		return "Permission denied. This tool requires root/administrator privileges to create raw sockets."
	case ErrInvalidIPv6:
		return "Invalid IPv6 address format. Please provide a valid IPv6 address."
	case ErrSocketCreate:
		return "Failed to create network socket. Please check your network configuration and permissions."
	case ErrTargetUnreachable:
		return "Target host is unreachable. Please verify the IPv6 address and network connectivity."
	case ErrRecvTimeout, ErrProbeTimeout:
		return "Network operation timed out. The target may be unreachable or network is slow."
	case ErrMTUTooSmall:
		return "Discovered MTU is too small for practical use. There may be network configuration issues."
	case ErrMSSDetectionFailed:
		return "TCP MSS detection failed. The target may not accept TCP connections on the specified port."
	case ErrContextCanceled:
		return "Operation was cancelled by user or timeout."
	case ErrNetworkUnreachable:
		return "Network is unreachable. Please check your IPv6 connectivity and routing."
	case ErrConnectionRefused:
		return "Connection refused by target. The service may not be running on the specified port."
	case ErrHostUnreachable:
		return "Host is unreachable. Please verify the IPv6 address and network path."
	case ErrInvalidMTURange:
		return "Invalid MTU range specified. MTU values must be between 68 and 65535 bytes."
	case ErrInvalidPortRange:
		return "Invalid port number. Port must be between 1 and 65535."
	case ErrConfigurationError:
		return "Configuration error. Please check your settings and try again."
	case ErrSystemError:
		return "System error occurred. Please check system logs for more details."
	case ErrTargetUnreachableTimeout:
		return "Target is unreachable due to timeouts. The host may be down or network path is blocked."
	case ErrTargetUnreachableICMP:
		return "Target is unreachable due to ICMP errors. Check firewall and network configuration."
	case ErrTargetUnreachableNetwork:
		return "Target network is unreachable. Check routing and network connectivity."
	case ErrTargetUnreachableFiltered:
		return "Target appears to be filtered or blocked. Check firewall rules and access policies."
	default:
		return e.Message
	}
}

// String returns the string representation of ErrorCode
func (ec ErrorCode) String() string {
	switch ec {
	case ErrSuccess:
		return "SUCCESS"
	case ErrInvalidArgs:
		return "INVALID_ARGS"
	case ErrPermissionDenied:
		return "PERMISSION_DENIED"
	case ErrInvalidIPv6:
		return "INVALID_IPV6"
	case ErrSocketCreate:
		return "SOCKET_CREATE"
	case ErrSocketBind:
		return "SOCKET_BIND"
	case ErrSendFailed:
		return "SEND_FAILED"
	case ErrRecvTimeout:
		return "RECV_TIMEOUT"
	case ErrTargetUnreachable:
		return "TARGET_UNREACHABLE"
	case ErrMTUTooSmall:
		return "MTU_TOO_SMALL"
	case ErrMSSDetectionFailed:
		return "MSS_DETECTION_FAILED"
	case ErrContextCanceled:
		return "CONTEXT_CANCELED"
	case ErrNetworkUnreachable:
		return "NETWORK_UNREACHABLE"
	case ErrConnectionRefused:
		return "CONNECTION_REFUSED"
	case ErrHostUnreachable:
		return "HOST_UNREACHABLE"
	case ErrProbeTimeout:
		return "PROBE_TIMEOUT"
	case ErrInvalidMTURange:
		return "INVALID_MTU_RANGE"
	case ErrInvalidPortRange:
		return "INVALID_PORT_RANGE"
	case ErrConfigurationError:
		return "CONFIGURATION_ERROR"
	case ErrSystemError:
		return "SYSTEM_ERROR"
	case ErrTargetUnreachableTimeout:
		return "TARGET_UNREACHABLE_TIMEOUT"
	case ErrTargetUnreachableICMP:
		return "TARGET_UNREACHABLE_ICMP"
	case ErrTargetUnreachableNetwork:
		return "TARGET_UNREACHABLE_NETWORK"
	case ErrTargetUnreachableFiltered:
		return "TARGET_UNREACHABLE_FILTERED"
	default:
		return "UNKNOWN"
	}
}

// isRetryableByDefault determines if an error code is retryable by default
func isRetryableByDefault(code ErrorCode) bool {
	switch code {
	case ErrRecvTimeout, ErrProbeTimeout, ErrSendFailed, ErrNetworkUnreachable, ErrTargetUnreachableTimeout:
		return true
	case ErrInvalidArgs, ErrPermissionDenied, ErrInvalidIPv6, ErrInvalidMTURange, ErrInvalidPortRange,
		ErrTargetUnreachableICMP, ErrTargetUnreachableNetwork, ErrTargetUnreachableFiltered:
		return false
	default:
		return false
	}
}

// Predefined errors for common scenarios
var (
	ErrInvalidArgsInstance      = NewProbeError(ErrInvalidArgs, "invalid arguments", nil)
	ErrPermissionDeniedInstance = NewProbeError(ErrPermissionDenied, "permission denied", nil)
	ErrContextCanceledInstance  = NewProbeError(ErrContextCanceled, "operation canceled", nil)
)

// Error classification functions

// IsTimeoutError checks if the error is a timeout error
func IsTimeoutError(err error) bool {
	if probeErr, ok := err.(*ProbeError); ok {
		return probeErr.Code == ErrRecvTimeout || probeErr.Code == ErrProbeTimeout
	}

	// Check for standard Go timeout errors
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout()
	}

	return false
}

// IsPermissionError checks if the error is a permission error
func IsPermissionError(err error) bool {
	if probeErr, ok := err.(*ProbeError); ok {
		return probeErr.Code == ErrPermissionDenied
	}
	return false
}

// IsNetworkError checks if the error is a network-related error
func IsNetworkError(err error) bool {
	if probeErr, ok := err.(*ProbeError); ok {
		switch probeErr.Code {
		case ErrSocketCreate, ErrSocketBind, ErrSendFailed, ErrRecvTimeout,
			ErrTargetUnreachable, ErrNetworkUnreachable, ErrConnectionRefused,
			ErrHostUnreachable, ErrProbeTimeout, ErrTargetUnreachableTimeout,
			ErrTargetUnreachableICMP, ErrTargetUnreachableNetwork, ErrTargetUnreachableFiltered:
			return true
		}
	}

	// Check for standard Go network errors
	if _, ok := err.(net.Error); ok {
		return true
	}

	return false
}

// IsRetryableError checks if the error should be retried
func IsRetryableError(err error) bool {
	if probeErr, ok := err.(*ProbeError); ok {
		return probeErr.IsRetryable()
	}

	// Check for standard retryable errors
	if netErr, ok := err.(net.Error); ok {
		return netErr.Timeout() || netErr.Temporary()
	}

	return false
}

// IsFatalError checks if the error is fatal and should stop execution
func IsFatalError(err error) bool {
	if probeErr, ok := err.(*ProbeError); ok {
		return probeErr.Severity == SeverityFatal ||
			probeErr.Code == ErrPermissionDenied ||
			probeErr.Code == ErrInvalidArgs ||
			probeErr.Code == ErrContextCanceled
	}

	// Context cancellation is always fatal
	if err == context.Canceled || err == context.DeadlineExceeded {
		return true
	}

	return false
}

// Error creation helpers

// WrapNetworkError wraps a standard network error into a ProbeError
func WrapNetworkError(err error, operation string) *ProbeError {
	if err == nil {
		return nil
	}

	var code ErrorCode
	var message string

	if netErr, ok := err.(net.Error); ok {
		if netErr.Timeout() {
			code = ErrRecvTimeout
			message = fmt.Sprintf("network timeout during %s", operation)
		} else if netErr.Temporary() {
			code = ErrSendFailed
			message = fmt.Sprintf("temporary network error during %s", operation)
		} else {
			code = ErrSystemError
			message = fmt.Sprintf("network error during %s", operation)
		}
	} else {
		// Check error message for common patterns
		errMsg := strings.ToLower(err.Error())
		switch {
		case strings.Contains(errMsg, "permission denied"):
			code = ErrPermissionDenied
			message = "permission denied for network operation"
		case strings.Contains(errMsg, "connection refused"):
			code = ErrConnectionRefused
			message = "connection refused by target"
		case strings.Contains(errMsg, "no route to host"):
			code = ErrHostUnreachable
			message = "no route to target host"
		case strings.Contains(errMsg, "network is unreachable"):
			code = ErrNetworkUnreachable
			message = "network is unreachable"
		default:
			code = ErrSystemError
			message = fmt.Sprintf("system error during %s", operation)
		}
	}

	return NewProbeError(code, message, err).WithContext("operation", operation)
}

// CreateTimeoutError creates a timeout error with context
func CreateTimeoutError(operation string, timeout time.Duration) *ProbeError {
	return NewProbeError(ErrProbeTimeout,
		fmt.Sprintf("operation timed out after %v", timeout), nil).
		WithContext("operation", operation).
		WithContext("timeout", timeout).
		WithRetryable(true)
}

// CreateValidationError creates a validation error
func CreateValidationError(field string, value interface{}, reason string) *ProbeError {
	message := fmt.Sprintf("validation failed for %s: %s", field, reason)
	return NewProbeError(ErrInvalidArgs, message, nil).
		WithContext("field", field).
		WithContext("value", value).
		WithRetryable(false)
}

// CreatePermissionError creates a permission error with helpful message
func CreatePermissionError(operation string) *ProbeError {
	message := fmt.Sprintf("insufficient privileges for %s - root/administrator access required", operation)
	return NewProbeErrorWithSeverity(ErrPermissionDenied, message, nil, SeverityFatal).
		WithContext("operation", operation).
		WithRetryable(false)
}
