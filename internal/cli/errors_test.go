package cli

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestNewProbeError(t *testing.T) {
	code := ErrInvalidIPv6
	message := "test error message"
	cause := errors.New("underlying cause")

	err := NewProbeError(code, message, cause)

	if err.Code != code {
		t.Errorf("Expected Code=%v, got %v", code, err.Code)
	}
	if err.Message != message {
		t.Errorf("Expected Message=%s, got %s", message, err.Message)
	}
	if err.Cause != cause {
		t.Errorf("Expected Cause=%v, got %v", cause, err.Cause)
	}
	if err.Severity != SeverityError {
		t.Errorf("Expected Severity=%v, got %v", SeverityError, err.Severity)
	}
	if err.Context == nil {
		t.Error("Context should be initialized")
	}
}

func TestNewProbeErrorWithSeverity(t *testing.T) {
	code := ErrPermissionDenied
	message := "permission denied"
	cause := errors.New("access denied")
	severity := SeverityFatal

	err := NewProbeErrorWithSeverity(code, message, cause, severity)

	if err.Severity != severity {
		t.Errorf("Expected Severity=%v, got %v", severity, err.Severity)
	}
}

func TestProbeErrorError(t *testing.T) {
	// Test with cause
	cause := errors.New("underlying error")
	err := NewProbeError(ErrSocketCreate, "socket creation failed", cause)
	expected := "socket creation failed: underlying error"
	if err.Error() != expected {
		t.Errorf("Expected Error()=%s, got %s", expected, err.Error())
	}

	// Test without cause
	err2 := NewProbeError(ErrInvalidArgs, "invalid arguments", nil)
	expected2 := "invalid arguments"
	if err2.Error() != expected2 {
		t.Errorf("Expected Error()=%s, got %s", expected2, err2.Error())
	}
}

func TestProbeErrorString(t *testing.T) {
	err := NewProbeError(ErrInvalidIPv6, "invalid address", nil)
	err.WithContext("address", "invalid::address")

	str := err.String()

	// Check that it contains expected components
	if !strings.Contains(str, "[ERROR]") {
		t.Error("String should contain severity prefix")
	}
	if !strings.Contains(str, "INVALID_IPV6") {
		t.Error("String should contain error code")
	}
	if !strings.Contains(str, "invalid address") {
		t.Error("String should contain message")
	}
	if !strings.Contains(str, "address=invalid::address") {
		t.Error("String should contain context")
	}
}

func TestProbeErrorWithContext(t *testing.T) {
	err := NewProbeError(ErrSocketCreate, "test", nil)

	err.WithContext("key1", "value1")
	err.WithContext("key2", 42)

	if err.Context["key1"] != "value1" {
		t.Errorf("Expected Context[key1]=value1, got %v", err.Context["key1"])
	}
	if err.Context["key2"] != 42 {
		t.Errorf("Expected Context[key2]=42, got %v", err.Context["key2"])
	}
}

func TestProbeErrorWithRetryable(t *testing.T) {
	err := NewProbeError(ErrSocketCreate, "test", nil)

	// Test setting retryable to true
	err.WithRetryable(true)
	if !err.IsRetryable() {
		t.Error("Expected error to be retryable")
	}

	// Test setting retryable to false
	err.WithRetryable(false)
	if err.IsRetryable() {
		t.Error("Expected error to not be retryable")
	}
}

func TestErrorCodeString(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		expected string
	}{
		{ErrSuccess, "SUCCESS"},
		{ErrInvalidArgs, "INVALID_ARGS"},
		{ErrPermissionDenied, "PERMISSION_DENIED"},
		{ErrInvalidIPv6, "INVALID_IPV6"},
		{ErrSocketCreate, "SOCKET_CREATE"},
		{ErrRecvTimeout, "RECV_TIMEOUT"},
		{ErrTargetUnreachable, "TARGET_UNREACHABLE"},
		{ErrorCode(999), "UNKNOWN"}, // Test unknown code
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			result := tt.code.String()
			if result != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestIsRetryableByDefault(t *testing.T) {
	retryableCodes := []ErrorCode{
		ErrRecvTimeout,
		ErrProbeTimeout,
		ErrSendFailed,
		ErrNetworkUnreachable,
	}

	for _, code := range retryableCodes {
		if !isRetryableByDefault(code) {
			t.Errorf("Expected %v to be retryable by default", code)
		}
	}

	nonRetryableCodes := []ErrorCode{
		ErrInvalidArgs,
		ErrPermissionDenied,
		ErrInvalidIPv6,
		ErrInvalidMTURange,
	}

	for _, code := range nonRetryableCodes {
		if isRetryableByDefault(code) {
			t.Errorf("Expected %v to not be retryable by default", code)
		}
	}
}

func TestGetUserFriendlyMessage(t *testing.T) {
	tests := []struct {
		code     ErrorCode
		contains string
	}{
		{ErrInvalidArgs, "Invalid command line arguments"},
		{ErrPermissionDenied, "root/administrator privileges"},
		{ErrInvalidIPv6, "Invalid IPv6 address format"},
		{ErrSocketCreate, "Failed to create network socket"},
		{ErrTargetUnreachable, "Target host is unreachable"},
		{ErrRecvTimeout, "Network operation timed out"},
		{ErrMTUTooSmall, "MTU is too small"},
		{ErrMSSDetectionFailed, "TCP MSS detection failed"},
		{ErrContextCanceled, "Operation was cancelled"},
	}

	for _, tt := range tests {
		t.Run(tt.code.String(), func(t *testing.T) {
			err := NewProbeError(tt.code, "test message", nil)
			message := err.GetUserFriendlyMessage()

			if !strings.Contains(message, tt.contains) {
				t.Errorf("Expected message to contain '%s', got '%s'", tt.contains, message)
			}
		})
	}
}

func TestIsTimeoutError(t *testing.T) {
	// Test ProbeError timeout
	timeoutErr := NewProbeError(ErrRecvTimeout, "timeout", nil)
	if !IsTimeoutError(timeoutErr) {
		t.Error("Expected timeout error to be detected")
	}

	probeTimeoutErr := NewProbeError(ErrProbeTimeout, "probe timeout", nil)
	if !IsTimeoutError(probeTimeoutErr) {
		t.Error("Expected probe timeout error to be detected")
	}

	// Test non-timeout error
	nonTimeoutErr := NewProbeError(ErrInvalidArgs, "invalid", nil)
	if IsTimeoutError(nonTimeoutErr) {
		t.Error("Expected non-timeout error to not be detected as timeout")
	}

	// Test standard Go timeout error
	// We can't easily create a real net.Error with timeout, so we'll test with nil
	if IsTimeoutError(nil) {
		t.Error("nil should not be timeout error")
	}
}

func TestIsPermissionError(t *testing.T) {
	permErr := NewProbeError(ErrPermissionDenied, "permission denied", nil)
	if !IsPermissionError(permErr) {
		t.Error("Expected permission error to be detected")
	}

	nonPermErr := NewProbeError(ErrInvalidArgs, "invalid", nil)
	if IsPermissionError(nonPermErr) {
		t.Error("Expected non-permission error to not be detected as permission error")
	}
}

func TestIsNetworkError(t *testing.T) {
	networkCodes := []ErrorCode{
		ErrSocketCreate,
		ErrSocketBind,
		ErrSendFailed,
		ErrRecvTimeout,
		ErrTargetUnreachable,
		ErrNetworkUnreachable,
		ErrConnectionRefused,
		ErrHostUnreachable,
		ErrProbeTimeout,
	}

	for _, code := range networkCodes {
		err := NewProbeError(code, "test", nil)
		if !IsNetworkError(err) {
			t.Errorf("Expected %v to be detected as network error", code)
		}
	}

	nonNetworkErr := NewProbeError(ErrInvalidArgs, "invalid", nil)
	if IsNetworkError(nonNetworkErr) {
		t.Error("Expected non-network error to not be detected as network error")
	}
}

func TestIsRetryableError(t *testing.T) {
	retryableErr := NewProbeError(ErrRecvTimeout, "timeout", nil)
	if !IsRetryableError(retryableErr) {
		t.Error("Expected retryable error to be detected")
	}

	nonRetryableErr := NewProbeError(ErrInvalidArgs, "invalid", nil)
	if IsRetryableError(nonRetryableErr) {
		t.Error("Expected non-retryable error to not be detected as retryable")
	}

	// Test with custom retryable setting
	customErr := NewProbeError(ErrInvalidArgs, "invalid", nil).WithRetryable(true)
	if !IsRetryableError(customErr) {
		t.Error("Expected custom retryable error to be detected")
	}
}

func TestIsFatalError(t *testing.T) {
	fatalCodes := []ErrorCode{
		ErrPermissionDenied,
		ErrInvalidArgs,
		ErrContextCanceled,
	}

	for _, code := range fatalCodes {
		err := NewProbeError(code, "test", nil)
		if !IsFatalError(err) {
			t.Errorf("Expected %v to be detected as fatal error", code)
		}
	}

	// Test with fatal severity
	fatalSeverityErr := NewProbeErrorWithSeverity(ErrSocketCreate, "test", nil, SeverityFatal)
	if !IsFatalError(fatalSeverityErr) {
		t.Error("Expected fatal severity error to be detected as fatal")
	}

	// Test context cancellation
	if !IsFatalError(context.Canceled) {
		t.Error("Expected context.Canceled to be fatal")
	}

	if !IsFatalError(context.DeadlineExceeded) {
		t.Error("Expected context.DeadlineExceeded to be fatal")
	}

	nonFatalErr := NewProbeError(ErrRecvTimeout, "timeout", nil)
	if IsFatalError(nonFatalErr) {
		t.Error("Expected non-fatal error to not be detected as fatal")
	}
}

func TestWrapNetworkError(t *testing.T) {
	// Test with nil error
	result := WrapNetworkError(nil, "test")
	if result != nil {
		t.Error("Expected nil result for nil error")
	}

	// Test with generic error
	genericErr := errors.New("connection refused")
	wrapped := WrapNetworkError(genericErr, "connect")

	if wrapped == nil {
		t.Fatal("Expected wrapped error")
	}

	if wrapped.Code != ErrConnectionRefused {
		t.Errorf("Expected Code=%v, got %v", ErrConnectionRefused, wrapped.Code)
	}

	if wrapped.Context["operation"] != "connect" {
		t.Errorf("Expected operation context to be 'connect', got %v", wrapped.Context["operation"])
	}

	// Test permission denied pattern
	permErr := errors.New("permission denied")
	wrappedPerm := WrapNetworkError(permErr, "socket")
	if wrappedPerm.Code != ErrPermissionDenied {
		t.Errorf("Expected Code=%v, got %v", ErrPermissionDenied, wrappedPerm.Code)
	}
}

func TestCreateTimeoutError(t *testing.T) {
	timeout := 5 * time.Second
	err := CreateTimeoutError("probe", timeout)

	if err.Code != ErrProbeTimeout {
		t.Errorf("Expected Code=%v, got %v", ErrProbeTimeout, err.Code)
	}

	if !err.IsRetryable() {
		t.Error("Expected timeout error to be retryable")
	}

	if err.Context["operation"] != "probe" {
		t.Errorf("Expected operation context to be 'probe', got %v", err.Context["operation"])
	}

	if err.Context["timeout"] != timeout {
		t.Errorf("Expected timeout context to be %v, got %v", timeout, err.Context["timeout"])
	}
}

func TestCreateValidationError(t *testing.T) {
	field := "ipv6_address"
	value := "invalid::address"
	reason := "malformed format"

	err := CreateValidationError(field, value, reason)

	if err.Code != ErrInvalidArgs {
		t.Errorf("Expected Code=%v, got %v", ErrInvalidArgs, err.Code)
	}

	if err.IsRetryable() {
		t.Error("Expected validation error to not be retryable")
	}

	if err.Context["field"] != field {
		t.Errorf("Expected field context to be '%s', got %v", field, err.Context["field"])
	}

	if err.Context["value"] != value {
		t.Errorf("Expected value context to be '%s', got %v", value, err.Context["value"])
	}
}

func TestCreatePermissionError(t *testing.T) {
	operation := "create raw socket"
	err := CreatePermissionError(operation)

	if err.Code != ErrPermissionDenied {
		t.Errorf("Expected Code=%v, got %v", ErrPermissionDenied, err.Code)
	}

	if err.Severity != SeverityFatal {
		t.Errorf("Expected Severity=%v, got %v", SeverityFatal, err.Severity)
	}

	if err.IsRetryable() {
		t.Error("Expected permission error to not be retryable")
	}

	if err.Context["operation"] != operation {
		t.Errorf("Expected operation context to be '%s', got %v", operation, err.Context["operation"])
	}

	message := err.GetUserFriendlyMessage()
	if !strings.Contains(message, "root/administrator") {
		t.Error("Expected user-friendly message to mention privileges")
	}
}

// Mock net.Error for testing
type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

func TestNetworkErrorDetection(t *testing.T) {
	// Test timeout detection with mock net.Error
	timeoutNetErr := &mockNetError{timeout: true, msg: "timeout"}
	if !IsTimeoutError(timeoutNetErr) {
		t.Error("Expected mock timeout error to be detected")
	}

	// Test retryable detection with mock net.Error
	tempNetErr := &mockNetError{temporary: true, msg: "temporary"}
	if !IsRetryableError(tempNetErr) {
		t.Error("Expected mock temporary error to be retryable")
	}

	// Test network error detection with mock net.Error
	netErr := &mockNetError{msg: "network error"}
	if !IsNetworkError(netErr) {
		t.Error("Expected mock net.Error to be detected as network error")
	}
}
