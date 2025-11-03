package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"time"
)

// ErrorHandler provides unified error handling and reporting
type ErrorHandler struct {
	writer       io.Writer
	verbose      bool
	logErrors    bool
	retryManager *RetryManager
}

// ErrorHandlerConfig configures the error handler behavior
type ErrorHandlerConfig struct {
	Writer      io.Writer
	Verbose     bool
	LogErrors   bool
	RetryConfig *RetryConfig
}

// NewErrorHandler creates a new error handler with the given configuration
func NewErrorHandler(config *ErrorHandlerConfig) *ErrorHandler {
	if config == nil {
		config = &ErrorHandlerConfig{}
	}

	writer := config.Writer
	if writer == nil {
		writer = os.Stderr
	}

	retryConfig := config.RetryConfig
	if retryConfig == nil {
		retryConfig = DefaultRetryConfig()
	}

	return &ErrorHandler{
		writer:       writer,
		verbose:      config.Verbose,
		logErrors:    config.LogErrors,
		retryManager: NewRetryManager(retryConfig),
	}
}

// HandleError processes and displays an error appropriately
func (eh *ErrorHandler) HandleError(err error) {
	if err == nil {
		return
	}

	// Log the error if logging is enabled
	if eh.logErrors {
		eh.logError(err)
	}

	// Display the error to the user
	eh.displayError(err)
}

// HandleErrorWithExit processes an error and exits with appropriate code
func (eh *ErrorHandler) HandleErrorWithExit(err error) {
	if err == nil {
		return
	}

	eh.HandleError(err)

	// Determine exit code based on error type
	exitCode := eh.getExitCode(err)
	os.Exit(exitCode)
}

// ExecuteWithRetry executes an operation with retry logic and error handling
func (eh *ErrorHandler) ExecuteWithRetry(ctx context.Context, operation RetryableOperation, operationName string) error {
	return eh.retryManager.RetryWithCallback(ctx, operation, func(attempt int, err error, delay time.Duration) {
		if err != nil && eh.verbose {
			if attempt == 1 {
				fmt.Fprintf(eh.writer, "Operation '%s' failed, retrying...\n", operationName)
			}
			fmt.Fprintf(eh.writer, "  Attempt %d failed: %s\n", attempt, eh.getShortErrorMessage(err))
			if delay > 0 {
				fmt.Fprintf(eh.writer, "  Waiting %v before next attempt...\n", delay.Round(time.Millisecond))
			}
		} else if err == nil && attempt > 1 && eh.verbose {
			fmt.Fprintf(eh.writer, "  Operation succeeded on attempt %d\n", attempt)
		}
	})
}

// ExecuteWithRetryAndResult executes an operation with retry logic and returns a result
// Note: Generic version commented out due to Go version compatibility
// func (eh *ErrorHandler) ExecuteWithRetryAndResult[T any](ctx context.Context, operation RetryableOperationWithResult[T], operationName string) (T, error) {
//	var zeroValue T
//
//	result, err := eh.retryManager.ExecuteWithResult(ctx, operation)
//	if err != nil && eh.verbose {
//		fmt.Fprintf(eh.writer, "Operation '%s' failed after all retry attempts\n", operationName)
//	}
//
//	return result, err
// }

// displayError displays an error message to the user
func (eh *ErrorHandler) displayError(err error) {
	if probeErr, ok := err.(*ProbeError); ok {
		eh.displayProbeError(probeErr)
	} else {
		// Handle standard Go errors
		fmt.Fprintf(eh.writer, "Error: %s\n", err.Error())
	}
}

// displayProbeError displays a ProbeError with appropriate formatting
func (eh *ErrorHandler) displayProbeError(err *ProbeError) {
	// Display severity indicator
	severityIcon := eh.getSeverityIcon(err.Severity)

	if eh.verbose {
		// Verbose mode: show detailed error information
		fmt.Fprintf(eh.writer, "%s %s\n", severityIcon, err.String())
	} else {
		// Normal mode: show user-friendly message
		fmt.Fprintf(eh.writer, "%s %s\n", severityIcon, err.GetUserFriendlyMessage())
	}

	// Show suggestions for common errors
	eh.displayErrorSuggestions(err)
}

// displayErrorSuggestions shows helpful suggestions for resolving errors
func (eh *ErrorHandler) displayErrorSuggestions(err *ProbeError) {
	suggestions := eh.getErrorSuggestions(err.Code)
	if len(suggestions) > 0 {
		fmt.Fprintln(eh.writer)
		fmt.Fprintln(eh.writer, "Suggestions:")
		for _, suggestion := range suggestions {
			fmt.Fprintf(eh.writer, "  • %s\n", suggestion)
		}
	}
}

// getErrorSuggestions returns helpful suggestions for resolving specific errors
func (eh *ErrorHandler) getErrorSuggestions(code ErrorCode) []string {
	switch code {
	case ErrPermissionDenied:
		return []string{
			"Run the command with sudo (Linux/macOS) or as Administrator (Windows)",
			"Ensure your user account has the necessary network privileges",
			"Check if security software is blocking raw socket access",
		}
	case ErrInvalidIPv6:
		return []string{
			"Verify the IPv6 address format (e.g., 2400:3200::1)",
			"Use brackets for IPv6 addresses with ports (e.g., [2400:3200::1]:80)",
			"Check if the address is a valid unicast IPv6 address",
		}
	case ErrTargetUnreachable, ErrNetworkUnreachable:
		return []string{
			"Verify your IPv6 connectivity with 'ping6' command",
			"Check your network routing configuration",
			"Ensure the target address is reachable from your network",
			"Try using a different IPv6 address or network interface",
		}
	case ErrConnectionRefused:
		return []string{
			"Verify the target service is running on the specified port",
			"Check if a firewall is blocking the connection",
			"Try a different port number",
			"Ensure the target accepts IPv6 connections",
		}
	case ErrRecvTimeout, ErrProbeTimeout:
		return []string{
			"Increase the timeout value with --timeout option",
			"Check your network latency to the target",
			"Verify the target responds to ICMP6 packets",
			"Try reducing the MTU size being tested",
		}
	case ErrMTUTooSmall:
		return []string{
			"Check for network configuration issues",
			"Verify tunnel or VPN MTU settings",
			"Contact your network administrator",
		}
	case ErrMSSDetectionFailed:
		return []string{
			"Verify the target port accepts TCP connections",
			"Check if the target service supports IPv6",
			"Try a different port (e.g., 80, 443, 22)",
			"Ensure no firewall is blocking TCP connections",
		}
	default:
		return nil
	}
}

// getSeverityIcon returns an icon representing the error severity
func (eh *ErrorHandler) getSeverityIcon(severity ErrorSeverity) string {
	switch severity {
	case SeverityFatal:
		return "💀"
	case SeverityError:
		return "❌"
	case SeverityWarning:
		return "⚠️"
	case SeverityInfo:
		return "ℹ️"
	default:
		return "❓"
	}
}

// getShortErrorMessage returns a concise error message for display
func (eh *ErrorHandler) getShortErrorMessage(err error) string {
	if probeErr, ok := err.(*ProbeError); ok {
		return probeErr.Message
	}
	return err.Error()
}

// getExitCode determines the appropriate exit code for an error
func (eh *ErrorHandler) getExitCode(err error) int {
	if probeErr, ok := err.(*ProbeError); ok {
		switch probeErr.Code {
		case ErrSuccess:
			return 0
		case ErrInvalidArgs:
			return 2
		case ErrPermissionDenied:
			return 77 // EX_NOPERM
		case ErrTargetUnreachable, ErrNetworkUnreachable, ErrHostUnreachable:
			return 68 // EX_NOHOST
		case ErrConnectionRefused:
			return 61 // EX_NOUSER (closest to connection refused)
		case ErrRecvTimeout, ErrProbeTimeout:
			return 70 // EX_SOFTWARE
		case ErrContextCanceled:
			return 130 // Interrupted by signal
		default:
			return 1 // General error
		}
	}

	// Handle context errors
	if err == context.Canceled {
		return 130
	}
	if err == context.DeadlineExceeded {
		return 124
	}

	return 1 // General error
}

// logError logs detailed error information
func (eh *ErrorHandler) logError(err error) {
	timestamp := time.Now().Format("2006-01-02 15:04:05")

	if probeErr, ok := err.(*ProbeError); ok {
		fmt.Fprintf(eh.writer, "[%s] ERROR: %s\n", timestamp, probeErr.String())
	} else {
		fmt.Fprintf(eh.writer, "[%s] ERROR: %s\n", timestamp, err.Error())
	}
}

// SetVerbose changes the verbosity level
func (eh *ErrorHandler) SetVerbose(verbose bool) {
	eh.verbose = verbose
}

// SetLogErrors enables or disables error logging
func (eh *ErrorHandler) SetLogErrors(logErrors bool) {
	eh.logErrors = logErrors
}

// GetRetryManager returns the retry manager
func (eh *ErrorHandler) GetRetryManager() *RetryManager {
	return eh.retryManager
}

// WrapOperation wraps an operation to provide consistent err
func (eh *ErrorHandler) WrapOperation(operationName string, operation func() error) error {
	err := operation()
	if err != nil {
		// Add operation context to the error
		if probeErr, ok := err.(*ProbeError); ok {
			return probeErr.WithContext("operation", operationName)
		}
		return WrapNetworkError(err, operationName)
	}
	return nil
}

// ValidateAndExecute validates arguments and executes an operation
func (eh *ErrorHandler) ValidateAndExecute(args *CLIArgs, operation func(*CLIArgs) error) error {
	// Validate arguments first
	if err := args.Validate(); err != nil {
		return err
	}

	// Execute the operation
	return eh.WrapOperation("main operation", func() error {
		return operation(args)
	})
}

// CreateProgressCallback creates a callback for displaying retry progress
func (eh *ErrorHandler) CreateProgressCallback(operationName string) func(int, error, time.Duration) {
	return func(attempt int, err error, delay time.Duration) {
		if !eh.verbose {
			return
		}

		if err != nil {
			if attempt == 1 {
				fmt.Fprintf(eh.writer, "Operation '%s' failed, retrying...\n", operationName)
			}
			fmt.Fprintf(eh.writer, "  Attempt %d: %s\n", attempt, eh.getShortErrorMessage(err))
			if delay > 0 {
				fmt.Fprintf(eh.writer, "  Waiting %v before retry...\n", delay.Round(time.Millisecond))
			}
		} else if attempt > 1 {
			fmt.Fprintf(eh.writer, "  Success on attempt %d\n", attempt)
		}
	}
}

// FormatErrorForUser formats an error message for end-user display
func (eh *ErrorHandler) FormatErrorForUser(err error) string {
	if err == nil {
		return ""
	}

	if probeErr, ok := err.(*ProbeError); ok {
		if eh.verbose {
			return probeErr.String()
		}
		return probeErr.GetUserFriendlyMessage()
	}

	return err.Error()
}

// IsRecoverableError determines if an error is recoverable
func (eh *ErrorHandler) IsRecoverableError(err error) bool {
	if IsFatalError(err) {
		return false
	}

	if probeErr, ok := err.(*ProbeError); ok {
		switch probeErr.Code {
		case ErrInvalidArgs, ErrPermissionDenied, ErrContextCanceled:
			return false
		default:
			return true
		}
	}

	return true
}

// SuggestRecoveryActions suggests actions to recover from an error
func (eh *ErrorHandler) SuggestRecoveryActions(err error) []string {
	if probeErr, ok := err.(*ProbeError); ok {
		suggestions := eh.getErrorSuggestions(probeErr.Code)
		if len(suggestions) > 0 {
			return suggestions
		}
	}

	// Generic recovery suggestions
	return []string{
		"Check your network connectivity",
		"Verify the target address and port",
		"Try running the command with different parameters",
		"Check system logs for additional information",
	}
}

// DisplayRecoveryHelp displays help for recovering from an error
func (eh *ErrorHandler) DisplayRecoveryHelp(err error) {
	if !eh.IsRecoverableError(err) {
		return
	}

	suggestions := eh.SuggestRecoveryActions(err)
	if len(suggestions) > 0 {
		fmt.Fprintln(eh.writer)
		fmt.Fprintln(eh.writer, "Recovery suggestions:")
		for i, suggestion := range suggestions {
			fmt.Fprintf(eh.writer, "  %d. %s\n", i+1, suggestion)
		}
	}
}
