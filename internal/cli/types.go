package cli

import (
	"fmt"
	"time"
)

// ProbeMode represents the different operation modes
type ProbeMode int

const (
	ModeMTUProbe ProbeMode = iota
	ModeTCPClientMSS
	ModeTCPServerMSS
	ModeMSSIntegrityCheck
)

// String returns the string representation of the probe mode
func (p ProbeMode) String() string {
	switch p {
	case ModeMTUProbe:
		return "mtu"
	case ModeTCPClientMSS:
		return "tcp-client"
	case ModeTCPServerMSS:
		return "tcp-server"
	case ModeMSSIntegrityCheck:
		return "mss-integrity"
	default:
		return "unknown"
	}
}

// CLIArgs represents command line arguments
type CLIArgs struct {
	TargetIPv6  string        // Target IPv6 address for probing
	Mode        ProbeMode     // Operation mode (MTU probe, TCP client/server MSS, MSS integrity check)
	Port        int           // TCP port for MSS detection
	ControlPort int           // Control port for MSS verification
	TestMSS     int           // Test MSS value for integrity verification
	Verbose     bool          // Enable verbose output
	Timeout     time.Duration // Timeout for network operations
	MaxRetries  int           // Maximum number of retries for failed probes
	MinMTU      int           // Minimum MTU size to test
	MaxMTU      int           // Maximum MTU size to test
	LogLevel    string        // Log level (debug, info, warn, error)
	LogFile     bool          // Enable file logging
	LogPath     string        // Path for log file

	// Unreachability detection parameters
	DisableUnreachabilityDetection bool          // Disable unreachability detection
	PreValidationTimeout           time.Duration // Timeout for pre-validation checks
	PreValidationRetries           int           // Number of retries for pre-validation
	ConsecutiveFailureThreshold    int           // Threshold for consecutive failures
	TotalFailureThreshold          float64       // Threshold for total failure rate
	ConfidenceThreshold            float64       // Confidence threshold for detection
}

// Validate validates the CLI arguments
func (args *CLIArgs) Validate() error {
	// Validate target IPv6 address
	if args.TargetIPv6 == "" {
		return fmt.Errorf("target IPv6 address is required")
	}

	// Validate port range
	if args.Port <= 0 || args.Port > 65535 {
		return fmt.Errorf("port must be between 1 and 65535, got %d", args.Port)
	}

	// Validate control port range (0 means not used)
	if args.ControlPort != 0 && (args.ControlPort <= 0 || args.ControlPort > 65535) {
		return fmt.Errorf("control port must be between 1 and 65535, got %d", args.ControlPort)
	}

	// Ensure control port is different from main port
	if args.ControlPort != 0 && args.ControlPort == args.Port {
		return fmt.Errorf("control port (%d) must be different from main port (%d)", args.ControlPort, args.Port)
	}

	// Validate timeout
	if args.Timeout <= 0 {
		return fmt.Errorf("timeout must be positive, got %v", args.Timeout)
	}
	if args.Timeout > 60*time.Second {
		return fmt.Errorf("timeout must not exceed 60 seconds, got %v", args.Timeout)
	}

	// Validate max retries
	if args.MaxRetries < 1 || args.MaxRetries > 10 {
		return fmt.Errorf("max retries must be between 1 and 10, got %d", args.MaxRetries)
	}

	// Validate MTU range
	if args.MinMTU < 68 || args.MinMTU > 9000 {
		return fmt.Errorf("minimum MTU must be between 68 and 9000, got %d", args.MinMTU)
	}
	if args.MaxMTU < 68 || args.MaxMTU > 9000 {
		return fmt.Errorf("maximum MTU must be between 68 and 9000, got %d", args.MaxMTU)
	}
	if args.MinMTU >= args.MaxMTU {
		return fmt.Errorf("minimum MTU (%d) must be less than maximum MTU (%d)", args.MinMTU, args.MaxMTU)
	}

	// Validate logging configuration
	validLogLevels := map[string]bool{
		"debug": true,
		"info":  true,
		"warn":  true,
		"error": true,
	}
	if args.LogLevel != "" && !validLogLevels[args.LogLevel] {
		return fmt.Errorf("invalid log level '%s', must be one of: debug, info, warn, error", args.LogLevel)
	}
	if args.LogFile && args.LogPath == "" {
		return fmt.Errorf("log file path is required when file logging is enabled")
	}

	// Validate unreachability detection parameters
	if args.PreValidationTimeout > 0 {
		if args.PreValidationTimeout > 60*time.Second {
			return fmt.Errorf("pre-validation timeout must not exceed 60 seconds, got %v", args.PreValidationTimeout)
		}
	}
	if args.PreValidationRetries < 0 || args.PreValidationRetries > 10 {
		return fmt.Errorf("pre-validation retries must be between 0 and 10, got %d", args.PreValidationRetries)
	}
	if args.ConsecutiveFailureThreshold < 0 || args.ConsecutiveFailureThreshold > 20 {
		return fmt.Errorf("consecutive failure threshold must be between 0 and 20, got %d", args.ConsecutiveFailureThreshold)
	}
	if args.TotalFailureThreshold < 0.0 || args.TotalFailureThreshold > 1.0 {
		return fmt.Errorf("total failure threshold must be between 0.0 and 1.0, got %f", args.TotalFailureThreshold)
	}
	if args.ConfidenceThreshold < 0.0 || args.ConfidenceThreshold > 1.0 {
		return fmt.Errorf("confidence threshold must be between 0.0 and 1.0, got %f", args.ConfidenceThreshold)
	}

	// Mode-specific validation
	switch args.Mode {
	case ModeTCPClientMSS, ModeTCPServerMSS:
		// TCP modes require valid port
		if args.Port == 0 {
			return fmt.Errorf("TCP mode requires a valid port number")
		}
	case ModeMSSIntegrityCheck:
		// MSS integrity check requires both main port and control port
		if args.Port == 0 {
			return fmt.Errorf("MSS integrity check mode requires a valid port number")
		}
		if args.ControlPort == 0 {
			return fmt.Errorf("MSS integrity check mode requires a valid control port number")
		}
		if args.TestMSS <= 0 || args.TestMSS > 65535 {
			return fmt.Errorf("test MSS must be between 1 and 65535, got %d", args.TestMSS)
		}
	case ModeMTUProbe:
		// MTU probe mode is always valid
	default:
		return fmt.Errorf("invalid probe mode: %v", args.Mode)
	}

	return nil
}
