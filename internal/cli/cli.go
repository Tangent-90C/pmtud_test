package cli

import (
	"fmt"
	"time"

	"github.com/spf13/cobra"
)

// CLI handles command line interface
type CLI struct {
	rootCmd *cobra.Command
}

// NewCLI creates a new CLI instance
func NewCLI() *CLI {
	cli := &CLI{}
	cli.setupCommands()
	return cli
}

// ParseArguments parses command line arguments
func (c *CLI) ParseArguments(args []string) (*CLIArgs, error) {
	// Handle special help commands that don't need target validation
	if len(args) > 0 {
		switch args[0] {
		case "examples", "requirements", "version", "help", "-h", "--help":
			c.rootCmd.SetArgs(args)
			err := c.rootCmd.Execute()
			return nil, err // Return nil CLIArgs to indicate help command was executed
		}
	}

	// Check for version flag in arguments
	for _, arg := range args {
		if arg == "--version" {
			c.PrintVersion()
			return nil, nil
		}
	}

	c.rootCmd.SetArgs(args)

	if err := c.rootCmd.Execute(); err != nil {
		return nil, NewProbeError(ErrInvalidArgs, "failed to parse command line arguments", err)
	}

	// Check for version flag
	if version, _ := c.rootCmd.Flags().GetBool("version"); version {
		c.PrintVersion()
		return nil, nil // Return nil to indicate no further processing needed
	}

	// Extract parsed values from cobra command
	targetIPv6, _ := c.rootCmd.Flags().GetString("target")
	mode, _ := c.rootCmd.Flags().GetString("mode")
	port, _ := c.rootCmd.Flags().GetInt("port")
	controlPort, _ := c.rootCmd.Flags().GetInt("control-port")
	testMSS, _ := c.rootCmd.Flags().GetInt("test-mss")
	verbose, _ := c.rootCmd.Flags().GetBool("verbose")
	timeoutSec, _ := c.rootCmd.Flags().GetInt("timeout")
	maxRetries, _ := c.rootCmd.Flags().GetInt("max-retries")
	minMTU, _ := c.rootCmd.Flags().GetInt("min-mtu")
	maxMTU, _ := c.rootCmd.Flags().GetInt("max-mtu")
	logLevel, _ := c.rootCmd.Flags().GetString("log-level")
	logFile, _ := c.rootCmd.Flags().GetBool("log-file")
	logPath, _ := c.rootCmd.Flags().GetString("log-path")

	// Unreachability detection parameters
	disableUnreachabilityDetection, _ := c.rootCmd.Flags().GetBool("disable-unreachability-detection")
	preValidationTimeoutSec, _ := c.rootCmd.Flags().GetInt("pre-validation-timeout")
	preValidationRetries, _ := c.rootCmd.Flags().GetInt("pre-validation-retries")
	consecutiveFailureThreshold, _ := c.rootCmd.Flags().GetInt("consecutive-failure-threshold")
	totalFailureThreshold, _ := c.rootCmd.Flags().GetFloat64("total-failure-threshold")
	confidenceThreshold, _ := c.rootCmd.Flags().GetFloat64("confidence-threshold")

	// Convert mode string to ProbeMode
	var probeMode ProbeMode
	switch mode {
	case "mtu":
		probeMode = ModeMTUProbe
	case "tcp-client":
		probeMode = ModeTCPClientMSS
	case "tcp-server":
		probeMode = ModeTCPServerMSS
	case "mss-integrity":
		probeMode = ModeMSSIntegrityCheck
	default:
		return nil, NewProbeError(ErrInvalidArgs, fmt.Sprintf("invalid mode '%s': must be 'mtu', 'tcp-client', 'tcp-server', or 'mss-integrity'", mode), nil)
	}

	cliArgs := &CLIArgs{
		TargetIPv6:  targetIPv6,
		Mode:        probeMode,
		Port:        port,
		ControlPort: controlPort,
		TestMSS:     testMSS,
		Verbose:     verbose,
		Timeout:     time.Duration(timeoutSec) * time.Second,
		MaxRetries:  maxRetries,
		MinMTU:      minMTU,
		MaxMTU:      maxMTU,
		LogLevel:    logLevel,
		LogFile:     logFile,
		LogPath:     logPath,

		// Unreachability detection parameters
		DisableUnreachabilityDetection: disableUnreachabilityDetection,
		PreValidationTimeout:           time.Duration(preValidationTimeoutSec) * time.Second,
		PreValidationRetries:           preValidationRetries,
		ConsecutiveFailureThreshold:    consecutiveFailureThreshold,
		TotalFailureThreshold:          totalFailureThreshold,
		ConfidenceThreshold:            confidenceThreshold,
	}

	// Validate arguments
	if err := cliArgs.Validate(); err != nil {
		return nil, NewProbeError(ErrInvalidArgs, "invalid arguments", err)
	}

	return cliArgs, nil
}

func (c *CLI) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:   "ipv6-mtu-discovery [flags] <target-ipv6-address>",
		Short: "IPv6 MTU Discovery Tool",
		Long: `IPv6 MTU Discovery Tool

A command-line tool for discovering IPv6 path MTU and detecting TCP MSS clamping.
This tool uses ICMP6 packets to probe the network path and determine the maximum
transmission unit (MTU) size, and can also detect TCP Maximum Segment Size (MSS)
clamping by network devices.

The tool supports four operation modes:
  mtu          - Discover path MTU using ICMP6 probes (default)
  tcp-client   - Detect MSS clamping as TCP client
  tcp-server   - Detect MSS clamping as TCP server
  mss-integrity - Verify MSS integrity and detect tampering

For detailed examples, run: ipv6-mtu-discovery examples
For system requirements, run: ipv6-mtu-discovery requirements

Note: This tool requires root/administrator privileges to create raw sockets.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// If target is provided as positional argument, use it
			if len(args) == 1 {
				cmd.Flags().Set("target", args[0])
			}
			// Command execution is handled by the app package
			return nil
		},
	}

	// Add subcommands for help information
	c.setupHelpCommands()

	// Add flags with detailed descriptions
	c.rootCmd.Flags().StringP("target", "t", "",
		"Target IPv6 address for MTU discovery or MSS detection (required)")
	c.rootCmd.Flags().StringP("mode", "m", "mtu",
		"Operation mode: 'mtu' for MTU discovery, 'tcp-client' for MSS detection as client, 'tcp-server' for MSS detection as server, 'mss-integrity' for MSS integrity verification")
	c.rootCmd.Flags().IntP("port", "p", 80,
		"TCP port number for MSS detection (1-65535)")
	c.rootCmd.Flags().IntP("control-port", "c", 0,
		"Control port for MSS integrity verification (0 = disabled, 1-65535)")
	c.rootCmd.Flags().IntP("test-mss", "", 1460,
		"Test MSS value for integrity verification (1-65535)")
	c.rootCmd.Flags().BoolP("verbose", "v", false,
		"Enable verbose output showing detailed probe information")
	c.rootCmd.Flags().IntP("timeout", "T", 5,
		"Timeout in seconds for network operations (1-60)")
	c.rootCmd.Flags().IntP("max-retries", "r", 3,
		"Maximum number of retries for failed probes (1-10)")
	c.rootCmd.Flags().IntP("min-mtu", "", 68,
		"Minimum MTU size to test (68-1500)")
	c.rootCmd.Flags().IntP("max-mtu", "", 1500,
		"Maximum MTU size to test (68-9000)")
	c.rootCmd.Flags().BoolP("version", "", false,
		"Show version information")
	c.rootCmd.Flags().String("log-level", "info",
		"Set log level (debug, info, warn, error)")
	c.rootCmd.Flags().Bool("log-file", false,
		"Enable file logging")
	c.rootCmd.Flags().String("log-path", "logs/ipv6-mtu-discovery.log",
		"Path for log file when file logging is enabled")

	// Unreachability detection flags
	c.rootCmd.Flags().Bool("disable-unreachability-detection", false,
		"Disable target unreachability detection (may show false small MTU values)")
	c.rootCmd.Flags().Int("pre-validation-timeout", 5,
		"Timeout in seconds for pre-validation reachability checks (1-60)")
	c.rootCmd.Flags().Int("pre-validation-retries", 2,
		"Number of retries for pre-validation checks (0-10)")
	c.rootCmd.Flags().Int("consecutive-failure-threshold", 3,
		"Number of consecutive failures to trigger unreachability detection (1-20)")
	c.rootCmd.Flags().Float64("total-failure-threshold", 0.8,
		"Total failure rate threshold to trigger unreachability detection (0.0-1.0)")
	c.rootCmd.Flags().Float64("confidence-threshold", 0.7,
		"Confidence threshold for unreachability detection (0.0-1.0)")

	// Target flag will be validated in ParseArguments for main commands
	// Don't mark as required here to allow help subcommands to work
}

// setupHelpCommands adds subcommands for detailed help information
func (c *CLI) setupHelpCommands() {
	// Examples subcommand
	examplesCmd := &cobra.Command{
		Use:   "examples",
		Short: "Show detailed usage examples",
		Long:  "Display comprehensive examples of how to use the IPv6 MTU Discovery Tool",
		Run: func(cmd *cobra.Command, args []string) {
			c.PrintExamples()
		},
	}

	// Requirements subcommand
	requirementsCmd := &cobra.Command{
		Use:   "requirements",
		Short: "Show system requirements and setup information",
		Long:  "Display system requirements, setup instructions, and troubleshooting information",
		Run: func(cmd *cobra.Command, args []string) {
			c.PrintRequirements()
		},
	}

	// Version subcommand
	versionCmd := &cobra.Command{
		Use:   "version",
		Short: "Show version information",
		Long:  "Display version and build information",
		Run: func(cmd *cobra.Command, args []string) {
			c.PrintVersion()
		},
	}

	// Add subcommands to root
	c.rootCmd.AddCommand(examplesCmd)
	c.rootCmd.AddCommand(requirementsCmd)
	c.rootCmd.AddCommand(versionCmd)
}

// PrintUsage prints usage information
func (c *CLI) PrintUsage() {
	c.rootCmd.Help()
}

// PrintVersion prints version information
func (c *CLI) PrintVersion() {
	fmt.Println("IPv6 MTU Discovery Tool v1.0.0")
	fmt.Println("Built with Go", "1.19+")
	fmt.Println("Copyright (c) 2024")
}

// PrintExamples prints detailed usage examples
func (c *CLI) PrintExamples() {
	examples := `
EXAMPLES:

Basic MTU Discovery:
  ipv6-mtu-discovery -t 2400:3200::1
  ipv6-mtu-discovery --target 2400:3200::1

MTU Discovery with Custom Parameters:
  ipv6-mtu-discovery -t 2400:3200::1 -v --timeout 10
  ipv6-mtu-discovery -t 2400:3200::1 --min-mtu 1280 --max-mtu 1500

TCP MSS Detection (Client Mode):
  ipv6-mtu-discovery -t 2400:3200::1 -m tcp-client -p 80
  ipv6-mtu-discovery -t 2400:3200::1 -m tcp-client -p 443 -v

TCP MSS Detection (Server Mode):
  ipv6-mtu-discovery -m tcp-server -p 8080 -t ::1
  ipv6-mtu-discovery -m tcp-server -p 9000 -t 2400:3200::1 --timeout 30

MSS Integrity Verification:
  ipv6-mtu-discovery -t 2400:3200::1 -m mss-integrity -p 80 -c 8080
  ipv6-mtu-discovery -t 2400:3200::1 -m mss-integrity -p 443 -c 8443 --test-mss 1440 -v

Advanced Usage:
  ipv6-mtu-discovery -t 2400:3200::1 -v --max-retries 5 --timeout 15
  ipv6-mtu-discovery -t fe80::1%eth0 -m tcp-client -p 22

Unreachability Detection:
  ipv6-mtu-discovery -t 2400:3200::1 --disable-unreachability-detection
  ipv6-mtu-discovery -t 2400:3200::1 --pre-validation-timeout 10 --consecutive-failure-threshold 5
  ipv6-mtu-discovery -t 2400:3200::1 --total-failure-threshold 0.9 --confidence-threshold 0.8

NOTES:
  - Root/Administrator privileges are required for raw socket operations
  - IPv6 addresses can include zone identifiers (e.g., fe80::1%eth0)
  - TCP server mode will listen on the specified address and port
  - MSS integrity mode requires both main port (-p) and control port (-c)
  - Control port must be different from main port for MSS integrity verification
  - Use verbose mode (-v) to see detailed probe information
  - Timeout values are in seconds (1-60 range)
  - Port numbers must be in range 1-65535
  - MTU range must be between 68 and 9000 bytes
  - Test MSS values must be in range 1-65535
  - Unreachability detection can be disabled to show raw MTU results
  - Detection thresholds can be adjusted for different network conditions
  - Higher confidence thresholds reduce false positives but may miss some cases
`
	fmt.Print(examples)
}

// PrintRequirements prints system requirements and setup information
func (c *CLI) PrintRequirements() {
	requirements := `
SYSTEM REQUIREMENTS:

Privileges:
  - Linux/macOS: Root privileges (sudo) required for raw sockets
  - Windows: Administrator privileges required for raw sockets

Network:
  - IPv6 connectivity to target addresses
  - ICMP6 packets allowed through firewall (for MTU discovery)
  - TCP connectivity allowed (for MSS detection)

Supported Platforms:
  - Linux (kernel 2.6+)
  - macOS (10.10+)
  - Windows (Windows 7+)

Setup:
  1. Ensure IPv6 is enabled on your system
  2. Run with appropriate privileges:
     - Linux/macOS: sudo ./ipv6-mtu-discovery [options]
     - Windows: Run as Administrator
  3. Configure firewall to allow ICMP6 and TCP traffic

Troubleshooting:
  - Permission denied: Run with root/administrator privileges
  - Network unreachable: Check IPv6 connectivity and routing
  - Timeout errors: Increase timeout value or check network connectivity
  - Invalid address: Ensure IPv6 address format is correct
`
	fmt.Print(requirements)
}
