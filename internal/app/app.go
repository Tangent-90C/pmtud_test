package app

import (
	"context"
	"fmt"
	"time"

	"ipv6-mtu-discovery/internal/cli"
	"ipv6-mtu-discovery/internal/config"
	"ipv6-mtu-discovery/internal/display"
	"ipv6-mtu-discovery/internal/logging"
	"ipv6-mtu-discovery/internal/network"
	"ipv6-mtu-discovery/internal/platform"
	"ipv6-mtu-discovery/internal/probe"
	"ipv6-mtu-discovery/internal/stats"
	"ipv6-mtu-discovery/internal/validator"
)

// App represents the main application
type App struct {
	config           *config.Config
	cli              *cli.CLI
	platformDetector *platform.Detector
	socketManager    *network.SocketManager
}

// AppState represents the current state of the application
type AppState struct {
	Args        *cli.CLIArgs
	TargetAddr  *validator.IPv6Address
	ICMPProber  *probe.ICMP6Prober
	MSSDetector *network.MSSDetector
	Running     bool
	Context     context.Context
	CancelFunc  context.CancelFunc

	// Additional state management fields
	StartTime time.Time
	Display   *display.ResultDisplay
	Config    *config.Config

	// Statistics tracking
	ProbeSession *stats.ProbeSession
	NetworkStats *stats.NetworkStats

	// Resource cleanup tracking
	resources   []func() error
	cleanupDone bool
}

// NewApp creates a new application instance
func NewApp() *App {
	app := &App{
		config:           config.GetDefaultConfig(),
		cli:              cli.NewCLI(),
		platformDetector: platform.NewDetector(),
		socketManager:    network.NewSocketManager(),
	}

	// Initialize logging with default configuration
	app.initializeLogging()

	return app
}

// NewAppWithConfig creates a new application instance with custom configuration
func NewAppWithConfig(configPath string) (*App, error) {
	cfg, err := config.LoadConfig(configPath)
	if err != nil {
		return nil, fmt.Errorf("failed to load configuration: %w", err)
	}

	app := &App{
		config:           cfg,
		cli:              cli.NewCLI(),
		platformDetector: platform.NewDetector(),
		socketManager:    network.NewSocketManager(),
	}

	// Initialize logging with loaded configuration
	app.initializeLogging()

	return app, nil
}

// Run executes the application with the given arguments
func (a *App) Run(ctx context.Context, args []string) error {
	logger := logging.GetLogger("app")

	logger.WithField("args", args).Debug("Starting application")

	// Parse command line arguments first to handle help/version commands
	cliArgs, err := a.cli.ParseArguments(args)
	if err != nil {
		logger.WithError(err).Error("Failed to parse command line arguments")
		return err
	}

	// If cliArgs is nil, it means a help command was executed
	if cliArgs == nil {
		logger.Debug("Help command executed, exiting")
		return nil
	}

	// Reinitialize logging with CLI argument overrides
	a.initializeLoggingWithArgs(cliArgs)

	// Get updated logger after reinitialization
	logger = logging.GetLogger("app")

	logger.WithFields(map[string]interface{}{
		"target": cliArgs.TargetIPv6,
		"mode":   cliArgs.Mode.String(),
		"port":   cliArgs.Port,
	}).Info("Application started with arguments")

	// Check permissions first before testing platform capabilities
	// This provides better error messages for permission issues
	logger.Debug("Checking permissions")
	permChecker := validator.NewPermissionChecker()

	// First, try to create a raw socket to see if it's a permission issue
	if err := permChecker.CanCreateRawSocket(); err != nil {
		logger.WithError(err).Debug("Raw socket creation test failed")
		// If raw socket creation fails, check if it's due to insufficient privileges
		if permErr := permChecker.CheckRootPrivileges(); permErr != nil {
			logger.WithError(permErr).Error("Insufficient privileges")
			permChecker.PrintPermissionError(permErr)
			return permErr
		}
		// If privileges are OK but socket creation still fails, it might be a platform issue
		logger.WithError(err).Warn("Raw socket creation failed despite having privileges")
		fmt.Printf("Warning: Raw socket creation failed despite having privileges: %v\n", err)
	} else {
		logger.Debug("Permission check passed")
	}

	// Now detect platform capabilities for actual probe operations
	logger.Debug("Detecting platform capabilities")
	platformInfo, err := a.platformDetector.DetectPlatform()
	if err != nil {
		logger.WithError(err).Error("Failed to detect platform")
		return fmt.Errorf("failed to detect platform: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"os":           platformInfo.OS,
		"architecture": platformInfo.Architecture,
		"ipv6_support": platformInfo.Capabilities.SupportsIPv6,
		"raw_sockets":  platformInfo.Capabilities.SupportsRawSockets,
	}).Info("Platform detected")

	// Check if platform supports IPv6
	if !platformInfo.Capabilities.SupportsIPv6 {
		logger.Error("IPv6 is not supported on this platform")
		return fmt.Errorf("IPv6 is not supported on this platform")
	}

	// Check raw socket support with better error messaging
	if !platformInfo.Capabilities.SupportsRawSockets {
		// Provide more detailed error information
		fmt.Println("Error: Raw sockets are not available on this platform")
		fmt.Println()
		fmt.Printf("Platform: %s/%s\n", platformInfo.OS, platformInfo.Architecture)
		// Get platform info for better error messages
		detector := platform.NewDetector()
		platInfo := detector.GetPlatformInfo()
		fmt.Printf("Required privileges: %s\n", platInfo.GetRequiredPrivileges())
		fmt.Println()

		// Show platform-specific notes
		notes := platInfo.GetPlatformSpecificNotes()
		if len(notes) > 0 {
			fmt.Println("Platform-specific notes:")
			for _, note := range notes {
				fmt.Printf("  • %s\n", note)
			}
			fmt.Println()
		}

		return fmt.Errorf("raw socket support is required for IPv6 MTU discovery")
	}

	// Create application state
	state := NewAppState(cliArgs, a.config, ctx)
	defer state.Cleanup()

	// Initialize components
	if err := state.InitializeComponents(); err != nil {
		return fmt.Errorf("failed to initialize components: %w", err)
	}

	// Validate mode and components
	if err := state.ValidateMode(); err != nil {
		return fmt.Errorf("mode validation failed: %w", err)
	}

	// Display start message
	state.Display.DisplayStartMessage(cliArgs.TargetIPv6, state.GetModeDescription())

	// Execute based on mode
	switch cliArgs.Mode {
	case cli.ModeMTUProbe:
		return a.runMTUProbe(state)
	case cli.ModeTCPClientMSS:
		return a.runTCPClientMSS(state)
	case cli.ModeTCPServerMSS:
		return a.runTCPServerMSS(state)
	case cli.ModeMSSIntegrityCheck:
		return a.runMSSIntegrityCheck(state)
	default:
		return cli.ErrInvalidArgsInstance
	}
}

func (a *App) runMTUProbe(state *AppState) error {
	logger := logging.GetLogger("mtu")

	if state.ICMPProber == nil {
		logger.Error("ICMP6 prober not initialized")
		return fmt.Errorf("ICMP6 prober not initialized")
	}

	logger.WithFields(map[string]interface{}{
		"target":  state.Args.TargetIPv6,
		"min_mtu": state.Args.MinMTU,
		"max_mtu": state.Args.MaxMTU,
	}).Info("Starting MTU discovery")

	// Use the application context for MTU discovery (no additional timeout)
	// The ICMP6 prober has its own internal timeout management

	// Display progress callback - now shows progress in both verbose and non-verbose modes
	progressCallback := func(currentMTU, low, high, iteration int) {
		logging.LogMTUDiscovery(state.Args.TargetIPv6, currentMTU, low, high, iteration)
		state.Display.DisplayProgress(currentMTU, low, high, iteration)
	}

	// Display result callback - shows individual test results and collects statistics
	resultCallback := func(success bool, mtu int, response *probe.PMTUDResponse) {
		// Record probe statistics
		timeout := response == nil && !success
		state.ProbeSession.RecordProbe(success, timeout)

		// Record network statistics if we have response timing information
		if response != nil {
			// Use actual RTT from probe response
			if response.RTT > 0 && response.RTT < 10*time.Second { // Sanity check for reasonable RTT
				state.NetworkStats.RecordPacket(false, response.RTT) // false = received packet
			}

			// Record errors based on response type
			if response.IsDestinationUnreachable() || response.IsTimeExceeded() {
				state.NetworkStats.RecordError(false) // ICMP error
			}
		} else if !success {
			// Record timeout or other error
			state.NetworkStats.RecordError(timeout)
		}

		// Record sent packet
		state.NetworkStats.RecordPacket(true, 0) // true = sent packet

		state.Display.DisplayProgressResult(success, mtu, response)
	}

	// Perform MTU discovery with both callbacks
	result, err := state.ICMPProber.DiscoverMTUWithCallbacks(state.Context, progressCallback, resultCallback)
	if err != nil {
		logger.WithError(err).Error("MTU discovery failed")
		state.Display.DisplayError(fmt.Errorf("MTU discovery failed: %w", err))
		return err
	}

	logger.WithFields(map[string]interface{}{
		"mtu_found":      result.MTUFound,
		"final_mtu":      result.FinalMTU,
		"probe_count":    result.ProbeAttempts,
		"tcp_mss_tested": result.TCPMSSTested,
	}).Info("MTU discovery completed")

	// If MTU was discovered, perform actual TCP MSS test
	if result.MTUFound && result.FinalMTU > 0 {
		if state.Display.IsVerbose() {
			state.Display.DisplayInfo("Testing actual TCP MSS...")
		}

		// Initialize MSS detector if not already done
		if state.MSSDetector == nil {
			// Temporarily create MSS detector for TCP client mode
			detector, err := network.NewMSSDetector(state.TargetAddr, cli.ModeTCPClientMSS, state.Args.Port, state.Args.ControlPort)
			if err != nil {
				if state.Display.IsVerbose() {
					state.Display.DisplayWarning(fmt.Sprintf("Could not initialize MSS detector: %v", err))
				}
			} else {
				state.MSSDetector = detector
				// Register cleanup function
				state.AddCleanupFunc(func() error {
					return detector.Close()
				})
			}
		}

		// Perform TCP MSS test if detector is available
		if state.MSSDetector != nil {
			mssResult, err := state.MSSDetector.DetectMSSClamping(state.Context)
			if err == nil && mssResult != nil && mssResult.ConnectionSuccess {
				// Update the result with actual TCP MSS
				result.ActualTCPMSS = mssResult.ClampedMSS
				result.TCPMSSTested = true
			} else if state.Display.IsVerbose() {
				if err != nil {
					state.Display.DisplayWarning(fmt.Sprintf("TCP MSS test failed: %v", err))
				} else {
					state.Display.DisplayWarning("TCP connection failed, using calculated MSS")
				}
			}
		}
	}

	// Finalize statistics collection
	state.ProbeSession.Finish()

	// Display results with statistics
	state.Display.DisplayMTUResult(result)

	// Display detailed statistics
	state.Display.DisplayProbeStatistics(state.ProbeSession, state.NetworkStats)

	// Display session summary with enhanced statistics
	duration := state.GetDuration()
	successRate := float64(state.ProbeSession.SuccessfulProbes) / float64(state.ProbeSession.TotalProbes)
	if state.ProbeSession.TotalProbes == 0 {
		successRate = 0.0
	}
	state.Display.DisplaySummary(duration, state.ProbeSession.TotalProbes, successRate)

	return nil
}

func (a *App) runTCPClientMSS(state *AppState) error {
	if state.MSSDetector == nil {
		return fmt.Errorf("MSS detector not initialized")
	}

	// Set timeout from CLI args
	probeCtx, cancel := state.WithTimeout(state.Args.Timeout)
	defer cancel()

	// Record connection attempt
	state.ProbeSession.RecordProbe(false, false) // Will update with actual result

	// Perform MSS detection
	result, err := state.MSSDetector.DetectMSSClamping(probeCtx)
	if err != nil {
		// Record failed probe
		state.ProbeSession.RecordProbe(false, true) // failed with timeout/error
		state.NetworkStats.RecordError(true)        // timeout or connection error
		state.Display.DisplayError(fmt.Errorf("MSS detection failed: %w", err))
		return err
	}

	// Update probe statistics based on result
	if result.ConnectionSuccess {
		state.ProbeSession.RecordProbe(true, false) // successful
		// Record successful TCP connection (use a default RTT estimate)
		state.NetworkStats.RecordPacket(false, 50*time.Millisecond) // Approximate TCP connection RTT
	} else {
		state.ProbeSession.RecordProbe(false, false) // failed but not timeout
		state.NetworkStats.RecordError(false)        // connection error
	}

	// Finalize statistics
	state.ProbeSession.Finish()

	// Display results
	state.Display.DisplayMSSResult(result)

	// Display statistics for verbose mode
	if state.Args.Verbose {
		state.Display.DisplayProbeStatistics(state.ProbeSession, state.NetworkStats)
	}

	// Display session summary
	duration := state.GetDuration()
	successRate := 0.0
	if result.ConnectionSuccess {
		successRate = 1.0
	}
	state.Display.DisplaySummary(duration, 1, successRate)

	return nil
}

func (a *App) runTCPServerMSS(state *AppState) error {
	if state.MSSDetector == nil {
		return fmt.Errorf("MSS detector not initialized")
	}

	// Display server listening information
	if listenAddr := state.MSSDetector.GetListenAddress(); listenAddr != nil {
		state.Display.DisplayInfo(fmt.Sprintf("Listening on %s (waiting for connection...)", listenAddr.String()))
	} else {
		state.Display.DisplayInfo(fmt.Sprintf("Listening on port %d (waiting for connection...)", state.Args.Port))
	}

	// Set timeout from CLI args
	probeCtx, cancel := state.WithTimeout(state.Args.Timeout)
	defer cancel()

	// Record connection wait
	state.ProbeSession.RecordProbe(false, false) // Will update with actual result

	// Perform MSS detection in server mode
	result, err := state.MSSDetector.DetectMSSClamping(probeCtx)
	if err != nil {
		// Record failed connection
		state.ProbeSession.RecordProbe(false, true) // failed with timeout/error
		state.NetworkStats.RecordError(true)        // timeout or connection error
		state.Display.DisplayError(fmt.Errorf("MSS detection failed: %w", err))
		return err
	}

	// Update probe statistics based on result
	if result.ConnectionSuccess {
		state.ProbeSession.RecordProbe(true, false) // successful
		// Record successful TCP connection
		state.NetworkStats.RecordPacket(false, 50*time.Millisecond) // Approximate TCP connection RTT
	} else {
		state.ProbeSession.RecordProbe(false, false) // failed but not timeout
		state.NetworkStats.RecordError(false)        // connection error
	}

	// Finalize statistics
	state.ProbeSession.Finish()

	// Display results
	state.Display.DisplayMSSResult(result)

	// Display statistics for verbose mode
	if state.Args.Verbose {
		state.Display.DisplayProbeStatistics(state.ProbeSession, state.NetworkStats)
	}

	// Display session summary
	duration := state.GetDuration()
	successRate := 0.0
	if result.ConnectionSuccess {
		successRate = 1.0
	}
	state.Display.DisplaySummary(duration, 1, successRate)

	return nil
}

func (a *App) runMSSIntegrityCheck(state *AppState) error {
	if state.MSSDetector == nil {
		return fmt.Errorf("MSS detector not initialized")
	}

	// Display start message for MSS integrity check
	state.Display.DisplayInfo(fmt.Sprintf("Starting MSS integrity verification with test MSS: %d", state.Args.TestMSS))
	state.Display.DisplayInfo(fmt.Sprintf("Control port: %d, Main port: %d", state.Args.ControlPort, state.Args.Port))

	// Set timeout from CLI args
	probeCtx, cancel := state.WithTimeout(state.Args.Timeout)
	defer cancel()

	// Create MSS integrity verifier
	verifier := network.NewMSSIntegrityVerifier(state.MSSDetector, state.Args.TestMSS, state.Args.ControlPort)
	defer verifier.Close()

	// Record integrity check attempt
	state.ProbeSession.RecordProbe(false, false) // Will update with actual result

	// Display verification progress
	state.Display.DisplayMSSVerificationProgress("Establishing control connection")

	// Start verification session
	session, err := verifier.StartVerificationSession(probeCtx)
	if err != nil {
		state.ProbeSession.RecordProbe(false, true) // failed with timeout/error
		state.NetworkStats.RecordError(true)        // timeout or connection error
		state.Display.DisplayError(fmt.Errorf("Failed to start verification session: %w", err))
		return err
	}

	state.Display.DisplayMSSVerificationProgress("Performing MSS integrity verification")

	// Perform bidirectional verification (client-side test)
	result, err := verifier.PerformBidirectionalVerification(probeCtx)
	if err != nil {
		// Record failed integrity check
		state.ProbeSession.RecordProbe(false, true) // failed with timeout/error
		state.NetworkStats.RecordError(true)        // timeout or connection error
		state.Display.DisplayError(fmt.Errorf("MSS integrity verification failed: %w", err))
		return err
	}

	// Update probe statistics based on result
	if result.ConnectionSuccess {
		state.ProbeSession.RecordProbe(true, false) // successful
		// Record successful connection
		state.NetworkStats.RecordPacket(false, 50*time.Millisecond) // Approximate TCP connection RTT
	} else {
		state.ProbeSession.RecordProbe(false, false) // failed but not timeout
		state.NetworkStats.RecordError(false)        // connection error
	}

	// Validate the result
	if err := state.MSSDetector.ValidateMSSIntegrityResult(result); err != nil {
		state.Display.DisplayWarning(fmt.Sprintf("Result validation warning: %v", err))
	}

	// Display detailed results using the dedicated MSS integrity display method
	state.Display.DisplayMSSIntegrityResult(result)

	// Display integrity summary
	summary := state.MSSDetector.GetMSSIntegrityVerificationSummary(result)
	if summary.Valid {
		state.Display.DisplayInfo("=== MSS Integrity Verification Summary ===")
		state.Display.DisplayInfo(summary.Description)

		if summary.TamperingDetected {
			state.Display.DisplayWarning(fmt.Sprintf("⚠️  MSS TAMPERING DETECTED (Severity: %s)", summary.TamperingSeverity))
			state.Display.DisplayInfo(fmt.Sprintf("   Client sent MSS: %d", summary.ClientSentMSS))
			state.Display.DisplayInfo(fmt.Sprintf("   Server received MSS: %d", summary.ServerReceivedMSS))
			state.Display.DisplayInfo(fmt.Sprintf("   Modification delta: %d", summary.ModificationDelta))
		} else {
			state.Display.DisplayInfo("✅ No MSS tampering detected - MSS values preserved")
		}

		if summary.ClampingDetected {
			state.Display.DisplayInfo(fmt.Sprintf("📉 MSS clamping detected: %d", summary.ClampedMSS))
		}
	}

	// Perform additional tampering detection with multiple MSS values if verbose
	if state.Args.Verbose {
		state.Display.DisplayInfo("\n=== Extended MSS Tampering Analysis ===")

		// Test with multiple MSS values using the detector's tampering detection
		testMSSValues := []int{1460, 1440, 1420, 1400, 1360, 1280, 536}
		tamperingResults, err := state.MSSDetector.DetectMSSTampering(probeCtx, testMSSValues)
		if err != nil {
			state.Display.DisplayWarning(fmt.Sprintf("Extended tampering analysis failed: %v", err))
		} else {
			// Record additional test statistics
			for _, testResult := range tamperingResults {
				if testResult.ConnectionSuccess {
					state.ProbeSession.RecordProbe(true, false)
					state.NetworkStats.RecordPacket(false, 50*time.Millisecond) // Approximate TCP connection RTT
				} else {
					state.ProbeSession.RecordProbe(false, false)
					state.NetworkStats.RecordError(false)
				}
			}

			// Analyze tampering patterns
			analysis := state.MSSDetector.AnalyzeMSSTamperingPattern(tamperingResults)

			// Display tampering analysis using the dedicated display method
			state.Display.DisplayMSSTamperingAnalysis(analysis)
		}
	}

	// Display MSS comparison report
	if result.ConnectionSuccess && result.MSSIntegrityCheck {
		state.Display.DisplayMSSComparisonReport(result.ClientSentMSS, result.ServerReceivedMSS, session.SessionID)
	}

	// Finalize statistics
	state.ProbeSession.Finish()

	// Display statistics for verbose mode
	if state.Args.Verbose {
		state.Display.DisplayProbeStatistics(state.ProbeSession, state.NetworkStats)
	}

	// Display session summary with enhanced statistics
	duration := state.GetDuration()
	successRate := float64(state.ProbeSession.SuccessfulProbes) / float64(state.ProbeSession.TotalProbes)
	if state.ProbeSession.TotalProbes == 0 {
		successRate = 0.0
	}
	state.Display.DisplaySummary(duration, state.ProbeSession.TotalProbes, successRate)

	return nil
}

// GetConfig returns the application configuration
func (a *App) GetConfig() *config.Config {
	return a.config
}

// GetPlatformInfo returns platform information
func (a *App) GetPlatformInfo() (*platform.Platform, error) {
	return a.platformDetector.DetectPlatform()
}

// GetSocketManager returns the socket manager
func (a *App) GetSocketManager() *network.SocketManager {
	return a.socketManager
}

// initializeLogging initializes the logging system based on configuration
func (a *App) initializeLogging() {
	a.initializeLoggingWithArgs(nil)
}

// initializeLoggingWithArgs initializes logging with CLI argument overrides
func (a *App) initializeLoggingWithArgs(cliArgs *cli.CLIArgs) {
	// Get logging configuration from config file
	logConfigMap, err := a.config.GetLoggingManagerConfig()
	if err != nil {
		// Fall back to default logging
		_ = logging.InitializeGlobalLogger(logging.DefaultConfig())
		return
	}

	// Convert to logging manager config
	logConfig, err := logging.ConfigFromMap(logConfigMap.(map[string]interface{}))
	if err != nil {
		// Fall back to default logging
		_ = logging.InitializeGlobalLogger(logging.DefaultConfig())
		return
	}

	// Override with CLI arguments if provided
	if cliArgs != nil {
		if cliArgs.LogLevel != "" {
			if level, err := logging.ParseLogLevel(cliArgs.LogLevel); err == nil {
				logConfig.Level = level
			}
		}
		if cliArgs.Verbose {
			logConfig.Verbose = true
		}
		if cliArgs.LogFile {
			logConfig.FileEnabled = true
			if cliArgs.LogPath != "" {
				logConfig.FilePath = cliArgs.LogPath
			}
		}
	}

	// Initialize global logger
	if err := logging.InitializeGlobalLogger(logConfig); err != nil {
		// Fall back to default logging if initialization fails
		_ = logging.InitializeGlobalLogger(logging.DefaultConfig())
	}

	// Log initialization
	logging.Info("Logging system initialized")
	logging.WithFields(map[string]interface{}{
		"level":        logConfig.Level.String(),
		"verbose":      logConfig.Verbose,
		"file_enabled": logConfig.FileEnabled,
		"file_path":    logConfig.FilePath,
	}).Debug("Logging configuration")
}

// NewAppState creates a new application state with proper initialization
func NewAppState(args *cli.CLIArgs, config *config.Config, ctx context.Context) *AppState {
	appCtx, cancel := context.WithCancel(ctx)

	return &AppState{
		Args:         args,
		Running:      true,
		Context:      appCtx,
		CancelFunc:   cancel,
		StartTime:    time.Now(),
		Display:      display.NewResultDisplay(args.Verbose, nil),
		Config:       config,
		ProbeSession: stats.NewProbeSession(),
		NetworkStats: stats.NewNetworkStats(),
		resources:    make([]func() error, 0),
	}
}

// InitializeComponents initializes all required components for the application state
func (s *AppState) InitializeComponents() error {
	// Validate and set target address
	if s.Args.TargetIPv6 != "" {
		targetAddr, err := validator.ValidateIPv6Address(s.Args.TargetIPv6)
		if err != nil {
			return fmt.Errorf("invalid target IPv6 address: %w", err)
		}
		s.TargetAddr = targetAddr
	}

	// Initialize components based on mode
	switch s.Args.Mode {
	case cli.ModeMTUProbe:
		return s.initializeMTUProbe()
	case cli.ModeTCPClientMSS, cli.ModeTCPServerMSS, cli.ModeMSSIntegrityCheck:
		return s.initializeMSSDetection()
	default:
		return fmt.Errorf("unsupported mode: %v", s.Args.Mode)
	}
}

// initializeMTUProbe initializes components for MTU probing
func (s *AppState) initializeMTUProbe() error {
	logger := logging.GetLogger("mtu")

	if s.TargetAddr == nil {
		logger.Error("Target address is required for MTU probing")
		return fmt.Errorf("target address is required for MTU probing")
	}

	logger.WithFields(map[string]interface{}{
		"target":  s.TargetAddr.String(),
		"min_mtu": s.Args.MinMTU,
		"max_mtu": s.Args.MaxMTU,
		"verbose": s.Args.Verbose,
	}).Debug("Initializing MTU probe components")

	// Set debug mode based on verbose flag
	probe.SetDebugMode(s.Args.Verbose)

	// Create ICMP6 prober
	prober, err := probe.NewICMP6Prober(s.TargetAddr)
	if err != nil {
		logger.WithError(err).Error("Failed to create ICMP6 prober")
		return fmt.Errorf("failed to create ICMP6 prober: %w", err)
	}

	logger.Debug("ICMP6 prober created successfully")
	s.ICMPProber = prober

	// Set MTU range from CLI args
	if err := prober.SetMTURange(s.Args.MinMTU, s.Args.MaxMTU); err != nil {
		logger.WithError(err).WithFields(map[string]interface{}{
			"min_mtu": s.Args.MinMTU,
			"max_mtu": s.Args.MaxMTU,
		}).Error("Failed to set MTU range")
		return fmt.Errorf("failed to set MTU range: %w", err)
	}

	logger.WithFields(map[string]interface{}{
		"min_mtu": s.Args.MinMTU,
		"max_mtu": s.Args.MaxMTU,
	}).Debug("MTU range configured")

	// Register cleanup function
	s.AddCleanupFunc(func() error {
		return prober.Close()
	})

	return nil
}

// initializeMSSDetection initializes components for MSS detection
func (s *AppState) initializeMSSDetection() error {
	logger := logging.GetLogger("mss")

	if s.TargetAddr == nil {
		logger.Error("Target address is required for MSS detection")
		return fmt.Errorf("target address is required for MSS detection")
	}

	logger.WithFields(map[string]interface{}{
		"target":       s.TargetAddr.String(),
		"mode":         s.Args.Mode.String(),
		"port":         s.Args.Port,
		"control_port": s.Args.ControlPort,
	}).Debug("Initializing MSS detection components")

	// Create MSS detector
	detector, err := network.NewMSSDetector(s.TargetAddr, s.Args.Mode, s.Args.Port, s.Args.ControlPort)
	if err != nil {
		logger.WithError(err).Error("Failed to create MSS detector")
		return fmt.Errorf("failed to create MSS detector: %w", err)
	}

	logger.Debug("MSS detector created successfully")
	s.MSSDetector = detector

	// Register cleanup function
	s.AddCleanupFunc(func() error {
		return detector.Close()
	})

	return nil
}

// AddCleanupFunc adds a cleanup function to be called when the state is cleaned up
func (s *AppState) AddCleanupFunc(cleanup func() error) {
	if cleanup != nil {
		s.resources = append(s.resources, cleanup)
	}
}

// Cleanup performs cleanup of all resources
func (s *AppState) Cleanup() error {
	if s.cleanupDone {
		return nil
	}

	s.cleanupDone = true
	s.Running = false

	var lastErr error

	// Call cancel function to stop any ongoing operations
	if s.CancelFunc != nil {
		s.CancelFunc()
	}

	// Execute all cleanup functions in reverse order
	for i := len(s.resources) - 1; i >= 0; i-- {
		if err := s.resources[i](); err != nil {
			lastErr = err
		}
	}

	return lastErr
}

// IsRunning returns whether the application state is still running
func (s *AppState) IsRunning() bool {
	return s.Running && s.Context.Err() == nil
}

// Stop stops the application state and cancels the context
func (s *AppState) Stop() {
	s.Running = false
	if s.CancelFunc != nil {
		s.CancelFunc()
	}
}

// GetDuration returns the duration since the application state was created
func (s *AppState) GetDuration() time.Duration {
	return time.Since(s.StartTime)
}

// SetTimeout sets a timeout for the application context
func (s *AppState) SetTimeout(timeout time.Duration) {
	if s.CancelFunc != nil {
		s.CancelFunc()
	}

	s.Context, s.CancelFunc = context.WithTimeout(context.Background(), timeout)
}

// WithTimeout creates a new context with timeout from the current context
func (s *AppState) WithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(s.Context, timeout)
}

// ValidateMode validates that the current mode is supported and properly configured
func (s *AppState) ValidateMode() error {
	switch s.Args.Mode {
	case cli.ModeMTUProbe:
		if s.TargetAddr == nil {
			return fmt.Errorf("target IPv6 address is required for MTU probing")
		}
		if s.ICMPProber == nil {
			return fmt.Errorf("ICMP6 prober not initialized for MTU probing")
		}
	case cli.ModeTCPClientMSS:
		if s.TargetAddr == nil {
			return fmt.Errorf("target IPv6 address is required for TCP client MSS detection")
		}
		if s.MSSDetector == nil {
			return fmt.Errorf("MSS detector not initialized for TCP client mode")
		}
	case cli.ModeTCPServerMSS:
		if s.MSSDetector == nil {
			return fmt.Errorf("MSS detector not initialized for TCP server mode")
		}
	case cli.ModeMSSIntegrityCheck:
		if s.TargetAddr == nil {
			return fmt.Errorf("target IPv6 address is required for MSS integrity check")
		}
		if s.MSSDetector == nil {
			return fmt.Errorf("MSS detector not initialized for MSS integrity check mode")
		}
		if s.Args.ControlPort == 0 {
			return fmt.Errorf("control port is required for MSS integrity check")
		}
		if s.Args.TestMSS <= 0 {
			return fmt.Errorf("test MSS value is required for MSS integrity check")
		}
	default:
		return fmt.Errorf("unsupported mode: %v", s.Args.Mode)
	}
	return nil
}

// GetModeDescription returns a human-readable description of the current mode
func (s *AppState) GetModeDescription() string {
	switch s.Args.Mode {
	case cli.ModeMTUProbe:
		return "IPv6 Path MTU Discovery"
	case cli.ModeTCPClientMSS:
		return "TCP MSS Detection (Client Mode)"
	case cli.ModeTCPServerMSS:
		return "TCP MSS Detection (Server Mode)"
	case cli.ModeMSSIntegrityCheck:
		return "MSS Integrity Verification"
	default:
		return "Unknown Mode"
	}
}
