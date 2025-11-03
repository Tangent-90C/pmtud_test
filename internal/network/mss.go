package network

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"

	"ipv6-mtu-discovery/internal/cli"
	"ipv6-mtu-discovery/internal/validator"
)

// MSSDetector handles TCP MSS detection
type MSSDetector struct {
	target      *validator.IPv6Address
	mode        cli.ProbeMode
	port        int
	controlPort int // Control port for MSS verification
	originalMSS int
	listener    net.Listener
	tcpManager  *TCPManager
	controlConn net.Conn // Control connection for MSS verification
}

// MSSResult represents the result of MSS detection
type MSSResult struct {
	MSSClamped        bool
	OriginalMSS       int
	ClampedMSS        int
	ConnectionSuccess bool
	DetectedMTU       int
	ErrorMessage      string
	// MSS integrity verification results
	MSSIntegrityCheck bool
	ClientSentMSS     int
	ServerReceivedMSS int
	MSSModified       bool
	ModificationDelta int
}

// NewMSSDetector creates a new MSS detector
func NewMSSDetector(target *validator.IPv6Address, mode cli.ProbeMode, port, controlPort int) (*MSSDetector, error) {
	if target == nil {
		return nil, fmt.Errorf("target address cannot be nil")
	}

	if port <= 0 || port > 65535 {
		return nil, fmt.Errorf("invalid port: %d (must be between 1 and 65535)", port)
	}

	if controlPort != 0 && (controlPort <= 0 || controlPort > 65535) {
		return nil, fmt.Errorf("invalid control port: %d (must be between 1 and 65535)", controlPort)
	}

	// Validate mode
	switch mode {
	case cli.ModeTCPClientMSS, cli.ModeTCPServerMSS, cli.ModeMSSIntegrityCheck:
		// Valid modes
	default:
		return nil, fmt.Errorf("invalid mode for MSS detection: %v", mode)
	}

	return &MSSDetector{
		target:      target,
		mode:        mode,
		port:        port,
		controlPort: controlPort,
		originalMSS: 1460, // Default MSS for IPv6 (1500 - 40)
		tcpManager:  NewTCPManager(),
	}, nil
}

// DetectMSSClamping detects TCP MSS clamping
func (d *MSSDetector) DetectMSSClamping(ctx context.Context) (*MSSResult, error) {
	switch d.mode {
	case cli.ModeTCPClientMSS:
		return d.detectClientMSS(ctx)
	case cli.ModeTCPServerMSS:
		return d.detectServerMSS(ctx)
	case cli.ModeMSSIntegrityCheck:
		return nil, fmt.Errorf("use VerifyMSSIntegrity for MSS integrity check mode")
	default:
		return nil, fmt.Errorf("unsupported mode: %v", d.mode)
	}
}

// detectClientMSS performs MSS detection in client mode
func (d *MSSDetector) detectClientMSS(ctx context.Context) (*MSSResult, error) {
	result := &MSSResult{
		OriginalMSS: d.originalMSS,
	}

	// Create target TCP address
	targetAddr := &net.TCPAddr{
		IP:   d.target.IP,
		Port: d.port,
	}

	// Attempt connection with timeout from context
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	conn, err := d.tcpManager.ConnectTCPv6(targetAddr, timeout)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to connect: %v", err)
		return result, nil // Return result with error, not error itself
	}
	defer conn.Close()

	result.ConnectionSuccess = true

	// Get the negotiated MSS
	negotiatedMSS, err := d.tcpManager.GetMSSOption(conn)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to get MSS: %v", err)
		return result, nil
	}

	result.ClampedMSS = negotiatedMSS

	// Check if MSS was clamped (reduced from original)
	if negotiatedMSS < d.originalMSS {
		result.MSSClamped = true
		// Estimate MTU from clamped MSS (add IPv6 header size)
		result.DetectedMTU = negotiatedMSS + 40
	} else {
		result.MSSClamped = false
		result.DetectedMTU = d.originalMSS + 40
	}

	// Try to get additional TCP information
	if tcpInfo, err := d.tcpManager.GetTCPInfo(conn); err == nil {
		if tcpInfo.PMTU > 0 {
			result.DetectedMTU = tcpInfo.PMTU
		}
		if tcpInfo.AdvMSS > 0 && tcpInfo.AdvMSS != negotiatedMSS {
			// Advertised MSS differs from negotiated MSS
			result.MSSClamped = true
			result.OriginalMSS = tcpInfo.AdvMSS
		}
	}

	return result, nil
}

// detectServerMSS performs MSS detection in server mode
func (d *MSSDetector) detectServerMSS(ctx context.Context) (*MSSResult, error) {
	result := &MSSResult{
		OriginalMSS: d.originalMSS,
	}

	// Create listen address
	listenAddr := &net.TCPAddr{
		IP:   net.IPv6zero, // Listen on all IPv6 interfaces
		Port: d.port,
	}

	// Start listening
	listener, err := d.tcpManager.ListenTCPv6(listenAddr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to listen: %v", err)
		return result, nil
	}
	d.listener = listener
	defer listener.Close()

	// Create a channel to handle connection acceptance
	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	// Accept connections in a goroutine
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	// Wait for connection or context cancellation
	select {
	case <-ctx.Done():
		result.ErrorMessage = "Context cancelled while waiting for connection"
		return result, nil
	case err := <-errChan:
		result.ErrorMessage = fmt.Sprintf("Failed to accept connection: %v", err)
		return result, nil
	case conn := <-connChan:
		defer conn.Close()
		result.ConnectionSuccess = true

		// Get the negotiated MSS from the accepted connection
		negotiatedMSS, err := d.tcpManager.GetMSSOption(conn)
		if err != nil {
			result.ErrorMessage = fmt.Sprintf("Failed to get MSS: %v", err)
			return result, nil
		}

		result.ClampedMSS = negotiatedMSS

		// Check if MSS was clamped
		if negotiatedMSS < d.originalMSS {
			result.MSSClamped = true
			result.DetectedMTU = negotiatedMSS + 40
		} else {
			result.MSSClamped = false
			result.DetectedMTU = d.originalMSS + 40
		}

		// Try to get additional TCP information
		if tcpInfo, err := d.tcpManager.GetTCPInfo(conn); err == nil {
			if tcpInfo.PMTU > 0 {
				result.DetectedMTU = tcpInfo.PMTU
			}
			if tcpInfo.AdvMSS > 0 && tcpInfo.AdvMSS != negotiatedMSS {
				result.MSSClamped = true
				result.OriginalMSS = tcpInfo.AdvMSS
			}
		}

		return result, nil
	}
}

// SetOriginalMSS sets the original MSS value for comparison
func (d *MSSDetector) SetOriginalMSS(mss int) error {
	if mss <= 0 || mss > 65535 {
		return fmt.Errorf("invalid MSS value: %d", mss)
	}
	d.originalMSS = mss
	return nil
}

// GetListenAddress returns the address the server is listening on (server mode only)
func (d *MSSDetector) GetListenAddress() *net.TCPAddr {
	if d.listener == nil {
		return nil
	}

	addr, ok := d.listener.Addr().(*net.TCPAddr)
	if !ok {
		return nil
	}

	return addr
}

// TestMSSWithSize tests MSS clamping with a specific MSS size
func (d *MSSDetector) TestMSSWithSize(ctx context.Context, mss int) (*MSSResult, error) {
	if mss <= 0 || mss > 65535 {
		return nil, fmt.Errorf("invalid MSS size: %d", mss)
	}

	// Store original MSS and restore it later
	originalMSS := d.originalMSS
	d.originalMSS = mss
	defer func() {
		d.originalMSS = originalMSS
	}()

	return d.DetectMSSClamping(ctx)
}

// PerformMSSDiscovery performs MSS discovery by testing different MSS sizes
func (d *MSSDetector) PerformMSSDiscovery(ctx context.Context) ([]*MSSResult, error) {
	// Test common MSS sizes to detect clamping patterns
	testSizes := []int{
		1460, // Standard IPv6 MSS (1500 - 40)
		1440, // Common clamped size
		1420, // Another common clamped size
		1400, // Conservative size
		1360, // PPPoE adjusted
		1280, // IPv6 minimum MTU - 40
		536,  // Conservative fallback
	}

	results := make([]*MSSResult, 0, len(testSizes))

	for _, size := range testSizes {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result, err := d.TestMSSWithSize(ctx, size)
		if err != nil {
			return results, fmt.Errorf("failed to test MSS size %d: %w", size, err)
		}

		results = append(results, result)

		// If we found a working size and it's not clamped, we can stop
		if result.ConnectionSuccess && !result.MSSClamped {
			break
		}

		// Small delay between tests
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	return results, nil
}

// VerifyMSSIntegrity performs MSS integrity verification
func (d *MSSDetector) VerifyMSSIntegrity(ctx context.Context, testMSS int) (*MSSResult, error) {
	if testMSS <= 0 || testMSS > 65535 {
		return nil, fmt.Errorf("invalid test MSS: %d", testMSS)
	}

	if d.controlPort == 0 {
		return nil, fmt.Errorf("control port not configured for MSS integrity verification")
	}

	result := &MSSResult{
		OriginalMSS:       testMSS,
		MSSIntegrityCheck: true,
		ClientSentMSS:     testMSS,
	}

	switch d.mode {
	case cli.ModeTCPClientMSS, cli.ModeMSSIntegrityCheck:
		return d.verifyMSSIntegrityClient(ctx, testMSS, result)
	case cli.ModeTCPServerMSS:
		return d.verifyMSSIntegrityServer(ctx, testMSS, result)
	default:
		return nil, fmt.Errorf("unsupported mode for MSS integrity verification: %v", d.mode)
	}
}

// PerformComprehensiveMSSIntegrityCheck performs a comprehensive MSS integrity check
// This method is specifically for ModeMSSIntegrityCheck mode and performs both client and server tests
func (d *MSSDetector) PerformComprehensiveMSSIntegrityCheck(ctx context.Context, testMSS int) (*MSSResult, error) {
	if d.mode != cli.ModeMSSIntegrityCheck {
		return nil, fmt.Errorf("comprehensive MSS integrity check only available in MSS integrity check mode")
	}

	if testMSS <= 0 || testMSS > 65535 {
		return nil, fmt.Errorf("invalid test MSS: %d", testMSS)
	}

	if d.controlPort == 0 {
		return nil, fmt.Errorf("control port not configured for MSS integrity verification")
	}

	// Create a comprehensive result
	result := &MSSResult{
		OriginalMSS:       testMSS,
		MSSIntegrityCheck: true,
		ClientSentMSS:     testMSS,
	}

	// Perform client-side verification
	clientResult, err := d.verifyMSSIntegrityClient(ctx, testMSS, result)
	if err != nil {
		return nil, fmt.Errorf("client-side verification failed: %w", err)
	}

	// Copy client results
	result.ConnectionSuccess = clientResult.ConnectionSuccess
	result.ServerReceivedMSS = clientResult.ServerReceivedMSS
	result.MSSModified = clientResult.MSSModified
	result.ModificationDelta = clientResult.ModificationDelta
	result.ClampedMSS = clientResult.ClampedMSS
	result.MSSClamped = clientResult.MSSClamped
	result.DetectedMTU = clientResult.DetectedMTU

	if clientResult.ErrorMessage != "" {
		result.ErrorMessage = clientResult.ErrorMessage
	}

	return result, nil
}

// CompareMSSValues compares client-sent and server-received MSS values
func (d *MSSDetector) CompareMSSValues(clientMSS, serverMSS int) *MSSComparisonResult {
	return &MSSComparisonResult{
		ClientMSS:         clientMSS,
		ServerMSS:         serverMSS,
		ValuesMatch:       clientMSS == serverMSS,
		ModificationDelta: clientMSS - serverMSS,
		MSSModified:       clientMSS != serverMSS,
		TamperingDetected: clientMSS != serverMSS,
	}
}

// MSSComparisonResult represents the result of MSS value comparison
type MSSComparisonResult struct {
	ClientMSS         int
	ServerMSS         int
	ValuesMatch       bool
	ModificationDelta int
	MSSModified       bool
	TamperingDetected bool
}

// verifyMSSIntegrityClient performs MSS integrity verification in client mode
func (d *MSSDetector) verifyMSSIntegrityClient(ctx context.Context, testMSS int, result *MSSResult) (*MSSResult, error) {
	// Establish control connection first
	controlAddr := &net.TCPAddr{
		IP:   d.target.IP,
		Port: d.controlPort,
	}

	controlConn, err := d.tcpManager.EstablishControlChannel(controlAddr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to establish control connection: %v", err)
		return result, nil
	}
	defer controlConn.Close()
	d.controlConn = controlConn

	// Send verification info to server
	verificationInfo := &MSSVerificationInfo{
		ClientMSS: testMSS,
		Timestamp: time.Now(),
		SessionID: fmt.Sprintf("client-%d", time.Now().UnixNano()),
	}

	if err := d.sendVerificationInfo(controlConn, verificationInfo); err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to send verification info: %v", err)
		return result, nil
	}

	// Create target TCP address for main connection
	targetAddr := &net.TCPAddr{
		IP:   d.target.IP,
		Port: d.port,
	}

	// Establish main connection with specific MSS
	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	conn, err := d.tcpManager.ConnectWithMSS(targetAddr, testMSS, timeout)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to connect with MSS %d: %v", testMSS, err)
		return result, nil
	}
	defer conn.Close()

	result.ConnectionSuccess = true

	// Get connection info
	connInfo, err := d.tcpManager.GetConnectionInfo(conn)
	if err == nil {
		result.ClampedMSS = connInfo.EffectiveMSS
	}

	// Receive server's verification result
	serverInfo, err := d.receiveVerificationInfo(controlConn)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to receive server verification: %v", err)
		return result, nil
	}

	// Compare MSS values
	result.ServerReceivedMSS = serverInfo.ServerMSS
	result.MSSModified = (result.ClientSentMSS != result.ServerReceivedMSS)
	result.ModificationDelta = result.ClientSentMSS - result.ServerReceivedMSS

	// Check for clamping
	if result.ClampedMSS > 0 && result.ClampedMSS < testMSS {
		result.MSSClamped = true
		result.DetectedMTU = result.ClampedMSS + 40
	}

	return result, nil
}

// verifyMSSIntegrityServer performs MSS integrity verification in server mode
func (d *MSSDetector) verifyMSSIntegrityServer(ctx context.Context, testMSS int, result *MSSResult) (*MSSResult, error) {
	// Start control listener
	controlAddr := &net.TCPAddr{
		IP:   net.IPv6zero,
		Port: d.controlPort,
	}

	controlListener, err := d.tcpManager.ListenTCPv6(controlAddr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to start control listener: %v", err)
		return result, nil
	}
	defer controlListener.Close()

	// Start main listener
	listenAddr := &net.TCPAddr{
		IP:   net.IPv6zero,
		Port: d.port,
	}

	listener, err := d.tcpManager.ListenTCPv6(listenAddr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to start main listener: %v", err)
		return result, nil
	}
	d.listener = listener
	defer listener.Close()

	// Accept control connection
	controlConnChan := make(chan net.Conn, 1)
	controlErrChan := make(chan error, 1)

	go func() {
		conn, err := controlListener.Accept()
		if err != nil {
			controlErrChan <- err
			return
		}
		controlConnChan <- conn
	}()

	var controlConn net.Conn
	select {
	case <-ctx.Done():
		result.ErrorMessage = "Context cancelled while waiting for control connection"
		return result, nil
	case err := <-controlErrChan:
		result.ErrorMessage = fmt.Sprintf("Failed to accept control connection: %v", err)
		return result, nil
	case controlConn = <-controlConnChan:
		defer controlConn.Close()
		d.controlConn = controlConn
	}

	// Receive client verification info
	clientInfo, err := d.receiveVerificationInfo(controlConn)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to receive client verification: %v", err)
		return result, nil
	}

	result.ClientSentMSS = clientInfo.ClientMSS

	// Accept main connection and capture MSS
	mainConnChan := make(chan net.Conn, 1)
	mainMSSChan := make(chan int, 1)
	mainErrChan := make(chan error, 1)

	go func() {
		conn, mss, err := d.tcpManager.AcceptWithMSSCapture(listener)
		if err != nil {
			mainErrChan <- err
			return
		}
		mainConnChan <- conn
		mainMSSChan <- mss
	}()

	select {
	case <-ctx.Done():
		result.ErrorMessage = "Context cancelled while waiting for main connection"
		return result, nil
	case err := <-mainErrChan:
		result.ErrorMessage = fmt.Sprintf("Failed to accept main connection: %v", err)
		return result, nil
	case conn := <-mainConnChan:
		defer conn.Close()
		result.ConnectionSuccess = true

		// Get captured MSS
		capturedMSS := <-mainMSSChan
		result.ServerReceivedMSS = capturedMSS

		// Get connection info
		if connInfo, err := d.tcpManager.GetConnectionInfo(conn); err == nil {
			if connInfo.EffectiveMSS > 0 {
				result.ServerReceivedMSS = connInfo.EffectiveMSS
			}
		}

		// Compare MSS values
		result.MSSModified = (result.ClientSentMSS != result.ServerReceivedMSS)
		result.ModificationDelta = result.ClientSentMSS - result.ServerReceivedMSS

		// Send verification result back to client
		serverInfo := &MSSVerificationInfo{
			ServerMSS: result.ServerReceivedMSS,
			Timestamp: time.Now(),
			SessionID: clientInfo.SessionID,
		}

		if err := d.sendVerificationInfo(controlConn, serverInfo); err != nil {
			result.ErrorMessage = fmt.Sprintf("Failed to send verification result: %v", err)
			return result, nil
		}

		return result, nil
	}
}

// DetectMSSTampering performs advanced MSS tampering detection
func (d *MSSDetector) DetectMSSTampering(ctx context.Context, testMSSValues []int) ([]*MSSResult, error) {
	if d.controlPort == 0 {
		return nil, fmt.Errorf("control port not configured for MSS tampering detection")
	}

	if len(testMSSValues) == 0 {
		// Use default test values if none provided
		testMSSValues = []int{1460, 1440, 1420, 1400, 1360, 1280, 536}
	}

	results := make([]*MSSResult, 0, len(testMSSValues))

	for _, testMSS := range testMSSValues {
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		default:
		}

		result, err := d.VerifyMSSIntegrity(ctx, testMSS)
		if err != nil {
			return results, fmt.Errorf("failed to verify MSS %d: %w", testMSS, err)
		}

		results = append(results, result)

		// Add small delay between tests to avoid overwhelming the network
		select {
		case <-ctx.Done():
			return results, ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}

	return results, nil
}

// AnalyzeMSSTamperingPattern analyzes MSS tampering patterns from multiple test results
func (d *MSSDetector) AnalyzeMSSTamperingPattern(results []*MSSResult) *MSSTamperingAnalysis {
	if len(results) == 0 {
		return &MSSTamperingAnalysis{
			TotalTests:        0,
			TamperingDetected: false,
		}
	}

	analysis := &MSSTamperingAnalysis{
		TotalTests:     len(results),
		TestResults:    results,
		TamperingCases: make([]*MSSResult, 0),
		ClampingCases:  make([]*MSSResult, 0),
	}

	for _, result := range results {
		if result.MSSModified {
			analysis.TamperingDetected = true
			analysis.TamperingCount++
			analysis.TamperingCases = append(analysis.TamperingCases, result)
		}

		if result.MSSClamped {
			analysis.ClampingDetected = true
			analysis.ClampingCount++
			analysis.ClampingCases = append(analysis.ClampingCases, result)
		}

		if result.ConnectionSuccess {
			analysis.SuccessfulConnections++
		}
	}

	// Calculate tampering percentage
	if analysis.TotalTests > 0 {
		analysis.TamperingPercentage = float64(analysis.TamperingCount) / float64(analysis.TotalTests) * 100
		analysis.ClampingPercentage = float64(analysis.ClampingCount) / float64(analysis.TotalTests) * 100
	}

	return analysis
}

// MSSTamperingAnalysis represents the analysis of MSS tampering patterns
type MSSTamperingAnalysis struct {
	TotalTests            int
	SuccessfulConnections int
	TamperingDetected     bool
	TamperingCount        int
	TamperingPercentage   float64
	ClampingDetected      bool
	ClampingCount         int
	ClampingPercentage    float64
	TestResults           []*MSSResult
	TamperingCases        []*MSSResult
	ClampingCases         []*MSSResult
}

// EstablishControlConnection establishes a control connection for MSS verification
func (d *MSSDetector) EstablishControlConnection(ctx context.Context) error {
	if d.controlPort == 0 {
		return fmt.Errorf("control port not configured")
	}

	controlAddr := &net.TCPAddr{
		IP:   d.target.IP,
		Port: d.controlPort,
	}

	conn, err := d.tcpManager.EstablishControlChannel(controlAddr)
	if err != nil {
		return fmt.Errorf("failed to establish control connection: %w", err)
	}

	d.controlConn = conn
	return nil
}

// ExchangeVerificationInfo exchanges MSS verification information
func (d *MSSDetector) ExchangeVerificationInfo(info *MSSVerificationInfo) (*MSSVerificationInfo, error) {
	if d.controlConn == nil {
		return nil, fmt.Errorf("control connection not established")
	}

	// Send our info
	if err := d.sendVerificationInfo(d.controlConn, info); err != nil {
		return nil, fmt.Errorf("failed to send verification info: %w", err)
	}

	// Receive peer info
	peerInfo, err := d.receiveVerificationInfo(d.controlConn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive verification info: %w", err)
	}

	return peerInfo, nil
}

// ValidateMSSIntegrityResult validates the integrity of MSS verification results
func (d *MSSDetector) ValidateMSSIntegrityResult(result *MSSResult) error {
	if result == nil {
		return fmt.Errorf("result cannot be nil")
	}

	if !result.MSSIntegrityCheck {
		return fmt.Errorf("result is not from MSS integrity verification")
	}

	if result.ClientSentMSS <= 0 || result.ClientSentMSS > 65535 {
		return fmt.Errorf("invalid client sent MSS: %d", result.ClientSentMSS)
	}

	if result.ServerReceivedMSS < 0 || result.ServerReceivedMSS > 65535 {
		return fmt.Errorf("invalid server received MSS: %d", result.ServerReceivedMSS)
	}

	// Validate modification delta calculation
	expectedDelta := result.ClientSentMSS - result.ServerReceivedMSS
	if result.ModificationDelta != expectedDelta {
		return fmt.Errorf("modification delta mismatch: expected %d, got %d", expectedDelta, result.ModificationDelta)
	}

	// Validate MSS modified flag
	expectedModified := result.ClientSentMSS != result.ServerReceivedMSS
	if result.MSSModified != expectedModified {
		return fmt.Errorf("MSS modified flag mismatch: expected %t, got %t", expectedModified, result.MSSModified)
	}

	return nil
}

// GetMSSIntegrityVerificationSummary provides a summary of MSS integrity verification
func (d *MSSDetector) GetMSSIntegrityVerificationSummary(result *MSSResult) *MSSIntegritySummary {
	if result == nil || !result.MSSIntegrityCheck {
		return &MSSIntegritySummary{
			Valid: false,
			Error: "Invalid or non-integrity verification result",
		}
	}

	summary := &MSSIntegritySummary{
		Valid:                true,
		ClientSentMSS:        result.ClientSentMSS,
		ServerReceivedMSS:    result.ServerReceivedMSS,
		MSSModified:          result.MSSModified,
		ModificationDelta:    result.ModificationDelta,
		TamperingDetected:    result.MSSModified,
		ConnectionSuccessful: result.ConnectionSuccess,
		ClampingDetected:     result.MSSClamped,
		ClampedMSS:           result.ClampedMSS,
	}

	// Determine tampering severity
	if result.MSSModified {
		absDelta := result.ModificationDelta
		if absDelta < 0 {
			absDelta = -absDelta
		}

		switch {
		case absDelta == 0:
			summary.TamperingSeverity = "None"
		case absDelta <= 20:
			summary.TamperingSeverity = "Low"
		case absDelta <= 100:
			summary.TamperingSeverity = "Medium"
		default:
			summary.TamperingSeverity = "High"
		}
	} else {
		summary.TamperingSeverity = "None"
	}

	// Generate description
	if result.MSSModified {
		summary.Description = fmt.Sprintf("MSS tampering detected: client sent %d, server received %d (delta: %d)",
			result.ClientSentMSS, result.ServerReceivedMSS, result.ModificationDelta)
	} else {
		summary.Description = fmt.Sprintf("No MSS tampering detected: MSS value %d preserved", result.ClientSentMSS)
	}

	return summary
}

// MSSIntegritySummary provides a summary of MSS integrity verification results
type MSSIntegritySummary struct {
	Valid                bool
	Error                string
	ClientSentMSS        int
	ServerReceivedMSS    int
	MSSModified          bool
	ModificationDelta    int
	TamperingDetected    bool
	TamperingSeverity    string
	ConnectionSuccessful bool
	ClampingDetected     bool
	ClampedMSS           int
	Description          string
}

// sendVerificationInfo sends MSS verification information over the control connection
func (d *MSSDetector) sendVerificationInfo(conn net.Conn, info *MSSVerificationInfo) error {
	// Create a simple protocol message
	message := fmt.Sprintf("MSS_VERIFY|%s|%d|%d|%s",
		info.SessionID,
		info.ClientMSS,
		info.ServerMSS,
		info.Timestamp.Format(time.RFC3339))

	data := []byte(message)
	return d.tcpManager.SendVerificationData(conn, data)
}

// receiveVerificationInfo receives MSS verification information from the control connection
func (d *MSSDetector) receiveVerificationInfo(conn net.Conn) (*MSSVerificationInfo, error) {
	data, err := d.tcpManager.ReceiveVerificationData(conn)
	if err != nil {
		return nil, err
	}

	message := string(data)
	parts := strings.Split(message, "|")
	if len(parts) != 5 || parts[0] != "MSS_VERIFY" {
		return nil, fmt.Errorf("invalid verification message format")
	}

	clientMSS, err := strconv.Atoi(parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid client MSS: %w", err)
	}

	serverMSS, err := strconv.Atoi(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid server MSS: %w", err)
	}

	timestamp, err := time.Parse(time.RFC3339, parts[4])
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	return &MSSVerificationInfo{
		SessionID: parts[1],
		ClientMSS: clientMSS,
		ServerMSS: serverMSS,
		Timestamp: timestamp,
	}, nil
}

// Close closes the detector and releases resources
func (d *MSSDetector) Close() error {
	var err error

	if d.controlConn != nil {
		if closeErr := d.controlConn.Close(); closeErr != nil {
			err = closeErr
		}
		d.controlConn = nil
	}

	if d.listener != nil {
		if closeErr := d.listener.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
		d.listener = nil
	}

	if d.tcpManager != nil {
		if closeErr := d.tcpManager.Close(); closeErr != nil && err == nil {
			err = closeErr
		}
	}

	return err
}
