package network

import (
	"context"
	"fmt"
	"net"
	"time"
)

// MSSIntegrityVerifier handles MSS integrity verification and tampering detection
type MSSIntegrityVerifier struct {
	detector    *MSSDetector
	tcpManager  *TCPManager
	testMSS     int
	controlPort int
	sessionID   string
}

// IntegrityTestSession represents an MSS integrity verification session
type IntegrityTestSession struct {
	SessionID  string
	ClientAddr net.Addr
	ServerAddr net.Addr
	TestMSS    int
	StartTime  time.Time
	Status     SessionStatus
}

// SessionStatus represents the status of an integrity test session
type SessionStatus int

const (
	SessionPending SessionStatus = iota
	SessionActive
	SessionCompleted
	SessionFailed
)

// String returns the string representation of SessionStatus
func (s SessionStatus) String() string {
	switch s {
	case SessionPending:
		return "pending"
	case SessionActive:
		return "active"
	case SessionCompleted:
		return "completed"
	case SessionFailed:
		return "failed"
	default:
		return "unknown"
	}
}

// NewMSSIntegrityVerifier creates a new MSS integrity verifier
func NewMSSIntegrityVerifier(detector *MSSDetector, testMSS, controlPort int) *MSSIntegrityVerifier {
	sessionID := fmt.Sprintf("mss-verify-%d", time.Now().UnixNano())

	return &MSSIntegrityVerifier{
		detector:    detector,
		tcpManager:  NewTCPManager(),
		testMSS:     testMSS,
		controlPort: controlPort,
		sessionID:   sessionID,
	}
}

// StartVerificationSession starts a new MSS integrity verification session
func (miv *MSSIntegrityVerifier) StartVerificationSession(ctx context.Context) (*IntegrityTestSession, error) {
	if miv.detector == nil {
		return nil, fmt.Errorf("MSS detector not initialized")
	}

	if miv.testMSS <= 0 || miv.testMSS > 65535 {
		return nil, fmt.Errorf("invalid test MSS: %d", miv.testMSS)
	}

	if miv.controlPort <= 0 || miv.controlPort > 65535 {
		return nil, fmt.Errorf("invalid control port: %d", miv.controlPort)
	}

	session := &IntegrityTestSession{
		SessionID: miv.sessionID,
		TestMSS:   miv.testMSS,
		StartTime: time.Now(),
		Status:    SessionPending,
	}

	// Set session addresses based on detector configuration
	if miv.detector.target != nil {
		session.ServerAddr = &net.TCPAddr{
			IP:   miv.detector.target.IP,
			Port: miv.detector.port,
		}
		session.ClientAddr = &net.TCPAddr{
			IP:   net.IPv6loopback, // Local client address
			Port: 0,                // Dynamic port assignment
		}
	}

	session.Status = SessionActive
	return session, nil
}

// ExecuteClientSideTest performs the client-side MSS integrity test
func (miv *MSSIntegrityVerifier) ExecuteClientSideTest(ctx context.Context, session *IntegrityTestSession) (*MSSResult, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if session.Status != SessionActive {
		return nil, fmt.Errorf("session is not active: %s", session.Status)
	}

	result := &MSSResult{
		OriginalMSS:       miv.testMSS,
		MSSIntegrityCheck: true,
		ClientSentMSS:     miv.testMSS,
	}

	// Step 1: Establish control connection
	controlAddr := &net.TCPAddr{
		IP:   miv.detector.target.IP,
		Port: miv.controlPort,
	}

	controlConn, err := miv.tcpManager.EstablishControlChannel(controlAddr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to establish control connection: %v", err)
		session.Status = SessionFailed
		return result, nil
	}
	defer controlConn.Close()

	// Step 2: Send client verification info to server
	clientInfo := &MSSVerificationInfo{
		ClientMSS: miv.testMSS,
		ServerMSS: 0, // Will be filled by server
		Timestamp: time.Now(),
		SessionID: session.SessionID,
	}

	if err := miv.sendVerificationInfo(controlConn, clientInfo); err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to send verification info: %v", err)
		session.Status = SessionFailed
		return result, nil
	}

	// Step 3: Establish main connection with specific MSS
	targetAddr := &net.TCPAddr{
		IP:   miv.detector.target.IP,
		Port: miv.detector.port,
	}

	timeout := 10 * time.Second
	if deadline, ok := ctx.Deadline(); ok {
		timeout = time.Until(deadline)
	}

	conn, err := miv.tcpManager.ConnectWithMSS(targetAddr, miv.testMSS, timeout)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to connect with MSS %d: %v", miv.testMSS, err)
		session.Status = SessionFailed
		return result, nil
	}
	defer conn.Close()

	result.ConnectionSuccess = true

	// Step 4: Get connection info to verify our MSS setting
	connInfo, err := miv.tcpManager.GetConnectionInfo(conn)
	if err == nil && connInfo.EffectiveMSS > 0 {
		result.ClampedMSS = connInfo.EffectiveMSS
		if connInfo.EffectiveMSS < miv.testMSS {
			result.MSSClamped = true
			result.DetectedMTU = connInfo.EffectiveMSS + 40 // Add IPv6 header size
		}
	}

	// Step 5: Receive server's verification result
	serverInfo, err := miv.receiveVerificationInfo(controlConn)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to receive server verification: %v", err)
		session.Status = SessionFailed
		return result, nil
	}

	// Step 6: Compare MSS values to detect tampering
	result.ServerReceivedMSS = serverInfo.ServerMSS
	result.MSSModified = (result.ClientSentMSS != result.ServerReceivedMSS)
	result.ModificationDelta = result.ClientSentMSS - result.ServerReceivedMSS

	session.Status = SessionCompleted
	return result, nil
}

// ExecuteServerSideTest performs the server-side MSS integrity test
func (miv *MSSIntegrityVerifier) ExecuteServerSideTest(ctx context.Context, session *IntegrityTestSession) (*MSSResult, error) {
	if session == nil {
		return nil, fmt.Errorf("session cannot be nil")
	}

	if session.Status != SessionActive {
		return nil, fmt.Errorf("session is not active: %s", session.Status)
	}

	result := &MSSResult{
		OriginalMSS:       miv.testMSS,
		MSSIntegrityCheck: true,
	}

	// Step 1: Start control listener
	controlAddr := &net.TCPAddr{
		IP:   net.IPv6zero, // Listen on all IPv6 interfaces
		Port: miv.controlPort,
	}

	controlListener, err := miv.tcpManager.ListenTCPv6(controlAddr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to start control listener: %v", err)
		session.Status = SessionFailed
		return result, nil
	}
	defer controlListener.Close()

	// Step 2: Start main listener
	listenAddr := &net.TCPAddr{
		IP:   net.IPv6zero,
		Port: miv.detector.port,
	}

	listener, err := miv.tcpManager.ListenTCPv6(listenAddr)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to start main listener: %v", err)
		session.Status = SessionFailed
		return result, nil
	}
	defer listener.Close()

	// Step 3: Accept control connection
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
		session.Status = SessionFailed
		return result, nil
	case err := <-controlErrChan:
		result.ErrorMessage = fmt.Sprintf("Failed to accept control connection: %v", err)
		session.Status = SessionFailed
		return result, nil
	case controlConn = <-controlConnChan:
		defer controlConn.Close()
	}

	// Step 4: Receive client verification info
	clientInfo, err := miv.receiveVerificationInfo(controlConn)
	if err != nil {
		result.ErrorMessage = fmt.Sprintf("Failed to receive client verification: %v", err)
		session.Status = SessionFailed
		return result, nil
	}

	result.ClientSentMSS = clientInfo.ClientMSS

	// Step 5: Accept main connection and capture MSS
	mainConnChan := make(chan net.Conn, 1)
	mainMSSChan := make(chan int, 1)
	mainErrChan := make(chan error, 1)

	go func() {
		conn, mss, err := miv.tcpManager.AcceptWithMSSCapture(listener)
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
		session.Status = SessionFailed
		return result, nil
	case err := <-mainErrChan:
		result.ErrorMessage = fmt.Sprintf("Failed to accept main connection: %v", err)
		session.Status = SessionFailed
		return result, nil
	case conn := <-mainConnChan:
		defer conn.Close()
		result.ConnectionSuccess = true

		// Get captured MSS
		capturedMSS := <-mainMSSChan
		result.ServerReceivedMSS = capturedMSS

		// Get additional connection info if available
		if connInfo, err := miv.tcpManager.GetConnectionInfo(conn); err == nil {
			if connInfo.EffectiveMSS > 0 {
				result.ServerReceivedMSS = connInfo.EffectiveMSS
			}
		}

		// Step 6: Compare MSS values
		result.MSSModified = (result.ClientSentMSS != result.ServerReceivedMSS)
		result.ModificationDelta = result.ClientSentMSS - result.ServerReceivedMSS

		// Step 7: Send verification result back to client
		serverInfo := &MSSVerificationInfo{
			ClientMSS: result.ClientSentMSS,
			ServerMSS: result.ServerReceivedMSS,
			Timestamp: time.Now(),
			SessionID: session.SessionID,
		}

		if err := miv.sendVerificationInfo(controlConn, serverInfo); err != nil {
			result.ErrorMessage = fmt.Sprintf("Failed to send verification result: %v", err)
			session.Status = SessionFailed
			return result, nil
		}

		session.Status = SessionCompleted
		return result, nil
	}
}

// CompareResults compares client and server MSS verification results
func (miv *MSSIntegrityVerifier) CompareResults(clientResult, serverResult *MSSVerificationInfo) *MSSResult {
	if clientResult == nil || serverResult == nil {
		return &MSSResult{
			MSSIntegrityCheck: true,
			ErrorMessage:      "Invalid verification results for comparison",
		}
	}

	result := &MSSResult{
		MSSIntegrityCheck: true,
		ClientSentMSS:     clientResult.ClientMSS,
		ServerReceivedMSS: serverResult.ServerMSS,
		ConnectionSuccess: true,
	}

	// Compare MSS values
	result.MSSModified = (clientResult.ClientMSS != serverResult.ServerMSS)
	result.ModificationDelta = clientResult.ClientMSS - serverResult.ServerMSS

	// Check for clamping (reduction in MSS)
	if serverResult.ServerMSS < clientResult.ClientMSS {
		result.MSSClamped = true
		result.ClampedMSS = serverResult.ServerMSS
		result.DetectedMTU = serverResult.ServerMSS + 40 // Add IPv6 header size
	}

	return result
}

// PerformBidirectionalVerification performs verification from both client and server perspectives
func (miv *MSSIntegrityVerifier) PerformBidirectionalVerification(ctx context.Context) (*MSSResult, error) {
	// Start verification session
	session, err := miv.StartVerificationSession(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to start verification session: %w", err)
	}

	// For bidirectional verification, we need to coordinate both client and server tests
	// This is a simplified implementation that performs client-side test
	// In a real scenario, this would coordinate with a separate server instance

	result, err := miv.ExecuteClientSideTest(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("client-side test failed: %w", err)
	}

	return result, nil
}

// ValidateSession validates an integrity test session
func (miv *MSSIntegrityVerifier) ValidateSession(session *IntegrityTestSession) error {
	if session == nil {
		return fmt.Errorf("session cannot be nil")
	}

	if session.SessionID == "" {
		return fmt.Errorf("session ID cannot be empty")
	}

	if session.TestMSS <= 0 || session.TestMSS > 65535 {
		return fmt.Errorf("invalid test MSS: %d", session.TestMSS)
	}

	if session.StartTime.IsZero() {
		return fmt.Errorf("session start time not set")
	}

	return nil
}

// GetSessionInfo returns information about the current session
func (miv *MSSIntegrityVerifier) GetSessionInfo() map[string]interface{} {
	return map[string]interface{}{
		"session_id":   miv.sessionID,
		"test_mss":     miv.testMSS,
		"control_port": miv.controlPort,
		"detector":     miv.detector != nil,
		"tcp_manager":  miv.tcpManager != nil,
	}
}

// sendVerificationInfo sends MSS verification information over the control connection
func (miv *MSSIntegrityVerifier) sendVerificationInfo(conn net.Conn, info *MSSVerificationInfo) error {
	if conn == nil {
		return fmt.Errorf("connection cannot be nil")
	}

	if info == nil {
		return fmt.Errorf("verification info cannot be nil")
	}

	// Create a protocol message
	message := fmt.Sprintf("MSS_INTEGRITY_VERIFY|%s|%d|%d|%s",
		info.SessionID,
		info.ClientMSS,
		info.ServerMSS,
		info.Timestamp.Format(time.RFC3339))

	data := []byte(message)
	return miv.tcpManager.SendVerificationData(conn, data)
}

// receiveVerificationInfo receives MSS verification information from the control connection
func (miv *MSSIntegrityVerifier) receiveVerificationInfo(conn net.Conn) (*MSSVerificationInfo, error) {
	if conn == nil {
		return nil, fmt.Errorf("connection cannot be nil")
	}

	data, err := miv.tcpManager.ReceiveVerificationData(conn)
	if err != nil {
		return nil, fmt.Errorf("failed to receive data: %w", err)
	}

	message := string(data)

	// Parse the protocol message
	return miv.parseVerificationMessage(message)
}

// parseVerificationMessage parses a verification protocol message
func (miv *MSSIntegrityVerifier) parseVerificationMessage(message string) (*MSSVerificationInfo, error) {
	// Split message by delimiter
	parts := make([]string, 0)
	current := ""
	inEscape := false

	for _, char := range message {
		if char == '\\' && !inEscape {
			inEscape = true
			continue
		}

		if char == '|' && !inEscape {
			parts = append(parts, current)
			current = ""
			continue
		}

		current += string(char)
		inEscape = false
	}

	// Add the last part
	if current != "" {
		parts = append(parts, current)
	}

	if len(parts) != 5 || parts[0] != "MSS_INTEGRITY_VERIFY" {
		return nil, fmt.Errorf("invalid verification message format: expected 5 parts with MSS_INTEGRITY_VERIFY prefix, got %d parts", len(parts))
	}

	// Parse client MSS
	clientMSS := 0
	if parts[2] != "" {
		if parsed, err := parseIntSafe(parts[2]); err != nil {
			return nil, fmt.Errorf("invalid client MSS: %w", err)
		} else {
			clientMSS = parsed
		}
	}

	// Parse server MSS
	serverMSS := 0
	if parts[3] != "" {
		if parsed, err := parseIntSafe(parts[3]); err != nil {
			return nil, fmt.Errorf("invalid server MSS: %w", err)
		} else {
			serverMSS = parsed
		}
	}

	// Parse timestamp
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

// parseIntSafe safely parses an integer string
func parseIntSafe(s string) (int, error) {
	if s == "" {
		return 0, nil
	}

	// Basic validation for integer format
	for _, char := range s {
		if char < '0' || char > '9' {
			return 0, fmt.Errorf("invalid integer format: %s", s)
		}
	}

	// Simple integer parsing (avoiding strconv import)
	result := 0
	for _, char := range s {
		digit := int(char - '0')
		result = result*10 + digit

		// Check for overflow (simple check for reasonable MSS values)
		if result > 65535 {
			return 0, fmt.Errorf("integer value too large: %s", s)
		}
	}

	return result, nil
}

// Close closes the MSS integrity verifier and releases resources
func (miv *MSSIntegrityVerifier) Close() error {
	var err error

	if miv.tcpManager != nil {
		if closeErr := miv.tcpManager.Close(); closeErr != nil {
			err = closeErr
		}
	}

	// Note: We don't close the detector here as it might be shared
	// The detector should be closed by its owner

	return err
}
