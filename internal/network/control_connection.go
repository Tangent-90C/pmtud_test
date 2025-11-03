package network

import (
	"context"
	"fmt"
	"net"
	"sync"
	"time"
)

// ControlConnectionManager manages control connections for MSS verification
type ControlConnectionManager struct {
	listener    net.Listener
	connections map[string]net.Conn
	port        int
	mutex       sync.RWMutex
	running     bool
	ctx         context.Context
	cancel      context.CancelFunc
}

// ControlMessage represents a control protocol message
type ControlMessage struct {
	Type      MessageType
	SessionID string
	Data      []byte
	Timestamp time.Time
}

// MessageType represents the type of control message
type MessageType int

const (
	MsgHandshake MessageType = iota
	MsgMSSInfo
	MsgVerificationResult
	MsgError
	MsgClose
)

// String returns the string representation of MessageType
func (mt MessageType) String() string {
	switch mt {
	case MsgHandshake:
		return "handshake"
	case MsgMSSInfo:
		return "mss_info"
	case MsgVerificationResult:
		return "verification_result"
	case MsgError:
		return "error"
	case MsgClose:
		return "close"
	default:
		return "unknown"
	}
}

// NewControlConnectionManager creates a new control connection manager
func NewControlConnectionManager(port int) *ControlConnectionManager {
	ctx, cancel := context.WithCancel(context.Background())

	return &ControlConnectionManager{
		connections: make(map[string]net.Conn),
		port:        port,
		running:     false,
		ctx:         ctx,
		cancel:      cancel,
	}
}

// StartListener starts the control connection listener
func (ccm *ControlConnectionManager) StartListener(ctx context.Context) error {
	ccm.mutex.Lock()
	defer ccm.mutex.Unlock()

	if ccm.running {
		return fmt.Errorf("listener already running")
	}

	if ccm.port <= 0 || ccm.port > 65535 {
		return fmt.Errorf("invalid port: %d", ccm.port)
	}

	// Create listen address
	listenAddr := &net.TCPAddr{
		IP:   net.IPv6zero, // Listen on all IPv6 interfaces
		Port: ccm.port,
	}

	// Start listening
	listener, err := net.ListenTCP("tcp6", listenAddr)
	if err != nil {
		return fmt.Errorf("failed to start listener on port %d: %w", ccm.port, err)
	}

	ccm.listener = listener
	ccm.running = true

	// Start accepting connections in a goroutine
	go ccm.acceptLoop(ctx)

	return nil
}

// acceptLoop continuously accepts new connections
func (ccm *ControlConnectionManager) acceptLoop(ctx context.Context) {
	defer func() {
		ccm.mutex.Lock()
		ccm.running = false
		ccm.mutex.Unlock()
	}()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ccm.ctx.Done():
			return
		default:
		}

		if ccm.listener == nil {
			return
		}

		// Set a timeout for accept to allow periodic context checking
		if tcpListener, ok := ccm.listener.(*net.TCPListener); ok {
			tcpListener.SetDeadline(time.Now().Add(1 * time.Second))
		}

		conn, err := ccm.listener.Accept()
		if err != nil {
			// Check if it's a timeout error
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue // Continue the loop to check context
			}
			// If not a timeout, it might be because the listener was closed
			return
		}

		// Handle the new connection
		go ccm.handleConnection(conn)
	}
}

// handleConnection handles a new control connection
func (ccm *ControlConnectionManager) handleConnection(conn net.Conn) {
	defer conn.Close()

	// Set initial read timeout
	conn.SetReadDeadline(time.Now().Add(30 * time.Second))

	// Read handshake message
	msg, err := ccm.ReceiveMessage(conn)
	if err != nil {
		ccm.sendErrorMessage(conn, "", fmt.Sprintf("Handshake failed: %v", err))
		return
	}

	if msg.Type != MsgHandshake {
		ccm.sendErrorMessage(conn, msg.SessionID, "Expected handshake message")
		return
	}

	sessionID := msg.SessionID
	if sessionID == "" {
		ccm.sendErrorMessage(conn, "", "Session ID required in handshake")
		return
	}

	// Register the connection
	ccm.mutex.Lock()
	ccm.connections[sessionID] = conn
	ccm.mutex.Unlock()

	// Send handshake response
	response := &ControlMessage{
		Type:      MsgHandshake,
		SessionID: sessionID,
		Data:      []byte("OK"),
		Timestamp: time.Now(),
	}

	if err := ccm.SendMessage(conn, response); err != nil {
		ccm.removeConnection(sessionID)
		return
	}

	// Keep connection alive and handle messages
	ccm.connectionLoop(conn, sessionID)
}

// connectionLoop handles messages for an established connection
func (ccm *ControlConnectionManager) connectionLoop(conn net.Conn, sessionID string) {
	defer ccm.removeConnection(sessionID)

	for {
		select {
		case <-ccm.ctx.Done():
			return
		default:
		}

		// Set read timeout
		conn.SetReadDeadline(time.Now().Add(60 * time.Second))

		msg, err := ccm.ReceiveMessage(conn)
		if err != nil {
			// Connection closed or error occurred
			return
		}

		// Handle different message types
		switch msg.Type {
		case MsgClose:
			// Client requested to close connection
			ccm.SendMessage(conn, &ControlMessage{
				Type:      MsgClose,
				SessionID: sessionID,
				Data:      []byte("OK"),
				Timestamp: time.Now(),
			})
			return
		case MsgMSSInfo, MsgVerificationResult:
			// These messages are handled by the application layer
			// For now, just acknowledge receipt
			ack := &ControlMessage{
				Type:      MsgVerificationResult,
				SessionID: sessionID,
				Data:      []byte("ACK"),
				Timestamp: time.Now(),
			}
			ccm.SendMessage(conn, ack)
		default:
			// Unknown message type
			ccm.sendErrorMessage(conn, sessionID, fmt.Sprintf("Unknown message type: %v", msg.Type))
		}
	}
}

// AcceptConnection waits for and accepts a new control connection
func (ccm *ControlConnectionManager) AcceptConnection(ctx context.Context) (net.Conn, error) {
	if !ccm.IsRunning() {
		return nil, fmt.Errorf("listener not running")
	}

	if ccm.listener == nil {
		return nil, fmt.Errorf("listener not initialized")
	}

	// Create a channel to receive the connection
	connChan := make(chan net.Conn, 1)
	errChan := make(chan error, 1)

	go func() {
		conn, err := ccm.listener.Accept()
		if err != nil {
			errChan <- err
			return
		}
		connChan <- conn
	}()

	// Wait for connection or context cancellation
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case err := <-errChan:
		return nil, fmt.Errorf("failed to accept connection: %w", err)
	case conn := <-connChan:
		return conn, nil
	}
}

// SendMessage sends a control message over the connection
func (ccm *ControlConnectionManager) SendMessage(conn net.Conn, msg *ControlMessage) error {
	if conn == nil {
		return fmt.Errorf("connection cannot be nil")
	}

	if msg == nil {
		return fmt.Errorf("message cannot be nil")
	}

	// Serialize the message
	data, err := ccm.serializeMessage(msg)
	if err != nil {
		return fmt.Errorf("failed to serialize message: %w", err)
	}

	// Send message length first (4 bytes)
	length := uint32(len(data))
	lengthBytes := make([]byte, 4)
	lengthBytes[0] = byte(length >> 24)
	lengthBytes[1] = byte(length >> 16)
	lengthBytes[2] = byte(length >> 8)
	lengthBytes[3] = byte(length)

	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to send message length: %w", err)
	}

	// Send message data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send message data: %w", err)
	}

	return nil
}

// ReceiveMessage receives a control message from the connection
func (ccm *ControlConnectionManager) ReceiveMessage(conn net.Conn) (*ControlMessage, error) {
	if conn == nil {
		return nil, fmt.Errorf("connection cannot be nil")
	}

	// Read message length first (4 bytes)
	lengthBytes := make([]byte, 4)
	if _, err := conn.Read(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read message length: %w", err)
	}

	length := uint32(lengthBytes[0])<<24 | uint32(lengthBytes[1])<<16 |
		uint32(lengthBytes[2])<<8 | uint32(lengthBytes[3])

	if length == 0 {
		return nil, fmt.Errorf("received zero-length message")
	}

	if length > 1024*1024 { // 1MB limit
		return nil, fmt.Errorf("message too large: %d bytes", length)
	}

	// Read message data
	data := make([]byte, length)
	totalRead := 0
	for totalRead < int(length) {
		n, err := conn.Read(data[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read message data: %w", err)
		}
		totalRead += n
	}

	// Deserialize the message
	msg, err := ccm.deserializeMessage(data)
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize message: %w", err)
	}

	return msg, nil
}

// GetConnection returns the connection for a given session ID
func (ccm *ControlConnectionManager) GetConnection(sessionID string) (net.Conn, bool) {
	ccm.mutex.RLock()
	defer ccm.mutex.RUnlock()

	conn, exists := ccm.connections[sessionID]
	return conn, exists
}

// CloseConnection closes the connection for a given session ID
func (ccm *ControlConnectionManager) CloseConnection(sessionID string) error {
	ccm.mutex.Lock()
	defer ccm.mutex.Unlock()

	conn, exists := ccm.connections[sessionID]
	if !exists {
		return fmt.Errorf("connection not found for session: %s", sessionID)
	}

	// Send close message
	closeMsg := &ControlMessage{
		Type:      MsgClose,
		SessionID: sessionID,
		Data:      []byte("Connection closed by server"),
		Timestamp: time.Now(),
	}

	// Try to send close message, but don't fail if it doesn't work
	ccm.SendMessage(conn, closeMsg)

	// Close the connection
	err := conn.Close()
	delete(ccm.connections, sessionID)

	return err
}

// removeConnection removes a connection from the manager
func (ccm *ControlConnectionManager) removeConnection(sessionID string) {
	ccm.mutex.Lock()
	defer ccm.mutex.Unlock()

	if conn, exists := ccm.connections[sessionID]; exists {
		conn.Close()
		delete(ccm.connections, sessionID)
	}
}

// sendErrorMessage sends an error message to the client
func (ccm *ControlConnectionManager) sendErrorMessage(conn net.Conn, sessionID, errorMsg string) {
	msg := &ControlMessage{
		Type:      MsgError,
		SessionID: sessionID,
		Data:      []byte(errorMsg),
		Timestamp: time.Now(),
	}
	ccm.SendMessage(conn, msg) // Ignore errors when sending error messages
}

// IsRunning returns whether the listener is running
func (ccm *ControlConnectionManager) IsRunning() bool {
	ccm.mutex.RLock()
	defer ccm.mutex.RUnlock()
	return ccm.running
}

// GetPort returns the port the manager is listening on
func (ccm *ControlConnectionManager) GetPort() int {
	return ccm.port
}

// GetConnectionCount returns the number of active connections
func (ccm *ControlConnectionManager) GetConnectionCount() int {
	ccm.mutex.RLock()
	defer ccm.mutex.RUnlock()
	return len(ccm.connections)
}

// GetActiveSessionIDs returns a list of active session IDs
func (ccm *ControlConnectionManager) GetActiveSessionIDs() []string {
	ccm.mutex.RLock()
	defer ccm.mutex.RUnlock()

	sessionIDs := make([]string, 0, len(ccm.connections))
	for sessionID := range ccm.connections {
		sessionIDs = append(sessionIDs, sessionID)
	}

	return sessionIDs
}

// serializeMessage serializes a control message to bytes
func (ccm *ControlConnectionManager) serializeMessage(msg *ControlMessage) ([]byte, error) {
	if msg == nil {
		return nil, fmt.Errorf("message cannot be nil")
	}

	// Create a simple protocol format: TYPE|SESSION_ID|TIMESTAMP|DATA_LENGTH|DATA
	timestamp := msg.Timestamp.Format(time.RFC3339)
	dataLength := len(msg.Data)

	// Build the message
	header := fmt.Sprintf("%d|%s|%s|%d|",
		int(msg.Type),
		msg.SessionID,
		timestamp,
		dataLength)

	// Combine header and data
	result := make([]byte, len(header)+len(msg.Data))
	copy(result, []byte(header))
	copy(result[len(header):], msg.Data)

	return result, nil
}

// deserializeMessage deserializes bytes to a control message
func (ccm *ControlConnectionManager) deserializeMessage(data []byte) (*ControlMessage, error) {
	if len(data) == 0 {
		return nil, fmt.Errorf("empty message data")
	}

	// Find the header separator (last | before data)
	headerEnd := -1
	pipeCount := 0
	for i, b := range data {
		if b == '|' {
			pipeCount++
			if pipeCount == 4 { // TYPE|SESSION_ID|TIMESTAMP|DATA_LENGTH|
				headerEnd = i
				break
			}
		}
	}

	if headerEnd == -1 {
		return nil, fmt.Errorf("invalid message format: header not found")
	}

	// Parse header
	header := string(data[:headerEnd])
	parts := make([]string, 0, 4)
	current := ""

	for _, char := range header {
		if char == '|' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(char)
		}
	}

	if len(parts) != 4 {
		return nil, fmt.Errorf("invalid header format: expected 4 parts, got %d", len(parts))
	}

	// Parse message type
	msgType, err := parseIntSafe(parts[0])
	if err != nil {
		return nil, fmt.Errorf("invalid message type: %w", err)
	}

	if msgType < 0 || msgType > int(MsgClose) {
		return nil, fmt.Errorf("unknown message type: %d", msgType)
	}

	// Parse session ID
	sessionID := parts[1]

	// Parse timestamp
	timestamp, err := time.Parse(time.RFC3339, parts[2])
	if err != nil {
		return nil, fmt.Errorf("invalid timestamp: %w", err)
	}

	// Parse data length
	dataLength, err := parseIntSafe(parts[3])
	if err != nil {
		return nil, fmt.Errorf("invalid data length: %w", err)
	}

	// Extract message data
	messageData := data[headerEnd+1:]
	if len(messageData) != dataLength {
		return nil, fmt.Errorf("data length mismatch: expected %d, got %d", dataLength, len(messageData))
	}

	return &ControlMessage{
		Type:      MessageType(msgType),
		SessionID: sessionID,
		Data:      messageData,
		Timestamp: timestamp,
	}, nil
}

// Close closes the control connection manager and all connections
func (ccm *ControlConnectionManager) Close() error {
	ccm.mutex.Lock()
	defer ccm.mutex.Unlock()

	// Cancel context to stop accept loop
	ccm.cancel()

	var lastErr error

	// Close all active connections
	for sessionID, conn := range ccm.connections {
		if err := conn.Close(); err != nil {
			lastErr = err
		}
		delete(ccm.connections, sessionID)
	}

	// Close listener
	if ccm.listener != nil {
		if err := ccm.listener.Close(); err != nil && lastErr == nil {
			lastErr = err
		}
		ccm.listener = nil
	}

	ccm.running = false

	return lastErr
}

// CreateHandshakeMessage creates a handshake message
func CreateHandshakeMessage(sessionID string) *ControlMessage {
	return &ControlMessage{
		Type:      MsgHandshake,
		SessionID: sessionID,
		Data:      []byte("HANDSHAKE"),
		Timestamp: time.Now(),
	}
}

// CreateMSSInfoMessage creates an MSS info message
func CreateMSSInfoMessage(sessionID string, mssInfo *MSSVerificationInfo) *ControlMessage {
	// Serialize MSS info
	data := fmt.Sprintf("CLIENT_MSS:%d|SERVER_MSS:%d|TIMESTAMP:%s",
		mssInfo.ClientMSS,
		mssInfo.ServerMSS,
		mssInfo.Timestamp.Format(time.RFC3339))

	return &ControlMessage{
		Type:      MsgMSSInfo,
		SessionID: sessionID,
		Data:      []byte(data),
		Timestamp: time.Now(),
	}
}

// CreateVerificationResultMessage creates a verification result message
func CreateVerificationResultMessage(sessionID string, result *MSSResult) *ControlMessage {
	// Serialize result
	data := fmt.Sprintf("CLIENT_SENT:%d|SERVER_RECEIVED:%d|MODIFIED:%t|DELTA:%d",
		result.ClientSentMSS,
		result.ServerReceivedMSS,
		result.MSSModified,
		result.ModificationDelta)

	return &ControlMessage{
		Type:      MsgVerificationResult,
		SessionID: sessionID,
		Data:      []byte(data),
		Timestamp: time.Now(),
	}
}

// CreateErrorMessage creates an error message
func CreateErrorMessage(sessionID, errorMsg string) *ControlMessage {
	return &ControlMessage{
		Type:      MsgError,
		SessionID: sessionID,
		Data:      []byte(errorMsg),
		Timestamp: time.Now(),
	}
}

// CreateCloseMessage creates a close message
func CreateCloseMessage(sessionID string) *ControlMessage {
	return &ControlMessage{
		Type:      MsgClose,
		SessionID: sessionID,
		Data:      []byte("CLOSE"),
		Timestamp: time.Now(),
	}
}
