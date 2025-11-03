package network

import (
	"fmt"
	"net"
	"os"
	"syscall"
	"time"
	"unsafe"

	"golang.org/x/sys/unix"
)

// TCPManager handles TCP connection management
type TCPManager struct {
	conn        net.Conn
	controlConn net.Conn // Control connection for MSS verification
}

// NewTCPManager creates a new TCP manager
func NewTCPManager() *TCPManager {
	return &TCPManager{}
}

// CreateTCPv6Socket creates a new TCPv6 socket
func (tm *TCPManager) CreateTCPv6Socket() (net.Conn, error) {
	// Create a TCP socket for IPv6
	fd, err := syscall.Socket(syscall.AF_INET6, syscall.SOCK_STREAM, syscall.IPPROTO_TCP)
	if err != nil {
		return nil, fmt.Errorf("failed to create IPv6 TCP socket: %w", err)
	}

	// Set socket to IPv6 only (disable dual stack)
	err = syscall.SetsockoptInt(fd, syscall.IPPROTO_IPV6, syscall.IPV6_V6ONLY, 1)
	if err != nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to set IPv6 only option: %w", err)
	}

	// Convert file descriptor to net.Conn
	file := os.NewFile(uintptr(fd), "tcp6")
	if file == nil {
		syscall.Close(fd)
		return nil, fmt.Errorf("failed to create file from socket descriptor")
	}
	defer file.Close()

	conn, err := net.FileConn(file)
	if err != nil {
		return nil, fmt.Errorf("failed to create connection from file: %w", err)
	}

	tm.conn = conn
	return conn, nil
}

// SetMSSOption sets the MSS option on a TCP connection
func (tm *TCPManager) SetMSSOption(conn net.Conn, mss int) error {
	if mss <= 0 || mss > 65535 {
		return fmt.Errorf("invalid MSS value: %d (must be between 1 and 65535)", mss)
	}

	// Get the underlying TCP connection
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return fmt.Errorf("connection is not a TCP connection")
	}

	// Get the raw connection to access socket options
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return fmt.Errorf("failed to get raw connection: %w", err)
	}

	var setErr error
	err = rawConn.Control(func(fd uintptr) {
		// Set TCP_MAXSEG socket option
		setErr = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
	})

	if err != nil {
		return fmt.Errorf("failed to control raw connection: %w", err)
	}
	if setErr != nil {
		return fmt.Errorf("failed to set TCP MSS option: %w", setErr)
	}

	return nil
}

// GetMSSOption gets the MSS option from a TCP connection
func (tm *TCPManager) GetMSSOption(conn net.Conn) (int, error) {
	// Get the underlying TCP connection
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, fmt.Errorf("connection is not a TCP connection")
	}

	// Get the raw connection to access socket options
	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return 0, fmt.Errorf("failed to get raw connection: %w", err)
	}

	var mss int
	var getErr error
	err = rawConn.Control(func(fd uintptr) {
		// Get TCP_MAXSEG socket option
		mss, getErr = syscall.GetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	})

	if err != nil {
		return 0, fmt.Errorf("failed to control raw connection: %w", err)
	}
	if getErr != nil {
		return 0, fmt.Errorf("failed to get TCP MSS option: %w", getErr)
	}

	return mss, nil
}

// ConnectTCPv6 establishes a TCPv6 connection
func (tm *TCPManager) ConnectTCPv6(target *net.TCPAddr, timeout time.Duration) (net.Conn, error) {
	if target == nil {
		return nil, fmt.Errorf("target address cannot be nil")
	}

	// Ensure the target is IPv6
	if target.IP.To4() != nil {
		return nil, fmt.Errorf("target address is not IPv6: %s", target.IP)
	}

	// Create a dialer with timeout
	dialer := &net.Dialer{
		Timeout: timeout,
	}

	// Force IPv6 by using "tcp6" network
	conn, err := dialer.Dial("tcp6", target.String())
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", target.String(), err)
	}

	tm.conn = conn
	return conn, nil
}

// ListenTCPv6 creates a TCPv6 listener
func (tm *TCPManager) ListenTCPv6(addr *net.TCPAddr) (net.Listener, error) {
	if addr == nil {
		// Listen on all IPv6 interfaces
		addr = &net.TCPAddr{
			IP:   net.IPv6zero,
			Port: 0,
		}
	}

	// Ensure we're using IPv6
	if addr.IP != nil && addr.IP.To4() != nil {
		return nil, fmt.Errorf("address is not IPv6: %s", addr.IP)
	}

	// Create IPv6-only listener
	listener, err := net.ListenTCP("tcp6", addr)
	if err != nil {
		return nil, fmt.Errorf("failed to listen on %s: %w", addr.String(), err)
	}

	return listener, nil
}

// GetTCPInfo retrieves TCP connection information including MSS
func (tm *TCPManager) GetTCPInfo(conn net.Conn) (*TCPInfo, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, fmt.Errorf("connection is not a TCP connection")
	}

	rawConn, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, fmt.Errorf("failed to get raw connection: %w", err)
	}

	var info *TCPInfo
	var getErr error
	err = rawConn.Control(func(fd uintptr) {
		info, getErr = tm.getTCPInfoFromFD(int(fd))
	})

	if err != nil {
		return nil, fmt.Errorf("failed to control raw connection: %w", err)
	}
	if getErr != nil {
		return nil, fmt.Errorf("failed to get TCP info: %w", getErr)
	}

	return info, nil
}

// TCPInfo contains TCP connection information
type TCPInfo struct {
	MSS         int
	PMTU        int
	AdvMSS      int
	State       int
	RTT         time.Duration
	RTTVar      time.Duration
	SndCwnd     int
	SndSSThresh int
}

// getTCPInfoFromFD gets TCP info from file descriptor (Linux-specific)
func (tm *TCPManager) getTCPInfoFromFD(fd int) (*TCPInfo, error) {
	// This is a simplified version - in a real implementation,
	// you would use TCP_INFO socket option to get detailed information

	// For now, just get the MSS
	mss, err := syscall.GetsockoptInt(fd, syscall.IPPROTO_TCP, syscall.TCP_MAXSEG)
	if err != nil {
		return nil, fmt.Errorf("failed to get MSS: %w", err)
	}

	// Try to get additional TCP information if available
	var tcpInfo unix.TCPInfo
	tcpInfoSize := unsafe.Sizeof(tcpInfo)

	_, _, errno := syscall.Syscall6(
		syscall.SYS_GETSOCKOPT,
		uintptr(fd),
		uintptr(syscall.IPPROTO_TCP),
		uintptr(unix.TCP_INFO),
		uintptr(unsafe.Pointer(&tcpInfo)),
		uintptr(unsafe.Pointer(&tcpInfoSize)),
		0,
	)

	info := &TCPInfo{
		MSS: mss,
	}

	if errno == 0 {
		// Successfully got TCP_INFO
		info.PMTU = int(tcpInfo.Pmtu)
		info.AdvMSS = int(tcpInfo.Advmss)
		info.State = int(tcpInfo.State)
		info.RTT = time.Duration(tcpInfo.Rtt) * time.Microsecond
		info.RTTVar = time.Duration(tcpInfo.Rttvar) * time.Microsecond
		info.SndCwnd = int(tcpInfo.Snd_cwnd)
		info.SndSSThresh = int(tcpInfo.Snd_ssthresh)
	}

	return info, nil
}

// TCPConnectionInfo contains detailed TCP connection information
type TCPConnectionInfo struct {
	LocalAddr    net.Addr
	RemoteAddr   net.Addr
	LocalMSS     int
	RemoteMSS    int
	EffectiveMSS int
	ConnectedAt  time.Time
}

// MSSVerificationInfo contains MSS verification data
type MSSVerificationInfo struct {
	ClientMSS int
	ServerMSS int
	Timestamp time.Time
	SessionID string
}

// GetConnectionInfo retrieves detailed connection information
func (tm *TCPManager) GetConnectionInfo(conn net.Conn) (*TCPConnectionInfo, error) {
	if conn == nil {
		return nil, fmt.Errorf("connection cannot be nil")
	}

	info := &TCPConnectionInfo{
		LocalAddr:   conn.LocalAddr(),
		RemoteAddr:  conn.RemoteAddr(),
		ConnectedAt: time.Now(),
	}

	// Get MSS information
	mss, err := tm.GetMSSOption(conn)
	if err == nil {
		info.EffectiveMSS = mss
		info.LocalMSS = mss
		info.RemoteMSS = mss
	}

	// Try to get more detailed TCP information if available
	if tcpInfo, err := tm.GetTCPInfo(conn); err == nil {
		if tcpInfo.MSS > 0 {
			info.EffectiveMSS = tcpInfo.MSS
		}
		if tcpInfo.AdvMSS > 0 {
			info.RemoteMSS = tcpInfo.AdvMSS
		}
	}

	return info, nil
}

// ConnectWithMSS establishes a TCP connection with a specific MSS value
func (tm *TCPManager) ConnectWithMSS(target *net.TCPAddr, mss int, timeout time.Duration) (net.Conn, error) {
	if target == nil {
		return nil, fmt.Errorf("target address cannot be nil")
	}

	if mss <= 0 || mss > 65535 {
		return nil, fmt.Errorf("invalid MSS value: %d", mss)
	}

	// Create a socket first to set MSS before connecting
	conn, err := tm.CreateTCPv6Socket()
	if err != nil {
		return nil, fmt.Errorf("failed to create socket: %w", err)
	}

	// Set MSS option before connecting
	if err := tm.SetMSSOption(conn, mss); err != nil {
		conn.Close()
		return nil, fmt.Errorf("failed to set MSS: %w", err)
	}

	// Close the connection we created and use a proper dialer
	conn.Close()

	// Use dialer with timeout
	dialer := &net.Dialer{
		Timeout: timeout,
		Control: func(network, address string, c syscall.RawConn) error {
			var err error
			c.Control(func(fd uintptr) {
				// Set MSS before connecting
				err = syscall.SetsockoptInt(int(fd), syscall.IPPROTO_TCP, syscall.TCP_MAXSEG, mss)
			})
			return err
		},
	}

	conn, err = dialer.Dial("tcp6", target.String())
	if err != nil {
		return nil, fmt.Errorf("failed to connect with MSS %d: %w", mss, err)
	}

	tm.conn = conn
	return conn, nil
}

// AcceptWithMSSCapture accepts a connection and captures MSS information
func (tm *TCPManager) AcceptWithMSSCapture(listener net.Listener) (net.Conn, int, error) {
	if listener == nil {
		return nil, 0, fmt.Errorf("listener cannot be nil")
	}

	conn, err := listener.Accept()
	if err != nil {
		return nil, 0, fmt.Errorf("failed to accept connection: %w", err)
	}

	// Capture MSS information immediately after accepting
	mss, err := tm.GetMSSOption(conn)
	if err != nil {
		// Don't fail the connection, just return 0 for MSS
		return conn, 0, nil
	}

	return conn, mss, nil
}

// EstablishControlChannel establishes a control connection for MSS verification
func (tm *TCPManager) EstablishControlChannel(addr *net.TCPAddr) (net.Conn, error) {
	if addr == nil {
		return nil, fmt.Errorf("control address cannot be nil")
	}

	// Create a separate connection for control communication
	dialer := &net.Dialer{
		Timeout: 10 * time.Second,
	}

	conn, err := dialer.Dial("tcp6", addr.String())
	if err != nil {
		return nil, fmt.Errorf("failed to establish control channel to %s: %w", addr.String(), err)
	}

	tm.controlConn = conn
	return conn, nil
}

// SendVerificationData sends MSS verification data over the control connection
func (tm *TCPManager) SendVerificationData(conn net.Conn, data []byte) error {
	if conn == nil {
		return fmt.Errorf("connection cannot be nil")
	}

	if len(data) == 0 {
		return fmt.Errorf("data cannot be empty")
	}

	// Send data length first (4 bytes)
	length := uint32(len(data))
	lengthBytes := make([]byte, 4)
	lengthBytes[0] = byte(length >> 24)
	lengthBytes[1] = byte(length >> 16)
	lengthBytes[2] = byte(length >> 8)
	lengthBytes[3] = byte(length)

	if _, err := conn.Write(lengthBytes); err != nil {
		return fmt.Errorf("failed to send data length: %w", err)
	}

	// Send actual data
	if _, err := conn.Write(data); err != nil {
		return fmt.Errorf("failed to send verification data: %w", err)
	}

	return nil
}

// ReceiveVerificationData receives MSS verification data from the control connection
func (tm *TCPManager) ReceiveVerificationData(conn net.Conn) ([]byte, error) {
	if conn == nil {
		return nil, fmt.Errorf("connection cannot be nil")
	}

	// Read data length first (4 bytes)
	lengthBytes := make([]byte, 4)
	if _, err := conn.Read(lengthBytes); err != nil {
		return nil, fmt.Errorf("failed to read data length: %w", err)
	}

	length := uint32(lengthBytes[0])<<24 | uint32(lengthBytes[1])<<16 |
		uint32(lengthBytes[2])<<8 | uint32(lengthBytes[3])

	if length == 0 {
		return nil, fmt.Errorf("received zero-length data")
	}

	if length > 1024*1024 { // 1MB limit
		return nil, fmt.Errorf("data too large: %d bytes", length)
	}

	// Read actual data
	data := make([]byte, length)
	totalRead := 0
	for totalRead < int(length) {
		n, err := conn.Read(data[totalRead:])
		if err != nil {
			return nil, fmt.Errorf("failed to read verification data: %w", err)
		}
		totalRead += n
	}

	return data, nil
}

// CloseControlConnection closes the control connection
func (tm *TCPManager) CloseControlConnection() error {
	if tm.controlConn != nil {
		err := tm.controlConn.Close()
		tm.controlConn = nil
		return err
	}
	return nil
}

// Close closes the managed connection
func (tm *TCPManager) Close() error {
	var err error

	if tm.conn != nil {
		if closeErr := tm.conn.Close(); closeErr != nil {
			err = closeErr
		}
		tm.conn = nil
	}

	if closeErr := tm.CloseControlConnection(); closeErr != nil && err == nil {
		err = closeErr
	}

	return err
}
